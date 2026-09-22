//! **Task 6: the confidential-transfer lifecycle, end to end.**
//!
//! ```text
//! create ATA (anyone) ─► KYC thaw (freeze authority) ─► ConfigureAccount (owner only)
//!   ─► ApproveAccount (confidential authority; approve_policy = manual)
//!   ─► Deposit: public balance ─► pending
//!   ─► ApplyPendingBalance: pending ─► available
//!   ─► confidential TransferWithFee: sender available ─► recipient pending (fee withheld, encrypted)
//!   ─► recipient ApplyPendingBalance ─► Withdraw: available ─► public balance
//! ```
//!
//! * **Owner-only configuration.** Anyone can create someone's ATA; only the owner can attach
//!   encryption keys to it. `ConfigureAccount` checks the owner's signature and a proof that the
//!   owner knows the ElGamal secret key (`PubkeyValidity`).
//! * **Two balances.** Incoming credits (deposits, transfers) land in `pending_balance`, so senders
//!   never touch a ciphertext the owner is concurrently proving against. Only `available_balance`
//!   can be spent or withdrawn, so pending funds must be applied first.
//! * **Fees stay confidential.** On a fee-bearing mint the transfer is a `TransferWithFee`: the fee
//!   is proven correct (`PercentageWithCap`) against the fee schedule of the *current epoch* and
//!   withheld encrypted under the issuer's withdraw-withheld ElGamal key.
//! * **Auditor.** Every transfer amount is also encrypted under the mint's auditor key.

use {
    crate::{
        proofs::ProofAccounts,
        state::{load_account, load_mint, AccountSnapshot},
        Cluster, Error, Result, TOKEN_2022_PROGRAM_ID,
    },
    solana_address::Address,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_zk_elgamal_proof_interface::instruction::ProofInstruction,
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            derivation::derive_confidential_keys,
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey, ElGamalSecretKey},
        },
        zk_elgamal_proof_program::build_pubkey_validity_proof_data,
    },
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext,
    spl_token_2022_interface::{
        extension::{
            confidential_transfer::{instruction as ct, DecryptableBalance},
            ExtensionType,
        },
        instruction::reallocate,
    },
    spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation,
    spl_token_confidential_transfer_proof_generation::{
        transfer_with_fee::transfer_with_fee_split_proof_data, withdraw::withdraw_proof_data,
        TRANSFER_AMOUNT_LO_BITS,
    },
    std::num::NonZeroI8,
};

/// How many credits (deposits + incoming transfers) may pile up in `pending_balance` before the
/// owner must apply them. Bounded so the pending ciphertexts stay decryptable.
pub const MAXIMUM_PENDING_BALANCE_CREDITS: u64 = 65_536;

/// A token account's encryption keys. Only the owner can derive them.
pub struct ConfidentialKeys {
    /// Encrypts balances; its secret decrypts pending balances and produces proofs.
    pub elgamal: ElGamalKeypair,
    /// Authenticated encryption of the available balance, for cheap decryption by the owner.
    pub ae: AeKey,
}

impl ConfidentialKeys {
    /// Derive the keys from the owner's signature over the protocol message for `token_account`
    /// (the `solana-conf-bal/v1` HKDF scheme). Deterministic: the owner can re-derive them from the
    /// wallet at any time, and nobody else can.
    pub fn derive(owner: &Keypair, token_account: &Address) -> Result<Self> {
        let (elgamal, ae) = derive_confidential_keys(owner, token_account.as_ref())
            .map_err(|error| Error::Crypto(error.to_string()))?;
        Ok(Self { elgamal, ae })
    }
}

fn crypto(message: &str) -> Error {
    Error::Crypto(message.into())
}

fn elgamal_ciphertext(pod: PodElGamalCiphertext) -> Result<ElGamalCiphertext> {
    ElGamalCiphertext::try_from(pod).map_err(|_| crypto("invalid ElGamal ciphertext"))
}

/// Decrypt a small ElGamal ciphertext (anything below 2^32 base units).
pub fn decrypt_u32(secret: &ElGamalSecretKey, pod: PodElGamalCiphertext) -> Result<u64> {
    secret
        .decrypt_u32(&elgamal_ciphertext(pod)?)
        .ok_or_else(|| crypto("ciphertext does not decrypt to a 32-bit amount"))
}

/// Decrypt a lo/hi pair split at [`TRANSFER_AMOUNT_LO_BITS`] and recombine it as
/// `lo + hi * 2^16`. Addition rather than bitwise OR: after several credits the pending `lo` part
/// can exceed 16 bits.
pub fn decrypt_lo_hi(
    secret: &ElGamalSecretKey,
    lo: PodElGamalCiphertext,
    hi: PodElGamalCiphertext,
) -> Result<u64> {
    decrypt_u32(secret, hi)?
        .checked_mul(1 << TRANSFER_AMOUNT_LO_BITS)
        .and_then(|hi| hi.checked_add(decrypt_u32(secret, lo).ok()?))
        .ok_or_else(|| crypto("lo/hi amounts overflow or fail to decrypt"))
}

/// The owner's available (spendable) confidential balance.
pub fn available_balance(account: &AccountSnapshot, keys: &ConfidentialKeys) -> Result<u64> {
    let decryptable = AeCiphertext::try_from(
        account
            .require_confidential()?
            .decryptable_available_balance,
    )
    .map_err(|_| crypto("invalid decryptable balance"))?;
    keys.ae
        .decrypt(&decryptable)
        .ok_or_else(|| crypto("decryptable balance does not decrypt with this AE key"))
}

/// The owner's pending (not yet spendable) confidential balance.
pub fn pending_balance(account: &AccountSnapshot, keys: &ConfidentialKeys) -> Result<u64> {
    let confidential = account.require_confidential()?;
    decrypt_lo_hi(
        keys.elgamal.secret(),
        confidential.pending_balance_lo,
        confidential.pending_balance_hi,
    )
}

/// Fees withheld (encrypted) in `account` by confidential transfers, decrypted with the issuer's
/// withdraw-withheld ElGamal key.
pub fn withheld_confidential_fee(
    account: &AccountSnapshot,
    withdraw_withheld_authority: &ElGamalKeypair,
) -> Result<u64> {
    let withheld = account
        .confidential_withheld
        .ok_or_else(|| Error::Invalid("account has no ConfidentialTransferFeeAmount".into()))?;
    decrypt_u32(
        withdraw_withheld_authority.secret(),
        withheld.withheld_amount,
    )
}

/// `Reallocate` making room for the confidential extensions. `ConfidentialTransferFeeAmount` is
/// needed as well because the mint charges transfer fees. Owner-signed.
pub fn reallocate_instruction(
    token_account: &Address,
    payer: &Address,
    owner: &Address,
) -> Result<Instruction> {
    Ok(reallocate(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        payer,
        owner,
        &[],
        &[
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    )?)
}

/// `ConfigureAccount` followed by its inline `VerifyPubkeyValidity` proof, with `authority` signing.
/// Token-2022 accepts it only when `authority` is the account owner.
pub fn configure_instructions(
    token_account: &Address,
    mint: &Address,
    authority: &Address,
    keys: &ConfidentialKeys,
) -> Result<Vec<Instruction>> {
    let proof = build_pubkey_validity_proof_data(&keys.elgamal)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let decryptable_zero: DecryptableBalance = keys.ae.encrypt(0).into();
    Ok(ct::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        mint,
        &decryptable_zero,
        MAXIMUM_PENDING_BALANCE_CREDITS,
        authority,
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )?)
}

/// Step 1, owner only: reallocate and configure `token_account` for confidential transfers, in one
/// transaction. The account still cannot be used until the confidential authority approves it.
pub fn configure_account(
    cluster: &mut impl Cluster,
    token_account: &Address,
    owner: &Keypair,
    keys: &ConfidentialKeys,
) -> Result<()> {
    let mint = load_account(cluster, token_account)?.mint;
    let mut instructions = vec![reallocate_instruction(
        token_account,
        &cluster.payer(),
        &owner.pubkey(),
    )?];
    instructions.extend(configure_instructions(
        token_account,
        &mint,
        &owner.pubkey(),
        keys,
    )?);
    cluster.send(&instructions, &[owner])?;
    Ok(())
}

/// Step 2, issuer: approve a configured account (`auto_approve_new_accounts = false`).
pub fn approve_account(
    cluster: &mut impl Cluster,
    token_account: &Address,
    confidential_authority: &Keypair,
) -> Result<()> {
    let mint = load_account(cluster, token_account)?.mint;
    let instruction = ct::approve_account(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        &mint,
        &confidential_authority.pubkey(),
        &[],
    )?;
    cluster.send(&[instruction], &[confidential_authority])?;
    Ok(())
}

/// Step 3, owner: move `amount` from the public balance into the pending confidential balance.
/// The amount is visible in the instruction; later movements are not.
pub fn deposit(
    cluster: &mut impl Cluster,
    token_account: &Address,
    owner: &Keypair,
    amount: u64,
) -> Result<()> {
    let mint = load_mint(cluster, &load_account(cluster, token_account)?.mint)?;
    let instruction = ct::deposit(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        &mint.address,
        amount,
        mint.decimals,
        &owner.pubkey(),
        &[],
    )?;
    cluster.send(&[instruction], &[owner])?;
    Ok(())
}

/// Step 4, owner: fold the pending balance into the available balance. Returns the new available
/// balance.
pub fn apply_pending_balance(
    cluster: &mut impl Cluster,
    token_account: &Address,
    owner: &Keypair,
    keys: &ConfidentialKeys,
) -> Result<u64> {
    let account = load_account(cluster, token_account)?;
    let available = available_balance(&account, keys)?;
    let pending = pending_balance(&account, keys)?;
    let new_available = available + pending;
    let new_decryptable: DecryptableBalance = keys.ae.encrypt(new_available).into();
    // The counter tells the program which credits this new decryptable balance accounts for.
    let credits = u64::from(
        account
            .require_confidential()?
            .pending_balance_credit_counter,
    );
    let instruction = ct::apply_pending_balance(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        credits,
        &new_decryptable,
        &owner.pubkey(),
        &[],
    )?;
    cluster.send(&[instruction], &[owner])?;
    Ok(new_available)
}

/// What a confidential transfer revealed, and to whom.
#[derive(Clone, Copy, Debug)]
pub struct ConfidentialTransfer {
    /// Gross amount (known to sender, recipient and auditor only).
    pub amount: u64,
    /// Fee withheld, computed with `calculate_epoch_fee(current_epoch, amount)`.
    pub fee: u64,
    /// Epoch the fee schedule was taken from.
    pub epoch: u64,
    /// The transfer amount's low 16 bits, encrypted under the auditor key.
    pub auditor_ciphertext_lo: PodElGamalCiphertext,
    /// The transfer amount's high 32 bits, encrypted under the auditor key.
    pub auditor_ciphertext_hi: PodElGamalCiphertext,
}

impl ConfidentialTransfer {
    /// What the auditor learns: decrypt the transfer amount with the auditor secret key.
    pub fn audit(&self, auditor: &ElGamalKeypair) -> Result<u64> {
        decrypt_lo_hi(
            auditor.secret(),
            self.auditor_ciphertext_lo,
            self.auditor_ciphertext_hi,
        )
    }
}

/// Step 5, owner: send `amount` confidentially from `source` to `destination`.
///
/// The mint has a `TransferFeeConfig`, so this is a `TransferWithFee` backed by five proofs,
/// verified into context-state accounts first (see [`crate::proofs`]).
pub fn transfer(
    cluster: &mut impl Cluster,
    source: &Address,
    destination: &Address,
    owner: &Keypair,
    keys: &ConfidentialKeys,
    amount: u64,
) -> Result<ConfidentialTransfer> {
    let source_account = load_account(cluster, source)?;
    let destination_account = load_account(cluster, destination)?;
    let mint = load_mint(cluster, &source_account.mint)?;

    let source_state = source_account.require_confidential()?;
    let available = available_balance(&source_account, keys)?;
    if available < amount {
        return Err(Error::InsufficientConfidentialBalance {
            available,
            requested: amount,
        });
    }
    let destination_pubkey =
        ElGamalPubkey::try_from(destination_account.require_confidential()?.elgamal_pubkey)
            .map_err(|_| crypto("invalid destination ElGamal pubkey"))?;
    let confidential_mint = mint
        .confidential
        .ok_or_else(|| Error::Invalid("mint has no ConfidentialTransferMint".into()))?;
    let auditor = confidential_mint
        .auditor_elgamal_pubkey
        .get()
        .map(ElGamalPubkey::try_from)
        .transpose()
        .map_err(|_| crypto("invalid auditor ElGamal pubkey"))?;
    let withdraw_withheld = ElGamalPubkey::try_from(
        mint.confidential_fee
            .ok_or_else(|| Error::Invalid("mint has no ConfidentialTransferFeeConfig".into()))?
            .withdraw_withheld_authority_elgamal_pubkey,
    )
    .map_err(|_| crypto("invalid withdraw-withheld ElGamal pubkey"))?;

    // Same epoch-aware schedule selection as the public path (task 2): the program checks the fee
    // proof against `get_epoch_fee(Clock::epoch)`.
    let epoch = cluster.epoch();
    let fee_config = mint.require_transfer_fee()?;
    let schedule = fee_config.get_epoch_fee(epoch);
    let fee = crate::transfer::expected_fee(&mint, epoch, amount)?;

    let proof = transfer_with_fee_split_proof_data(
        &elgamal_ciphertext(source_state.available_balance)?,
        &AeCiphertext::try_from(source_state.decryptable_available_balance)
            .map_err(|_| crypto("invalid decryptable balance"))?,
        amount,
        &keys.elgamal,
        &keys.ae,
        &destination_pubkey,
        auditor.as_ref(),
        &withdraw_withheld,
        u16::from(schedule.transfer_fee_basis_points),
        u64::from(schedule.maximum_fee),
    )
    .map_err(|error| Error::Crypto(error.to_string()))?;

    let auditor_lo = proof
        .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_lo;
    let auditor_hi = proof
        .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_hi;
    let new_decryptable: DecryptableBalance = keys.ae.encrypt(available - amount).into();

    let mut accounts = ProofAccounts::default();
    let result = (|| {
        let equality = accounts.verify(
            cluster,
            ProofInstruction::VerifyCiphertextCommitmentEquality,
            &proof.equality_proof_data,
        )?;
        let amount_validity = accounts.verify(
            cluster,
            ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
            &proof
                .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
                .proof_data,
        )?;
        let fee_sigma = accounts.verify(
            cluster,
            ProofInstruction::VerifyPercentageWithCap,
            &proof.percentage_with_cap_proof_data,
        )?;
        let fee_validity = accounts.verify(
            cluster,
            ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity,
            &proof.fee_ciphertext_validity_proof_data,
        )?;
        let range = accounts.verify_via_record(
            cluster,
            ProofInstruction::VerifyBatchedRangeProofU256,
            &proof.range_proof_data,
        )?;
        let instructions = ct::transfer_with_fee(
            &TOKEN_2022_PROGRAM_ID,
            source,
            &mint.address,
            destination,
            &new_decryptable,
            &auditor_lo,
            &auditor_hi,
            &owner.pubkey(),
            &[],
            ProofLocation::ContextStateAccount(&equality),
            ProofLocation::ContextStateAccount(&amount_validity),
            ProofLocation::ContextStateAccount(&fee_sigma),
            ProofLocation::ContextStateAccount(&fee_validity),
            ProofLocation::ContextStateAccount(&range),
        )?;
        cluster.send(&instructions, &[owner])
    })();
    accounts.close_after(cluster, result)?;

    Ok(ConfidentialTransfer {
        amount,
        fee,
        epoch,
        auditor_ciphertext_lo: auditor_lo,
        auditor_ciphertext_hi: auditor_hi,
    })
}

/// Step 6, owner: move `amount` from the available confidential balance back to the public
/// balance. Pending funds are not spendable, so apply them first.
pub fn withdraw(
    cluster: &mut impl Cluster,
    token_account: &Address,
    owner: &Keypair,
    keys: &ConfidentialKeys,
    amount: u64,
) -> Result<()> {
    let account = load_account(cluster, token_account)?;
    let available = available_balance(&account, keys)?;
    if available < amount {
        return Err(Error::InsufficientConfidentialBalance {
            available,
            requested: amount,
        });
    }
    let available_ciphertext =
        elgamal_ciphertext(account.require_confidential()?.available_balance)?;
    withdraw_against(
        cluster,
        token_account,
        owner,
        keys,
        &available_ciphertext,
        available,
        amount,
    )
}

/// [`withdraw`] with the proofs built against an arbitrary `balance_ciphertext` that encrypts
/// `balance`, and no local checks. `withdraw` passes the account's available balance. The tests
/// pass the *pending* balance instead: the proofs are valid, and Token-2022 still rejects them
/// because it checks them against the real available balance. The chain enforces "apply before
/// spend", not the client.
pub fn withdraw_against(
    cluster: &mut impl Cluster,
    token_account: &Address,
    owner: &Keypair,
    keys: &ConfidentialKeys,
    balance_ciphertext: &ElGamalCiphertext,
    balance: u64,
    amount: u64,
) -> Result<()> {
    let account = load_account(cluster, token_account)?;
    let mint = load_mint(cluster, &account.mint)?;
    let proof = withdraw_proof_data(balance_ciphertext, balance, amount, &keys.elgamal)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let new_decryptable: DecryptableBalance = keys.ae.encrypt(balance - amount).into();

    let mut accounts = ProofAccounts::default();
    let result = (|| {
        let equality = accounts.verify(
            cluster,
            ProofInstruction::VerifyCiphertextCommitmentEquality,
            &proof.equality_proof_data,
        )?;
        let range = accounts.verify(
            cluster,
            ProofInstruction::VerifyBatchedRangeProofU64,
            &proof.range_proof_data,
        )?;
        let instructions = ct::withdraw(
            &TOKEN_2022_PROGRAM_ID,
            token_account,
            &mint.address,
            amount,
            mint.decimals,
            &new_decryptable,
            &owner.pubkey(),
            &[],
            ProofLocation::ContextStateAccount(&equality),
            ProofLocation::ContextStateAccount(&range),
        )?;
        cluster.send(&instructions, &[owner])
    })();
    accounts.close_after(cluster, result).map(|_| ())
}
