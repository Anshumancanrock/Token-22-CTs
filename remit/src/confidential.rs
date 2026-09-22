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
        state::{load_account, load_mint, AccountSnapshot},
        Cluster, Error, Result, TOKEN_2022_PROGRAM_ID,
    },
    solana_address::Address,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            derivation::derive_confidential_keys,
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalSecretKey},
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
    spl_token_confidential_transfer_proof_generation::TRANSFER_AMOUNT_LO_BITS,
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
