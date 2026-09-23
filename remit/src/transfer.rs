//! **Task 2: transfers go through `transfer_checked_with_fee`.**
//!
//! The fee is recomputed for every transfer from the mint's live `TransferFeeConfig` and the live
//! epoch: `calculate_epoch_fee(current_epoch, amount)`. It is never taken from a cached rate.
//!
//! A cached rate goes wrong because `TransferFeeConfig` holds two fee schedules. `SetTransferFee`
//! writes the new schedule into `newer_transfer_fee` with `epoch = current + 2`, and until that
//! epoch arrives the program keeps charging `older_transfer_fee`. A client that caches "the fee"
//! or reads `newer_transfer_fee` directly is wrong for part of that window.
//! `calculate_epoch_fee` picks the schedule the program will use in the given epoch.
//!
//! Token-2022 computes the same number on-chain and rejects the transfer with `FeeMismatch` when
//! the two differ. `TransferCheckedWithFee` therefore works as a guard: the sender never pays a fee
//! it did not sign for, even if the epoch rolls over between signing and execution.

use {
    crate::{
        state::{load_account, load_mint, MintSnapshot},
        Cluster, Error, Result, TOKEN_2022_PROGRAM_ID,
    },
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::extension::transfer_fee::instruction::{
        harvest_withheld_tokens_to_mint, set_transfer_fee as set_transfer_fee_instruction,
        transfer_checked_with_fee, withdraw_withheld_tokens_from_mint,
    },
};

/// What a fee-bearing transfer moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeTransfer {
    /// Gross amount debited from the source.
    pub amount: u64,
    /// Fee stated in the instruction and withheld in the destination account (issuer revenue).
    /// Token-2022 still checks it on a self-transfer, but withholds nothing there.
    pub fee: u64,
    /// Epoch the fee was computed for.
    pub epoch: u64,
}

impl FeeTransfer {
    /// Amount the recipient can spend.
    pub fn net(&self) -> u64 {
        self.amount - self.fee
    }
}

/// Fee Token-2022 will charge for `amount` in `epoch`, from the mint's `TransferFeeConfig`.
pub fn expected_fee(mint: &MintSnapshot, epoch: u64, amount: u64) -> Result<u64> {
    mint.require_transfer_fee()?
        .calculate_epoch_fee(epoch, amount)
        .ok_or_else(|| Error::Invalid(format!("fee on {amount} overflows")))
}

/// Move `amount` from `source` to `destination` with `TransferCheckedWithFee`.
///
/// `authority` is the source owner or its delegate. The fee is computed from the mint state and the
/// epoch fetched for this call.
pub fn transfer_with_fee(
    cluster: &mut impl Cluster,
    source: &Address,
    destination: &Address,
    authority: &Keypair,
    amount: u64,
) -> Result<FeeTransfer> {
    let mint_address = load_account(cluster, source)?.mint;
    let mint = load_mint(cluster, &mint_address)?;
    let epoch = cluster.epoch();
    let fee = expected_fee(&mint, epoch, amount)?;
    let instruction = transfer_checked_with_fee(
        &TOKEN_2022_PROGRAM_ID,
        source,
        &mint_address,
        destination,
        &authority.pubkey(),
        &[],
        amount,
        mint.decimals,
        fee,
    )?;
    cluster.send(&[instruction], &[authority])?;
    Ok(FeeTransfer { amount, fee, epoch })
}

/// Schedule a new fee. Token-2022 applies it from `current epoch + 2`; until then the old fee holds.
pub fn set_transfer_fee(
    cluster: &mut impl Cluster,
    mint: &Address,
    fee_authority: &Keypair,
    transfer_fee_basis_points: u16,
    maximum_fee: u64,
) -> Result<()> {
    let instruction = set_transfer_fee_instruction(
        &TOKEN_2022_PROGRAM_ID,
        mint,
        &fee_authority.pubkey(),
        &[],
        transfer_fee_basis_points,
        maximum_fee,
    )?;
    cluster.send(&[instruction], &[fee_authority])?;
    Ok(())
}

/// Collect issuer revenue: sweep withheld fees from `sources` into the mint (permissionless), then
/// withdraw everything the mint holds to `treasury` (withdraw-withheld authority only). Returns the
/// amount collected.
///
/// `treasury` is an ordinary token account of this mint, so it must have cleared KYC (be thawed) to
/// receive.
pub fn collect_fees(
    cluster: &mut impl Cluster,
    mint: &Address,
    sources: &[Address],
    treasury: &Address,
    withdraw_authority: &Keypair,
) -> Result<u64> {
    let before = load_account(cluster, treasury)?.amount;
    let sources: Vec<&Address> = sources.iter().collect();
    let harvest = harvest_withheld_tokens_to_mint(&TOKEN_2022_PROGRAM_ID, mint, &sources)?;
    let withdraw = withdraw_withheld_tokens_from_mint(
        &TOKEN_2022_PROGRAM_ID,
        mint,
        treasury,
        &withdraw_authority.pubkey(),
        &[],
    )?;
    cluster.send(&[harvest, withdraw], &[withdraw_authority])?;
    Ok(load_account(cluster, treasury)?.amount - before)
}
