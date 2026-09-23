//! Seizure with the permanent delegate (task 5 mint).
//!
//! Token-2022 refuses to move tokens out of a frozen account, even when the permanent delegate
//! asks. A sanctioned account is normally frozen, so seizure is one atomic transaction: thaw,
//! transfer as the permanent delegate, freeze again. The account is never usable in between.
//!
//! The permanent delegate reaches only the **public** balance (`amount`). Confidential balances are
//! ciphertexts that only the owner's ElGamal key can spend. See the README finding.

use {
    crate::{
        state::{load_account, load_mint},
        transfer::{expected_fee, FeeTransfer},
        Cluster, Result, TOKEN_2022_PROGRAM_ID,
    },
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{
        extension::transfer_fee::instruction::transfer_checked_with_fee,
        instruction::{freeze_account, thaw_account},
    },
};

/// Move `amount` of `from`'s public balance to `to` as the permanent delegate. If `from` is frozen
/// it is thawed and re-frozen within the same transaction.
pub fn seize(
    cluster: &mut impl Cluster,
    from: &Address,
    to: &Address,
    freeze_authority: &Keypair,
    permanent_delegate: &Keypair,
    amount: u64,
) -> Result<FeeTransfer> {
    let account = load_account(cluster, from)?;
    let mint = load_mint(cluster, &account.mint)?;
    let epoch = cluster.epoch();
    let fee = expected_fee(&mint, epoch, amount)?;
    let transfer = transfer_checked_with_fee(
        &TOKEN_2022_PROGRAM_ID,
        from,
        &mint.address,
        to,
        &permanent_delegate.pubkey(),
        &[],
        amount,
        mint.decimals,
        fee,
    )?;
    let freeze = &freeze_authority.pubkey();
    if account.is_frozen() {
        let instructions = [
            thaw_account(&TOKEN_2022_PROGRAM_ID, from, &mint.address, freeze, &[])?,
            transfer,
            freeze_account(&TOKEN_2022_PROGRAM_ID, from, &mint.address, freeze, &[])?,
        ];
        cluster.send(&instructions, &[freeze_authority, permanent_delegate])?;
    } else {
        cluster.send(&[transfer], &[permanent_delegate])?;
    }
    Ok(FeeTransfer { amount, fee, epoch })
}
