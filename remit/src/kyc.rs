//! **Task 4: the unfreeze (KYC) path.**
//!
//! `DefaultAccountState(Frozen)` makes every new token account start frozen, including ATAs that
//! anyone can create for anyone. A frozen account can neither receive (not even `MintTo`) nor send.
//!
//! Clearing KYC thaws one account with `ThawAccount`, signed by the mint's freeze authority. The
//! mint-level default (`UpdateDefaultAccountState`) is never touched, so accounts opened afterwards
//! still start frozen, and other accounts that are still frozen stay frozen. The reverse also holds:
//! changing the default does not thaw existing accounts. Per-account KYC and the mint-wide policy
//! are separate controls.

use {
    crate::{state::load_account, Cluster, Error, Result, TOKEN_2022_PROGRAM_ID},
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{
        extension::default_account_state::instruction::update_default_account_state,
        instruction::{freeze_account, thaw_account},
        state::AccountState,
    },
};

/// KYC cleared: thaw `token_account` so it can receive and send.
pub fn approve_kyc(
    cluster: &mut impl Cluster,
    token_account: &Address,
    freeze_authority: &Keypair,
) -> Result<()> {
    let account = load_account(cluster, token_account)?;
    if !account.is_frozen() {
        return Err(Error::Invalid(format!(
            "{token_account} is not frozen; KYC was already approved"
        )));
    }
    let instruction = thaw_account(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        &account.mint,
        &freeze_authority.pubkey(),
        &[],
    )?;
    cluster.send(&[instruction], &[freeze_authority])?;
    Ok(())
}

/// KYC revoked (e.g. the owner is sanctioned): freeze `token_account` again.
pub fn revoke_kyc(
    cluster: &mut impl Cluster,
    token_account: &Address,
    freeze_authority: &Keypair,
) -> Result<()> {
    let account = load_account(cluster, token_account)?;
    if account.is_frozen() {
        return Err(Error::Invalid(format!("{token_account} is already frozen")));
    }
    let instruction = freeze_account(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        &account.mint,
        &freeze_authority.pubkey(),
        &[],
    )?;
    cluster.send(&[instruction], &[freeze_authority])?;
    Ok(())
}

/// Mint-wide policy change: the state *new* accounts start in. It does not touch any existing
/// account, and the KYC path never calls it.
pub fn set_default_account_state(
    cluster: &mut impl Cluster,
    mint: &Address,
    freeze_authority: &Keypair,
    state: AccountState,
) -> Result<()> {
    let instruction = update_default_account_state(
        &TOKEN_2022_PROGRAM_ID,
        mint,
        &freeze_authority.pubkey(),
        &[],
        &state,
    )?;
    cluster.send(&[instruction], &[freeze_authority])?;
    Ok(())
}
