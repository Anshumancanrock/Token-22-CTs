//! Plain token-account helpers shared by the flows and the tests.

use {
    crate::{
        state::{load_account, load_mint},
        Cluster, Result, TOKEN_2022_PROGRAM_ID,
    },
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_associated_token_account_interface::{
        address::get_associated_token_address_with_program_id,
        instruction::create_associated_token_account,
    },
    spl_token_2022_interface::{
        extension::{
            cpi_guard::instruction::enable_cpi_guard as enable_cpi_guard_instruction, ExtensionType,
        },
        instruction::{approve_checked, mint_to_checked, reallocate},
    },
};

/// `owner`'s associated token account for `mint` under Token-2022.
pub fn associated_token_address(owner: &Address, mint: &Address) -> Address {
    get_associated_token_address_with_program_id(owner, mint, &TOKEN_2022_PROGRAM_ID)
}

/// Create `owner`'s associated token account, paid by the cluster payer.
///
/// Anyone can do this for anyone: the ATA program needs no signature from the owner. That is why
/// the confidential-transfer configuration is a separate, owner-signed step (see
/// [`crate::confidential::configure_account`]).
pub fn create_token_account(
    cluster: &mut impl Cluster,
    owner: &Address,
    mint: &Address,
) -> Result<Address> {
    let instruction =
        create_associated_token_account(&cluster.payer(), owner, mint, &TOKEN_2022_PROGRAM_ID);
    cluster.send(&[instruction], &[])?;
    Ok(associated_token_address(owner, mint))
}

/// Mint `amount` base units into `destination`.
pub fn mint_to(
    cluster: &mut impl Cluster,
    mint: &Address,
    destination: &Address,
    mint_authority: &Keypair,
    amount: u64,
) -> Result<()> {
    let decimals = load_mint(cluster, mint)?.decimals;
    let instruction = mint_to_checked(
        &TOKEN_2022_PROGRAM_ID,
        mint,
        destination,
        &mint_authority.pubkey(),
        &[],
        amount,
        decimals,
    )?;
    cluster.send(&[instruction], &[mint_authority])?;
    Ok(())
}

/// Owner grants `delegate` an allowance of `amount` on `source` (a top-level `ApproveChecked`).
pub fn approve(
    cluster: &mut impl Cluster,
    source: &Address,
    delegate: &Address,
    owner: &Keypair,
    amount: u64,
) -> Result<()> {
    let mint = load_account(cluster, source)?.mint;
    let decimals = load_mint(cluster, &mint)?.decimals;
    let instruction = approve_checked(
        &TOKEN_2022_PROGRAM_ID,
        source,
        &mint,
        delegate,
        &owner.pubkey(),
        &[],
        amount,
        decimals,
    )?;
    cluster.send(&[instruction], &[owner])?;
    Ok(())
}

/// Owner turns on CPI Guard: `Reallocate` room for the `CpiGuard` extension, then `EnableCpiGuard`,
/// both top-level and in one transaction. (CPI Guard cannot be toggled through CPI.)
pub fn enable_cpi_guard(
    cluster: &mut impl Cluster,
    token_account: &Address,
    owner: &Keypair,
) -> Result<()> {
    let reallocate = reallocate(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        &cluster.payer(),
        &owner.pubkey(),
        &[],
        &[ExtensionType::CpiGuard],
    )?;
    let enable =
        enable_cpi_guard_instruction(&TOKEN_2022_PROGRAM_ID, token_account, &owner.pubkey(), &[])?;
    cluster.send(&[reallocate, enable], &[owner])?;
    Ok(())
}
