//! Task 1: TransferFeeConfig + MetadataPointer (-> the mint) + DefaultAccountState(Frozen) +
//! MintCloseAuthority, sized with `try_calculate_account_len`, every init before InitializeMint.

mod common;

use {
    common::*,
    remit::{
        mint::{self, V1_EXTENSIONS},
        Cluster,
    },
    solana_address::Address,
    solana_instruction::error::InstructionError,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_system_interface::instruction::create_account,
    spl_token_2022_interface::{
        error::TokenError,
        extension::ExtensionType,
        instruction::{burn_checked, initialize_mint2, TokenInstruction},
        state::{AccountState, Mint},
    },
};

#[test]
fn mint_carries_the_four_extensions_and_is_sized_exactly() {
    let coin = Stablecoin::v1();
    let mint = coin.mint();

    // Allocation = try_calculate_account_len over exactly the four fixed-size extensions.
    let fixed = ExtensionType::try_calculate_account_len::<Mint>(&V1_EXTENSIONS).unwrap();
    assert_eq!(coin.plan.extensions, V1_EXTENSIONS);
    assert_eq!(coin.plan.space, fixed);

    // On-chain: the four extensions, then the TokenMetadata entry written after InitializeMint.
    let mut expected = V1_EXTENSIONS.to_vec();
    expected.push(ExtensionType::TokenMetadata);
    assert_eq!(mint.extensions, expected);
    assert_eq!(mint.data_len, fixed + coin.plan.metadata_len);
    // Funded up front for the final size: exactly rent-exempt, nothing wasted.
    assert_eq!(
        mint.lamports,
        coin.svm.minimum_balance_for_rent_exemption(mint.data_len)
    );

    let fee = mint.transfer_fee.unwrap();
    for schedule in [fee.older_transfer_fee, fee.newer_transfer_fee] {
        assert_eq!(u16::from(schedule.transfer_fee_basis_points), 25);
        assert_eq!(u64::from(schedule.maximum_fee), 2_500_000);
    }
    assert_eq!(
        fee.transfer_fee_config_authority.get(),
        Some(coin.authorities.fee_config.pubkey())
    );
    assert_eq!(
        fee.withdraw_withheld_authority.get(),
        Some(coin.authorities.fee_withdraw.pubkey())
    );

    let pointer = mint.metadata_pointer.unwrap();
    assert_eq!(
        pointer.metadata_address.get(),
        Some(coin.mint),
        "points at itself"
    );
    assert_eq!(
        pointer.authority.get(),
        Some(coin.authorities.metadata.pubkey())
    );

    assert_eq!(mint.default_account_state, Some(AccountState::Frozen));
    assert_eq!(mint.close_authority, Some(coin.authorities.close.pubkey()));
    assert_eq!(
        mint.freeze_authority,
        Some(coin.authorities.freeze.pubkey())
    );
    assert_eq!(mint.mint_authority, Some(coin.authorities.mint.pubkey()));
    assert_eq!(mint.decimals, 6);

    // The metadata a wallet reads is in the mint account itself.
    let metadata = mint.metadata.unwrap();
    assert_eq!(metadata.mint, coin.mint);
    assert_eq!(metadata.name, "Remit USD");
    assert_eq!(metadata.symbol, "rUSD");
    assert_eq!(
        metadata.additional_metadata,
        coin.params.additional_metadata
    );
    assert_eq!(
        metadata.update_authority.get(),
        Some(coin.authorities.metadata.pubkey())
    );
}

#[test]
fn every_extension_init_comes_before_initialize_mint() {
    let coin = Stablecoin::v1();
    let initialize = &coin.plan.initialize;
    assert_eq!(
        initialize[0].program_id,
        solana_system_interface::program::ID
    );

    let decoded: Vec<TokenInstruction> = initialize[1..]
        .iter()
        .map(|ix| TokenInstruction::unpack(&ix.data).unwrap())
        .collect();
    let (last, inits) = decoded.split_last().unwrap();
    assert!(matches!(last, TokenInstruction::InitializeMint2 { .. }));
    assert!(matches!(
        inits,
        [
            TokenInstruction::TransferFeeExtension,
            TokenInstruction::MetadataPointerExtension,
            TokenInstruction::DefaultAccountStateExtension,
            TokenInstruction::InitializeMintCloseAuthority { .. },
        ]
    ));
    // Metadata comes after, in its own transaction, because it needs the mint authority.
    assert!(coin
        .plan
        .metadata
        .iter()
        .all(|ix| ix.program_id == remit::TOKEN_2022_PROGRAM_ID));
}

fn fresh_plan(svm: &Svm, mint: &Address) -> (remit::mint::Authorities, remit::mint::MintPlan) {
    let authorities = remit::mint::Authorities::generate();
    let plan = mint::plan_v1(svm, mint, &authorities, &Default::default()).unwrap();
    (authorities, plan)
}

#[test]
fn initialize_mint_before_the_extension_inits_is_rejected() {
    let mut svm = Svm::new();
    let mint = Keypair::new();
    let (_, plan) = fresh_plan(&svm, &mint.pubkey());
    let mut reordered = plan.initialize.clone();
    let init_mint = reordered.pop().unwrap();
    reordered.insert(1, init_mint);

    // The account is sized for four extensions but none is initialized yet, so InitializeMint sees
    // a length that matches no extension set.
    assert_instruction_error(
        svm.send(&reordered, &[&mint]),
        1,
        InstructionError::InvalidAccountData,
    );
}

#[test]
fn allocating_the_metadata_up_front_is_rejected() {
    let mut svm = Svm::new();
    let mint = Keypair::new();
    let (_, plan) = fresh_plan(&svm, &mint.pubkey());
    let mut oversized = plan.initialize.clone();
    oversized[0] = create_account(
        &svm.payer(),
        &mint.pubkey(),
        plan.lamports,
        (plan.space + plan.metadata_len) as u64,
        &remit::TOKEN_2022_PROGRAM_ID,
    );

    // InitializeMint demands len == try_calculate_account_len(fixed extensions), not more.
    assert_instruction_error(
        svm.send(&oversized, &[&mint]),
        5,
        InstructionError::InvalidAccountData,
    );
}

#[test]
fn a_frozen_default_needs_a_freeze_authority() {
    let mut svm = Svm::new();
    let mint = Keypair::new();
    let (authorities, plan) = fresh_plan(&svm, &mint.pubkey());
    let mut no_freeze = plan.initialize.clone();
    *no_freeze.last_mut().unwrap() = initialize_mint2(
        &remit::TOKEN_2022_PROGRAM_ID,
        &mint.pubkey(),
        &authorities.mint.pubkey(),
        None,
        6,
    )
    .unwrap();

    assert_token_error(svm.send(&no_freeze, &[&mint]), TokenError::MintCannotFreeze);
}

#[test]
fn close_authority_decommissions_the_mint_once_supply_is_zero() {
    let mut coin = Stablecoin::v1();
    let holder = Keypair::new();
    let account = coin.onboard(&holder);
    coin.fund(&account, 5 * RUSD);
    let refund = Keypair::new().pubkey();
    let mint = coin.mint;

    // Only the close authority may close it.
    let stranger = Keypair::new();
    assert_token_error(
        mint::close_mint(&mut coin.svm, &mint, &stranger, &refund),
        TokenError::OwnerMismatch,
    );
    // Not while tokens exist.
    assert_token_error(
        mint::close_mint(&mut coin.svm, &mint, &coin.authorities.close, &refund),
        TokenError::MintHasSupply,
    );

    let burn = burn_checked(
        &remit::TOKEN_2022_PROGRAM_ID,
        &account,
        &mint,
        &holder.pubkey(),
        &[],
        5 * RUSD,
        6,
    )
    .unwrap();
    coin.svm.send(&[burn], &[&holder]).unwrap();
    assert_eq!(coin.mint().supply, 0);

    let rent = coin.mint().lamports;
    mint::close_mint(&mut coin.svm, &mint, &coin.authorities.close, &refund).unwrap();
    assert!(coin.svm.account_data(&mint).is_none());
    assert_eq!(coin.svm.lamports(&refund), rent);
}
