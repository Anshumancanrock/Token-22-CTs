//! Task 5: re-issue with the v1 extension set carried forward, plus PermanentDelegate and
//! confidential transfers with approve_policy = manual.

mod common;

use {
    common::*,
    remit::{
        mint::{
            self, v1_extension_inits, v2_added_extension_inits, V1_EXTENSIONS, V2_ADDED_EXTENSIONS,
        },
        transfer::transfer_with_fee,
        Cluster,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    spl_token_2022_interface::{
        error::TokenError,
        extension::{confidential_transfer, ExtensionType},
        instruction::burn_checked,
        state::{AccountState, Mint},
    },
};

#[test]
fn reissued_mint_keeps_the_v1_set_and_adds_seizure_and_confidentiality() {
    let coin = Stablecoin::v2();
    let mint = coin.mint();

    let all: Vec<ExtensionType> = V1_EXTENSIONS
        .iter()
        .chain(&V2_ADDED_EXTENSIONS)
        .copied()
        .collect();
    assert_eq!(coin.plan.extensions, all);
    assert_eq!(
        coin.plan.space,
        ExtensionType::try_calculate_account_len::<Mint>(&all).unwrap()
    );
    let mut on_chain = all.clone();
    on_chain.push(ExtensionType::TokenMetadata);
    assert_eq!(mint.extensions, on_chain);
    assert_eq!(
        mint.lamports,
        coin.svm.minimum_balance_for_rent_exemption(mint.data_len)
    );

    // Carried forward.
    assert!(mint.transfer_fee.is_some());
    assert_eq!(
        mint.metadata_pointer.unwrap().metadata_address.get(),
        Some(coin.mint)
    );
    assert_eq!(mint.default_account_state, Some(AccountState::Frozen));
    assert_eq!(mint.close_authority, Some(coin.authorities.close.pubkey()));

    // Added.
    assert_eq!(
        mint.permanent_delegate,
        Some(coin.compliance.seizure.pubkey())
    );
    let confidential = mint.confidential.unwrap();
    assert_eq!(
        confidential.authority.get(),
        Some(coin.compliance.confidential.pubkey())
    );
    assert!(
        !bool::from(confidential.auto_approve_new_accounts),
        "manual approval"
    );
    assert_eq!(
        confidential.auditor_elgamal_pubkey.get(),
        Some(PodElGamalPubkey::from(
            coin.compliance.auditor.pubkey_owned()
        ))
    );
    let fee = mint.confidential_fee.unwrap();
    assert_eq!(
        fee.withdraw_withheld_authority_elgamal_pubkey,
        PodElGamalPubkey::from(coin.compliance.fee_withdraw_elgamal.pubkey_owned())
    );
}

#[test]
fn fee_mint_rejects_confidential_transfers_without_a_confidential_fee_config() {
    // The gap in "same extensions + confidentiality": a public fee cannot be charged on an encrypted
    // amount, so Token-2022 insists on ConfidentialTransferFeeConfig as well.
    let mut coin = Stablecoin::v1();
    let mint = Keypair::new();
    let mut inits = v1_extension_inits(&mint.pubkey(), &coin.authorities, &coin.params).unwrap();
    inits.extend(
        v2_added_extension_inits(&mint.pubkey(), &coin.authorities, &coin.compliance)
            .unwrap()
            .into_iter()
            .filter(|(extension, _)| *extension != ExtensionType::ConfidentialTransferFeeConfig),
    );
    let plan = mint::plan_from_inits(
        &coin.svm,
        &mint.pubkey(),
        &coin.authorities,
        &coin.params,
        inits,
    )
    .unwrap();
    assert_token_error(
        coin.svm.send(&plan.initialize, &[&mint]),
        TokenError::InvalidExtensionCombination,
    );
}

#[test]
fn confidential_transfers_cannot_be_bolted_onto_the_live_v1_mint() {
    // Why task 5 is a re-issue: extension inits only work before InitializeMint.
    let mut coin = Stablecoin::v1();
    let instruction = confidential_transfer::instruction::initialize_mint(
        &remit::TOKEN_2022_PROGRAM_ID,
        &coin.mint,
        Some(coin.compliance.confidential.pubkey()),
        false,
        None,
    )
    .unwrap();
    assert_token_error(coin.svm.send(&[instruction], &[]), TokenError::AlreadyInUse);
}

#[test]
fn permanent_delegate_seizes_and_burns_public_balances_without_the_owner() {
    let mut coin = Stablecoin::v2();
    let mallory = Keypair::new();
    let mallory_account = coin.onboard(&mallory);
    let evidence = coin.onboard(&Keypair::new());
    coin.fund(&mallory_account, 1_000 * RUSD);

    let seized = transfer_with_fee(
        &mut coin.svm,
        &mallory_account,
        &evidence,
        &coin.compliance.seizure,
        400 * RUSD,
    )
    .unwrap();
    assert_eq!(coin.account(&evidence).amount, 400 * RUSD - seized.fee);

    let burn = burn_checked(
        &remit::TOKEN_2022_PROGRAM_ID,
        &mallory_account,
        &coin.mint,
        &coin.compliance.seizure.pubkey(),
        &[],
        100 * RUSD,
        6,
    )
    .unwrap();
    coin.svm.send(&[burn], &[&coin.compliance.seizure]).unwrap();

    assert_eq!(coin.account(&mallory_account).amount, 500 * RUSD);
    assert_eq!(coin.mint().supply, 900 * RUSD);
}
