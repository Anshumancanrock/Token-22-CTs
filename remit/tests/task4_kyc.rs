//! Task 4: the freeze authority thaws one account after KYC; the mint-level default is separate.

mod common;

use {
    common::*,
    remit::{
        kyc::{approve_kyc, revoke_kyc, set_default_account_state},
        token::{create_token_account, mint_to},
        transfer::transfer_with_fee,
        Cluster, TOKEN_2022_PROGRAM_ID,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_system_interface::instruction::create_account,
    spl_token_2022_interface::{
        error::TokenError,
        extension::ExtensionType,
        instruction::{initialize_account3, set_authority, thaw_account, AuthorityType},
        state::{Account, AccountState},
    },
};

#[test]
fn accounts_anyone_opens_start_frozen_and_cannot_receive() {
    let mut coin = Stablecoin::v1();
    let alice = Keypair::new();
    // The harness payer, not Alice, creates her account.
    let account = create_token_account(&mut coin.svm, &alice.pubkey(), &coin.mint).unwrap();
    assert_eq!(coin.account(&account).state, AccountState::Frozen);

    let mint = coin.mint;
    assert_token_error(
        mint_to(&mut coin.svm, &mint, &account, &coin.authorities.mint, RUSD),
        TokenError::AccountFrozen,
    );
}

#[test]
fn only_the_freeze_authority_can_clear_kyc() {
    let mut coin = Stablecoin::v1();
    let alice = Keypair::new();
    let account = create_token_account(&mut coin.svm, &alice.pubkey(), &coin.mint).unwrap();

    // Not the owner (no self-certified KYC), not a stranger.
    for impostor in [&alice, &Keypair::new(), &coin.authorities.mint] {
        assert_token_error(
            approve_kyc(&mut coin.svm, &account, impostor),
            TokenError::OwnerMismatch,
        );
    }
    approve_kyc(&mut coin.svm, &account, &coin.authorities.freeze).unwrap();
    assert_eq!(coin.account(&account).state, AccountState::Initialized);
}

#[test]
fn thawing_one_account_leaves_the_default_and_every_other_account_frozen() {
    let mut coin = Stablecoin::v1();
    let alice = Keypair::new();
    let alice_account = create_token_account(&mut coin.svm, &alice.pubkey(), &coin.mint).unwrap();
    let bob_account =
        create_token_account(&mut coin.svm, &Keypair::new().pubkey(), &coin.mint).unwrap();

    approve_kyc(&mut coin.svm, &alice_account, &coin.authorities.freeze).unwrap();

    assert_eq!(
        coin.account(&alice_account).state,
        AccountState::Initialized
    );
    assert_eq!(coin.account(&bob_account).state, AccountState::Frozen);
    assert_eq!(
        coin.mint().default_account_state,
        Some(AccountState::Frozen)
    );
    let carol_account =
        create_token_account(&mut coin.svm, &Keypair::new().pubkey(), &coin.mint).unwrap();
    assert_eq!(coin.account(&carol_account).state, AccountState::Frozen);

    // Alice is live; Bob cannot receive until his own KYC clears.
    coin.fund(&alice_account, 50 * RUSD);
    assert_token_error(
        transfer_with_fee(&mut coin.svm, &alice_account, &bob_account, &alice, RUSD),
        TokenError::AccountFrozen,
    );
    approve_kyc(&mut coin.svm, &bob_account, &coin.authorities.freeze).unwrap();
    transfer_with_fee(&mut coin.svm, &alice_account, &bob_account, &alice, RUSD).unwrap();
}

#[test]
fn changing_the_default_does_not_thaw_existing_accounts() {
    // The mint-level switch is a different control: it affects future accounts only.
    let mut coin = Stablecoin::v1();
    let bob_account =
        create_token_account(&mut coin.svm, &Keypair::new().pubkey(), &coin.mint).unwrap();
    let mint = coin.mint;
    set_default_account_state(
        &mut coin.svm,
        &mint,
        &coin.authorities.freeze,
        AccountState::Initialized,
    )
    .unwrap();

    assert_eq!(coin.account(&bob_account).state, AccountState::Frozen);
    let dave_account =
        create_token_account(&mut coin.svm, &Keypair::new().pubkey(), &coin.mint).unwrap();
    assert_eq!(coin.account(&dave_account).state, AccountState::Initialized);
}

#[test]
fn kyc_can_be_revoked() {
    let mut coin = Stablecoin::v1();
    let alice = Keypair::new();
    let alice_account = coin.onboard(&alice);
    let bob_account = coin.onboard(&Keypair::new());
    coin.fund(&alice_account, 10 * RUSD);

    revoke_kyc(&mut coin.svm, &alice_account, &coin.authorities.freeze).unwrap();
    assert_token_error(
        transfer_with_fee(&mut coin.svm, &alice_account, &bob_account, &alice, RUSD),
        TokenError::AccountFrozen,
    );
    assert_eq!(coin.account(&alice_account).amount, 10 * RUSD);
}

#[test]
fn kyc_is_only_granted_to_accounts_whose_owner_cannot_change() {
    let mut coin = Stablecoin::v1();
    let alice = Keypair::new();

    // A token account at its own address, created without ImmutableOwner.
    let loose = Keypair::new();
    let space =
        ExtensionType::try_calculate_account_len::<Account>(&[ExtensionType::TransferFeeAmount])
            .unwrap();
    let rent = coin.svm.minimum_balance_for_rent_exemption(space);
    let payer = coin.svm.payer();
    coin.svm
        .send(
            &[
                create_account(
                    &payer,
                    &loose.pubkey(),
                    rent,
                    space as u64,
                    &TOKEN_2022_PROGRAM_ID,
                ),
                initialize_account3(
                    &TOKEN_2022_PROGRAM_ID,
                    &loose.pubkey(),
                    &coin.mint,
                    &alice.pubkey(),
                )
                .unwrap(),
            ],
            &[&loose],
        )
        .unwrap();
    assert!(coin.account(&loose.pubkey()).is_frozen());

    // The library will not clear KYC for it.
    let error = approve_kyc(&mut coin.svm, &loose.pubkey(), &coin.authorities.freeze).unwrap_err();
    assert!(error.to_string().contains("ImmutableOwner"), "{error}");

    // Why: once thawed, Alice can hand the verified account to someone who never did KYC.
    let thaw = thaw_account(
        &TOKEN_2022_PROGRAM_ID,
        &loose.pubkey(),
        &coin.mint,
        &coin.authorities.freeze.pubkey(),
        &[],
    )
    .unwrap();
    coin.svm.send(&[thaw], &[&coin.authorities.freeze]).unwrap();
    let stranger = Keypair::new().pubkey();
    let hand_over = |account: &solana_address::Address| {
        set_authority(
            &TOKEN_2022_PROGRAM_ID,
            account,
            Some(&stranger),
            AuthorityType::AccountOwner,
            &alice.pubkey(),
            &[],
        )
        .unwrap()
    };
    coin.svm
        .send(&[hand_over(&loose.pubkey())], &[&alice])
        .unwrap();
    let sold = coin.account(&loose.pubkey());
    assert_eq!((sold.owner, sold.is_frozen()), (stranger, false));

    // An ATA carries ImmutableOwner, so the same hand-over fails there.
    let ata = coin.onboard(&alice);
    assert_token_error(
        coin.svm.send(&[hand_over(&ata)], &[&alice]),
        TokenError::ImmutableOwner,
    );
}
