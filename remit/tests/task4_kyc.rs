//! Task 4: the freeze authority thaws one account after KYC; the mint-level default is separate.

mod common;

use {
    common::*,
    remit::{
        kyc::{approve_kyc, revoke_kyc, set_default_account_state},
        token::{create_token_account, mint_to},
        transfer::transfer_with_fee,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{error::TokenError, state::AccountState},
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
