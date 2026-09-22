//! Evidence for the written finding: a sanctioned user moves their balance into the confidential
//! system before the permanent delegate acts.

mod common;

use {
    common::*,
    remit::{
        compliance::seize,
        confidential::{
            apply_pending_balance, available_balance, deposit, pending_balance, transfer, withdraw,
        },
        kyc::{approve_kyc, revoke_kyc},
        mint::close_mint,
        Cluster,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{
        error::TokenError,
        extension::confidential_transfer::instruction::apply_pending_balance as apply_instruction,
        instruction::burn_checked,
    },
};

#[test]
fn a_deposit_that_lands_first_puts_the_funds_out_of_the_permanent_delegates_reach() {
    let mut coin = Stablecoin::v2();
    let mallory = Keypair::new();
    let (mallory_account, keys) = coin.onboard_confidential(&mallory);
    let (accomplice, accomplice_keys) = coin.onboard_confidential(&Keypair::new());
    let evidence = coin.onboard(&Keypair::new());
    coin.fund(&mallory_account, 1_000 * RUSD);

    // Mallory sees the sanction coming. One owner-signed instruction, no proofs needed.
    deposit(&mut coin.svm, &mallory_account, &mallory, 1_000 * RUSD).unwrap();
    let snapshot = coin.account(&mallory_account);
    assert_eq!(snapshot.amount, 0);
    assert_eq!(pending_balance(&snapshot, &keys).unwrap(), 1_000 * RUSD);

    // 1. The permanent delegate only reaches the public balance, and it is empty.
    assert_token_error(
        seize(
            &mut coin.svm,
            &mallory_account,
            &evidence,
            &coin.authorities.freeze,
            &coin.compliance.seizure,
            1_000 * RUSD,
        ),
        TokenError::InsufficientFunds,
    );
    let burn = burn_checked(
        &remit::TOKEN_2022_PROGRAM_ID,
        &mallory_account,
        &coin.mint,
        &coin.compliance.seizure.pubkey(),
        &[],
        1_000 * RUSD,
        6,
    )
    .unwrap();
    assert_token_error(
        coin.svm.send(&[burn], &[&coin.compliance.seizure]),
        TokenError::InsufficientFunds,
    );

    // 2. Confidential instructions are owner-only. The delegate cannot even apply the pending
    //    balance, let alone produce the withdraw proofs, which need Mallory's ElGamal secret.
    let apply_as_delegate = apply_instruction(
        &remit::TOKEN_2022_PROGRAM_ID,
        &mallory_account,
        1,
        &keys.ae.encrypt(1_000 * RUSD).into(),
        &coin.compliance.seizure.pubkey(),
        &[],
    )
    .unwrap();
    assert_token_error(
        coin.svm
            .send(&[apply_as_delegate], &[&coin.compliance.seizure]),
        TokenError::OwnerMismatch,
    );

    // 3. Freezing is the only lever left. It locks the funds; it does not seize them.
    revoke_kyc(&mut coin.svm, &mallory_account, &coin.authorities.freeze).unwrap();
    assert_token_error(
        apply_pending_balance(&mut coin.svm, &mallory_account, &mallory, &keys),
        TokenError::AccountFrozen,
    );

    // Had Mallory applied before the freeze, the frozen available balance could not move either.
    approve_kyc(&mut coin.svm, &mallory_account, &coin.authorities.freeze).unwrap();
    apply_pending_balance(&mut coin.svm, &mallory_account, &mallory, &keys).unwrap();
    revoke_kyc(&mut coin.svm, &mallory_account, &coin.authorities.freeze).unwrap();
    assert_token_error(
        transfer(
            &mut coin.svm,
            &mallory_account,
            &accomplice,
            &mallory,
            &keys,
            10 * RUSD,
        ),
        TokenError::AccountFrozen,
    );
    assert_token_error(
        withdraw(&mut coin.svm, &mallory_account, &mallory, &keys, 10 * RUSD),
        TokenError::AccountFrozen,
    );
    let accomplice_snapshot = coin.account(&accomplice);
    assert_eq!(
        pending_balance(&accomplice_snapshot, &accomplice_keys).unwrap(),
        0
    );
    assert_eq!(
        available_balance(&coin.account(&mallory_account), &keys).unwrap(),
        1_000 * RUSD
    );

    // 4. The tokens stay in supply for good, so the mint can never be decommissioned either.
    assert_eq!(coin.mint().supply, 1_000 * RUSD);
    let mint = coin.mint;
    let refund = Keypair::new().pubkey();
    assert_token_error(
        close_mint(&mut coin.svm, &mint, &coin.authorities.close, &refund),
        TokenError::MintHasSupply,
    );
}

#[test]
fn a_freeze_that_lands_first_wins_the_race() {
    let mut coin = Stablecoin::v2();
    let mallory = Keypair::new();
    let (mallory_account, _keys) = coin.onboard_confidential(&mallory);
    let evidence = coin.onboard(&Keypair::new());
    coin.fund(&mallory_account, 1_000 * RUSD);

    // The freeze authority acts first: Deposit is rejected on a frozen account.
    revoke_kyc(&mut coin.svm, &mallory_account, &coin.authorities.freeze).unwrap();
    assert_token_error(
        deposit(&mut coin.svm, &mallory_account, &mallory, 1_000 * RUSD),
        TokenError::AccountFrozen,
    );

    // Seizure is then one atomic transaction: thaw, transfer as permanent delegate, refreeze.
    let seized = seize(
        &mut coin.svm,
        &mallory_account,
        &evidence,
        &coin.authorities.freeze,
        &coin.compliance.seizure,
        1_000 * RUSD,
    )
    .unwrap();
    let snapshot = coin.account(&mallory_account);
    assert_eq!(snapshot.amount, 0);
    assert!(snapshot.is_frozen(), "never usable in between");
    assert_eq!(coin.account(&evidence).amount, 1_000 * RUSD - seized.fee);
}
