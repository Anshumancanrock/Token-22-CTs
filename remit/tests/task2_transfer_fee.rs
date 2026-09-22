//! Task 2: every transfer is a `TransferCheckedWithFee` whose fee comes from
//! `calculate_epoch_fee(current_epoch, amount)`, not from a cached rate.

mod common;

use {
    common::*,
    remit::{
        transfer::{collect_fees, expected_fee, set_transfer_fee, transfer_with_fee},
        Cluster,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{
        error::TokenError, extension::transfer_fee::instruction::transfer_checked_with_fee,
        instruction::transfer_checked,
    },
};

struct Setup {
    coin: Stablecoin,
    alice: Keypair,
    alice_account: solana_address::Address,
    bob_account: solana_address::Address,
}

fn setup() -> Setup {
    let mut coin = Stablecoin::v1();
    let alice = Keypair::new();
    let alice_account = coin.onboard(&alice);
    let bob_account = coin.onboard(&Keypair::new());
    coin.fund(&alice_account, 10_000 * RUSD);
    Setup {
        coin,
        alice,
        alice_account,
        bob_account,
    }
}

#[test]
fn fee_is_withheld_in_the_recipient_account() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        bob_account,
    } = setup();

    let sent = transfer_with_fee(
        &mut coin.svm,
        &alice_account,
        &bob_account,
        &alice,
        100 * RUSD,
    )
    .unwrap();

    // 0.25 % of 100 rUSD, rounded up: 0.25 rUSD.
    assert_eq!(sent.fee, 250_000);
    let config = coin.mint().transfer_fee.unwrap();
    assert_eq!(
        sent.fee,
        config.calculate_epoch_fee(sent.epoch, 100 * RUSD).unwrap()
    );

    let bob = coin.account(&bob_account);
    assert_eq!(bob.amount, 100 * RUSD - 250_000);
    assert_eq!(bob.withheld_fee, Some(250_000));
    assert_eq!(coin.account(&alice_account).amount, 9_900 * RUSD);
}

#[test]
fn fee_is_capped_at_the_maximum() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        bob_account,
    } = setup();

    // 0.25 % of 5,000 rUSD would be 12.5 rUSD; the cap is 2.5 rUSD.
    let sent = transfer_with_fee(
        &mut coin.svm,
        &alice_account,
        &bob_account,
        &alice,
        5_000 * RUSD,
    )
    .unwrap();
    assert_eq!(sent.fee, 2_500_000);
    assert_eq!(coin.account(&bob_account).amount, 5_000 * RUSD - 2_500_000);
}

#[test]
fn a_cached_or_premature_rate_is_rejected_and_the_epoch_fee_is_not() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        bob_account,
    } = setup();
    let mint = coin.mint;
    let amount = 100 * RUSD;
    let pay_with_fee = |fee: u64| {
        transfer_checked_with_fee(
            &remit::TOKEN_2022_PROGRAM_ID,
            &alice_account,
            &mint,
            &bob_account,
            &alice.pubkey(),
            &[],
            amount,
            6,
            fee,
        )
        .unwrap()
    };

    // A client that cached the rate when it started: 25 bps.
    let cached_fee = expected_fee(&coin.mint(), coin.svm.epoch(), amount).unwrap();
    assert_eq!(cached_fee, 250_000);

    // Epoch 0: the issuer raises the fee to 100 bps. Token-2022 schedules it for epoch 2.
    set_transfer_fee(
        &mut coin.svm,
        &mint,
        &coin.authorities.fee_config,
        100,
        2_500_000,
    )
    .unwrap();
    let config = coin.mint().transfer_fee.unwrap();
    assert_eq!(u64::from(config.newer_transfer_fee.epoch), 2);
    let premature_fee = config.newer_transfer_fee.calculate_fee(amount).unwrap();
    assert_eq!(premature_fee, 1_000_000);

    for epoch in [0, 1] {
        coin.svm.warp_to_epoch(epoch);
        // Reading `newer_transfer_fee` directly charges the new rate too early.
        assert_token_error(
            coin.svm.send(&[pay_with_fee(premature_fee)], &[&alice]),
            TokenError::FeeMismatch,
        );
        // calculate_epoch_fee still selects the old schedule.
        let sent =
            transfer_with_fee(&mut coin.svm, &alice_account, &bob_account, &alice, amount).unwrap();
        assert_eq!((sent.epoch, sent.fee), (epoch, 250_000));
    }

    coin.svm.warp_to_epoch(2);
    // The cached rate is now stale.
    assert_token_error(
        coin.svm.send(&[pay_with_fee(cached_fee)], &[&alice]),
        TokenError::FeeMismatch,
    );
    // calculate_epoch_fee switches to the new schedule on its own.
    let sent =
        transfer_with_fee(&mut coin.svm, &alice_account, &bob_account, &alice, amount).unwrap();
    assert_eq!((sent.epoch, sent.fee), (2, 1_000_000));
}

#[test]
fn plain_transfer_checked_also_withholds_but_does_not_pin_the_fee() {
    // For contrast: TransferChecked lands and silently takes whatever the current fee is. Only
    // TransferCheckedWithFee lets the sender state the fee it agreed to pay.
    let Setup {
        mut coin,
        alice,
        alice_account,
        bob_account,
    } = setup();
    let instruction = transfer_checked(
        &remit::TOKEN_2022_PROGRAM_ID,
        &alice_account,
        &coin.mint,
        &bob_account,
        &alice.pubkey(),
        &[],
        100 * RUSD,
        6,
    )
    .unwrap();
    coin.svm.send(&[instruction], &[&alice]).unwrap();
    assert_eq!(coin.account(&bob_account).withheld_fee, Some(250_000));
}

#[test]
fn issuer_collects_the_withheld_fees_as_revenue() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        bob_account,
    } = setup();
    let carol_account = coin.onboard(&Keypair::new());
    let treasury = coin.onboard(&Keypair::new());

    let mut total = 0;
    for (to, amount) in [
        (bob_account, 100 * RUSD),
        (carol_account, 3_000 * RUSD),
        (bob_account, 7 * RUSD),
    ] {
        total += transfer_with_fee(&mut coin.svm, &alice_account, &to, &alice, amount)
            .unwrap()
            .fee;
    }
    assert_eq!(total, 250_000 + 2_500_000 + 17_500);

    // Only the withdraw-withheld authority can take the revenue out.
    let mint = coin.mint;
    let impostor = Keypair::new();
    assert_token_error(
        collect_fees(&mut coin.svm, &mint, &[bob_account], &treasury, &impostor),
        TokenError::OwnerMismatch,
    );

    let collected = collect_fees(
        &mut coin.svm,
        &mint,
        &[bob_account, carol_account],
        &treasury,
        &coin.authorities.fee_withdraw,
    )
    .unwrap();
    assert_eq!(collected, total);
    assert_eq!(coin.account(&bob_account).withheld_fee, Some(0));
    assert_eq!(coin.account(&carol_account).withheld_fee, Some(0));
    assert_eq!(coin.account(&treasury).amount, total);
    // Nothing was created or destroyed: supply is unchanged.
    assert_eq!(coin.mint().supply, 10_000 * RUSD);
}
