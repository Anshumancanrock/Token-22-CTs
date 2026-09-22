//! Extension challenge: an on-chain agent spends a user's `Approve`d allowance, and the same
//! delegated path keeps working after the user enables CPI Guard.
//!
//! Needs `target/deploy/remit_agent.so` (`cargo build-sbf --manifest-path programs/remit-agent/Cargo.toml`).

mod common;

use {
    common::*,
    remit::{
        token::{approve, enable_cpi_guard},
        transfer::transfer_with_fee,
        Cluster,
    },
    remit_agent::{
        instruction::{execute_mandate, forward_approve, forward_owner_transfer},
        mandate_address, AgentError,
    },
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::error::TokenError,
};

struct Setup {
    coin: Stablecoin,
    alice: Keypair,
    alice_account: Address,
    merchant: Address,
}

fn setup() -> Setup {
    let mut coin = Stablecoin::deploy(Svm::new().with_agent(), false);
    let alice = Keypair::new();
    let alice_account = coin.onboard(&alice);
    let merchant = coin.onboard(&Keypair::new());
    coin.fund(&alice_account, 1_000 * RUSD);
    Setup {
        coin,
        alice,
        alice_account,
        merchant,
    }
}

#[test]
fn delegated_agent_transfers_keep_working_after_cpi_guard() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        merchant,
    } = setup();

    // Alice approves the mandate PDA (top level, her signature).
    let (mandate, _) = mandate_address(&alice_account, &merchant);
    approve(&mut coin.svm, &alice_account, &mandate, &alice, 300 * RUSD).unwrap();

    // The keeper's instruction is built once and reused unchanged. No user signature involved.
    let pay = execute_mandate(&alice_account, &coin.mint, &merchant, 100 * RUSD);
    coin.svm.send(std::slice::from_ref(&pay), &[]).unwrap();
    assert_eq!(coin.account(&merchant).amount, 100 * RUSD - 250_000);
    assert_eq!(coin.account(&alice_account).delegated_amount, 200 * RUSD);

    enable_cpi_guard(&mut coin.svm, &alice_account, &alice).unwrap();
    assert_eq!(coin.account(&alice_account).cpi_guard, Some(true));

    // Same bytes, same accounts: still works, because the PDA signs as delegate, not as owner.
    let receipt = coin.svm.send(std::slice::from_ref(&pay), &[]).unwrap();
    assert!(receipt
        .logs
        .iter()
        .any(|line| line.contains("remit-agent: mandate transfer amount=100000000 fee=250000")));
    assert_eq!(coin.account(&merchant).amount, 2 * (100 * RUSD - 250_000));
    assert_eq!(coin.account(&alice_account).delegated_amount, 100 * RUSD);

    // The allowance is the ceiling.
    assert_token_error(
        coin.svm.send(
            &[execute_mandate(
                &alice_account,
                &coin.mint,
                &merchant,
                150 * RUSD,
            )],
            &[],
        ),
        TokenError::InsufficientFunds,
    );
}

#[test]
fn cpi_guard_blocks_what_a_malicious_program_would_do_with_the_owners_signature() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        merchant,
    } = setup();
    let attacker = Keypair::new().pubkey();

    // Without the guard, any program Alice signs for can spend or approve on her behalf.
    coin.svm
        .send(
            &[forward_owner_transfer(
                &alice_account,
                &coin.mint,
                &merchant,
                &alice.pubkey(),
                RUSD,
            )],
            &[&alice],
        )
        .unwrap();
    coin.svm
        .send(
            &[forward_approve(
                &alice_account,
                &coin.mint,
                &attacker,
                &alice.pubkey(),
                RUSD,
            )],
            &[&alice],
        )
        .unwrap();
    assert_eq!(coin.account(&alice_account).delegate, Some(attacker));

    enable_cpi_guard(&mut coin.svm, &alice_account, &alice).unwrap();

    assert_token_error(
        coin.svm.send(
            &[forward_owner_transfer(
                &alice_account,
                &coin.mint,
                &merchant,
                &alice.pubkey(),
                RUSD,
            )],
            &[&alice],
        ),
        TokenError::CpiGuardTransferBlocked,
    );
    assert_token_error(
        coin.svm.send(
            &[forward_approve(
                &alice_account,
                &coin.mint,
                &attacker,
                &alice.pubkey(),
                RUSD,
            )],
            &[&alice],
        ),
        TokenError::CpiGuardApproveBlocked,
    );
    // Alice's own top-level transfers are unaffected.
    transfer_with_fee(&mut coin.svm, &alice_account, &merchant, &alice, RUSD).unwrap();
}

#[test]
fn a_mandate_only_pays_the_destination_it_was_derived_for() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        merchant,
    } = setup();
    let (mandate, _) = mandate_address(&alice_account, &merchant);
    approve(&mut coin.svm, &alice_account, &mandate, &alice, 300 * RUSD).unwrap();
    let thief = coin.onboard(&Keypair::new());

    // Reusing Alice's mandate PDA for another destination: the agent refuses.
    let mut redirected = execute_mandate(&alice_account, &coin.mint, &merchant, 10 * RUSD);
    redirected.accounts[2].pubkey = thief;
    let error = coin.svm.send(&[redirected], &[]).unwrap_err();
    assert_eq!(
        error.custom_code(),
        Some(AgentError::MandateMismatch as u32)
    );

    // A PDA for the thief's destination: valid for the agent, but Alice never approved it.
    assert_token_error(
        coin.svm.send(
            &[execute_mandate(
                &alice_account,
                &coin.mint,
                &thief,
                10 * RUSD,
            )],
            &[],
        ),
        TokenError::OwnerMismatch,
    );
    assert_eq!(coin.account(&thief).amount, 0);
}
