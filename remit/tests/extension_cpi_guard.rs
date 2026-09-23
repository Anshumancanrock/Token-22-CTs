//! Extension challenge: an on-chain agent spends a user's `Approve`d allowance, and the same
//! delegated path keeps working after the user enables CPI Guard.
//!
//! Needs the SBF programs in `target/deploy` (`make build-sbf`).

mod common;

use {
    common::*,
    cpi_guard_probe::instruction::{forward_approve, forward_owner_transfer},
    remit::{
        token::{approve, enable_cpi_guard},
        transfer::transfer_with_fee,
        Cluster,
    },
    remit_agent::{instruction::execute_mandate, mandate_address, AgentError, AgentInstruction},
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::error::TokenError,
};

/// Size of each mandate payment.
const PAYMENT: u64 = 100 * RUSD;

struct Setup {
    coin: Stablecoin,
    alice: Keypair,
    alice_account: Address,
    merchant: Address,
}

fn setup() -> Setup {
    let mut coin = Stablecoin::deploy(Svm::new().with_sbf_programs(), false);
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

    // Alice approves 100 rUSD payments to the merchant, 250 rUSD in total (top level, her signature).
    let (mandate, _) = mandate_address(&alice_account, &merchant, PAYMENT);
    approve(&mut coin.svm, &alice_account, &mandate, &alice, 250 * RUSD).unwrap();

    // The keeper's instruction is built once and reused unchanged. No user signature involved.
    let pay = execute_mandate(&alice_account, &coin.mint, &merchant, PAYMENT);
    coin.svm.send(std::slice::from_ref(&pay), &[]).unwrap();
    assert_eq!(coin.account(&merchant).amount, PAYMENT - 250_000);
    assert_eq!(coin.account(&alice_account).delegated_amount, 150 * RUSD);

    enable_cpi_guard(&mut coin.svm, &alice_account, &alice).unwrap();
    assert_eq!(coin.account(&alice_account).cpi_guard, Some(true));

    // Same bytes, same accounts: still works, because the PDA signs as delegate, not as owner.
    let receipt = coin.svm.send(std::slice::from_ref(&pay), &[]).unwrap();
    assert!(receipt
        .logs
        .iter()
        .any(|line| line.contains("remit-agent: mandate transfer amount=100000000 fee=250000")));
    assert_eq!(coin.account(&merchant).amount, 2 * (PAYMENT - 250_000));
    assert_eq!(coin.account(&alice_account).delegated_amount, 50 * RUSD);

    // The allowance is the ceiling: 50 rUSD left, so a third payment of 100 does not fit.
    assert_token_error(
        coin.svm.send(std::slice::from_ref(&pay), &[]),
        TokenError::InsufficientFunds,
    );
}

#[test]
fn a_mandate_pays_only_its_recipient_and_only_its_amount() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        merchant,
    } = setup();
    let (mandate, _) = mandate_address(&alice_account, &merchant, PAYMENT);
    approve(&mut coin.svm, &alice_account, &mandate, &alice, 300 * RUSD).unwrap();
    let thief = coin.onboard(&Keypair::new());
    let pay = execute_mandate(&alice_account, &coin.mint, &merchant, PAYMENT);

    // Pointing the approved PDA at another recipient: the agent refuses before any CPI.
    let mut redirected = pay.clone();
    redirected.accounts[2].pubkey = thief;
    // Or at another amount, e.g. 1-unit payments whose rounded-up fee would eat the allowance.
    let mut dust = pay.clone();
    dust.data = AgentInstruction::ExecuteMandate { amount: 1 }.pack();
    for forged in [redirected, dust] {
        let error = coin.svm.send(&[forged], &[]).unwrap_err();
        assert_eq!(
            error.custom_code(),
            Some(AgentError::MandateMismatch as u32)
        );
    }

    // PDAs for another recipient or amount are valid for the agent, but Alice never approved them.
    for unapproved in [
        execute_mandate(&alice_account, &coin.mint, &thief, PAYMENT),
        execute_mandate(&alice_account, &coin.mint, &merchant, 1),
    ] {
        assert_token_error(coin.svm.send(&[unapproved], &[]), TokenError::OwnerMismatch);
    }
    assert_eq!(coin.account(&thief).amount, 0);
    assert_eq!(coin.account(&alice_account).delegated_amount, 300 * RUSD);
}

#[test]
fn the_agent_refuses_a_foreign_token_program_or_mint() {
    let Setup {
        mut coin,
        alice,
        alice_account,
        merchant,
    } = setup();
    let (mandate, _) = mandate_address(&alice_account, &merchant, PAYMENT);
    approve(&mut coin.svm, &alice_account, &mandate, &alice, 300 * RUSD).unwrap();
    let pay = execute_mandate(&alice_account, &coin.mint, &merchant, PAYMENT);

    let mut foreign_program = pay.clone();
    foreign_program.accounts[4].pubkey = solana_system_interface::program::ID;
    let error = coin.svm.send(&[foreign_program], &[]).unwrap_err();
    assert_eq!(
        error.custom_code(),
        Some(AgentError::WrongTokenProgram as u32)
    );

    let mut forged_mint = pay.clone();
    forged_mint.accounts[1].pubkey = Keypair::new().pubkey();
    let error = coin.svm.send(&[forged_mint], &[]).unwrap_err();
    assert_eq!(
        error.custom_code(),
        Some(AgentError::MintNotOwnedByToken2022 as u32)
    );
    assert_eq!(coin.account(&alice_account).amount, 1_000 * RUSD);
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
    let spend =
        forward_owner_transfer(&alice_account, &coin.mint, &merchant, &alice.pubkey(), RUSD);
    let grant = forward_approve(&alice_account, &coin.mint, &attacker, &alice.pubkey(), RUSD);

    // Without the guard, any program Alice signs for can spend or approve on her behalf.
    coin.svm
        .send(std::slice::from_ref(&spend), &[&alice])
        .unwrap();
    coin.svm
        .send(std::slice::from_ref(&grant), &[&alice])
        .unwrap();
    assert_eq!(coin.account(&alice_account).delegate, Some(attacker));

    enable_cpi_guard(&mut coin.svm, &alice_account, &alice).unwrap();

    assert_token_error(
        coin.svm.send(&[spend], &[&alice]),
        TokenError::CpiGuardTransferBlocked,
    );
    assert_token_error(
        coin.svm.send(&[grant], &[&alice]),
        TokenError::CpiGuardApproveBlocked,
    );
    // Alice's own top-level transfers are unaffected.
    transfer_with_fee(&mut coin.svm, &alice_account, &merchant, &alice, RUSD).unwrap();
}
