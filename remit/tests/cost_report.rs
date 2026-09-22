//! What each flow costs on-chain: transactions, bytes, compute units.
//!
//! `cargo test --test cost_report -- --nocapture` prints the table quoted in the README.

mod common;

use {
    common::*,
    remit::{
        confidential::{apply_pending_balance, deposit, transfer, withdraw},
        transfer::transfer_with_fee,
        PACKET_DATA_SIZE,
    },
    solana_keypair::Keypair,
};

struct Row {
    step: &'static str,
    transactions: usize,
    largest: usize,
    compute_units: u64,
}

fn record(rows: &mut Vec<Row>, svm: &Svm, from: usize, step: &'static str) -> usize {
    let receipts = svm.since(from);
    rows.push(Row {
        step,
        transactions: receipts.len(),
        largest: receipts.iter().map(|r| r.size).max().unwrap_or(0),
        compute_units: receipts.iter().map(|r| r.compute_units).sum(),
    });
    svm.receipts.len()
}

#[test]
fn every_flow_fits_the_packet_limit() {
    let mut rows = Vec::new();

    let v1 = Stablecoin::v1();
    record(&mut rows, &v1.svm, 0, "create v1 mint (init + metadata)");

    let mut coin = Stablecoin::v2();
    record(&mut rows, &coin.svm, 0, "create v2 mint (init + metadata)");

    let (alice, bob) = (Keypair::new(), Keypair::new());
    let alice_account = coin.onboard(&alice);
    let bob_account = coin.onboard(&bob);
    coin.fund(&alice_account, 1_000 * RUSD);
    let mut mark = coin.svm.receipts.len();

    transfer_with_fee(
        &mut coin.svm,
        &alice_account,
        &bob_account,
        &alice,
        10 * RUSD,
    )
    .unwrap();
    mark = record(&mut rows, &coin.svm, mark, "public TransferCheckedWithFee");

    let alice_keys = remit::confidential::ConfidentialKeys::derive(&alice, &alice_account).unwrap();
    remit::confidential::configure_account(&mut coin.svm, &alice_account, &alice, &alice_keys)
        .unwrap();
    mark = record(
        &mut rows,
        &coin.svm,
        mark,
        "Reallocate + ConfigureAccount + proof",
    );
    remit::confidential::approve_account(
        &mut coin.svm,
        &alice_account,
        &coin.compliance.confidential,
    )
    .unwrap();
    record(&mut rows, &coin.svm, mark, "ApproveAccount");
    let bob_keys = remit::confidential::ConfidentialKeys::derive(&bob, &bob_account).unwrap();
    remit::confidential::configure_account(&mut coin.svm, &bob_account, &bob, &bob_keys).unwrap();
    remit::confidential::approve_account(
        &mut coin.svm,
        &bob_account,
        &coin.compliance.confidential,
    )
    .unwrap();
    mark = coin.svm.receipts.len();

    deposit(&mut coin.svm, &alice_account, &alice, 500 * RUSD).unwrap();
    mark = record(&mut rows, &coin.svm, mark, "Deposit");
    apply_pending_balance(&mut coin.svm, &alice_account, &alice, &alice_keys).unwrap();
    mark = record(&mut rows, &coin.svm, mark, "ApplyPendingBalance");
    transfer(
        &mut coin.svm,
        &alice_account,
        &bob_account,
        &alice,
        &alice_keys,
        100 * RUSD,
    )
    .unwrap();
    mark = record(
        &mut rows,
        &coin.svm,
        mark,
        "confidential TransferWithFee (5 proofs)",
    );
    withdraw(
        &mut coin.svm,
        &alice_account,
        &alice,
        &alice_keys,
        100 * RUSD,
    )
    .unwrap();
    record(&mut rows, &coin.svm, mark, "Withdraw (2 proofs)");

    println!("\n| step | txs | largest tx (bytes) | total CU |");
    println!("|---|---:|---:|---:|");
    for row in &rows {
        println!(
            "| {} | {} | {} | {} |",
            row.step, row.transactions, row.largest, row.compute_units
        );
    }
    let largest = coin.svm.receipts.iter().map(|r| r.size).max().unwrap();
    println!("\nlargest transaction overall: {largest} / {PACKET_DATA_SIZE} bytes");
    println!(
        "v1 mint: {} bytes allocated + {} metadata = {} bytes",
        v1.plan.space,
        v1.plan.metadata_len,
        v1.plan.space + v1.plan.metadata_len
    );
    println!(
        "v2 mint: {} bytes allocated + {} metadata = {} bytes",
        coin.plan.space,
        coin.plan.metadata_len,
        coin.plan.space + coin.plan.metadata_len
    );

    assert!(largest <= PACKET_DATA_SIZE);
}
