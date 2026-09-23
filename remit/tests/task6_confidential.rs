//! Task 6: ConfigureAccount (owner only) -> ApproveAccount (manual) -> Deposit ->
//! ApplyPendingBalance -> confidential TransferWithFee -> ApplyPendingBalance -> Withdraw.

mod common;

use {
    common::*,
    remit::{
        confidential::{
            apply_pending_balance, approve_account, available_balance, configure_account,
            configure_instructions, deposit, pending_balance, reallocate_instruction, transfer,
            withdraw, withdraw_against, withheld_confidential_fee, ConfidentialKeys,
        },
        Cluster, Error, PACKET_DATA_SIZE,
    },
    solana_instruction::error::InstructionError,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_zk_sdk::encryption::elgamal::ElGamalCiphertext,
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    spl_token_2022_interface::{
        error::TokenError,
        extension::confidential_transfer::instruction::apply_pending_balance as apply_pending_balance_instruction,
    },
    spl_token_confidential_transfer_proof_generation::try_combine_lo_hi_ciphertexts,
};

#[test]
fn configuring_is_owner_only_although_anyone_can_create_the_account() {
    let mut coin = Stablecoin::v2();
    let alice = Keypair::new();
    // The harness payer created Alice's ATA; the freeze authority cleared her KYC.
    let account = coin.onboard(&alice);

    // Someone else (here the issuer) tries to attach their own encryption keys to it.
    let issuer = &coin.compliance.confidential;
    let issuer_keys = ConfidentialKeys::derive(issuer, &account).unwrap();
    let payer = coin.svm.payer();
    let realloc = reallocate_instruction(&account, &payer, &issuer.pubkey()).unwrap();
    assert_token_error(
        coin.svm.send(&[realloc], &[issuer]),
        TokenError::OwnerMismatch,
    );
    let configure =
        configure_instructions(&account, &coin.mint, &issuer.pubkey(), &issuer_keys).unwrap();
    assert_token_error(
        coin.svm.send(&configure, &[issuer]),
        TokenError::OwnerMismatch,
    );

    let keys = ConfidentialKeys::derive(&alice, &account).unwrap();
    configure_account(&mut coin.svm, &account, &alice, &keys).unwrap();
    let snapshot = coin.account(&account);
    let state = snapshot.confidential.unwrap();
    assert_eq!(
        state.elgamal_pubkey,
        PodElGamalPubkey::from(keys.elgamal.pubkey_owned())
    );
    assert!(!bool::from(state.approved), "manual policy: not usable yet");
    // The mint charges fees, so the account also got an encrypted withheld-fee slot.
    assert!(snapshot.confidential_withheld.is_some());

    // The keys are a pure function of Alice's wallet signature: recoverable, not stored anywhere.
    let again = ConfidentialKeys::derive(&alice, &account).unwrap();
    assert_eq!(again.elgamal.pubkey(), keys.elgamal.pubkey());
}

#[test]
fn manual_approval_gates_confidential_use() {
    let mut coin = Stablecoin::v2();
    let alice = Keypair::new();
    let account = coin.onboard(&alice);
    let keys = ConfidentialKeys::derive(&alice, &account).unwrap();
    configure_account(&mut coin.svm, &account, &alice, &keys).unwrap();
    coin.fund(&account, 100 * RUSD);

    assert_token_error(
        deposit(&mut coin.svm, &account, &alice, 10 * RUSD),
        TokenError::ConfidentialTransferAccountNotApproved,
    );
    // Only the ConfidentialTransferMint authority can approve.
    assert_instruction_error(
        approve_account(&mut coin.svm, &account, &alice),
        0,
        InstructionError::MissingRequiredSignature,
    );
    approve_account(&mut coin.svm, &account, &coin.compliance.confidential).unwrap();
    deposit(&mut coin.svm, &account, &alice, 10 * RUSD).unwrap();
    apply_pending_balance(&mut coin.svm, &account, &alice, &keys).unwrap();

    // Approval also gates receiving: a configured but unapproved account cannot be paid.
    let bob = Keypair::new();
    let bob_account = coin.onboard(&bob);
    let bob_keys = ConfidentialKeys::derive(&bob, &bob_account).unwrap();
    configure_account(&mut coin.svm, &bob_account, &bob, &bob_keys).unwrap();
    assert_token_error(
        transfer(&mut coin.svm, &account, &bob_account, &alice, &keys, RUSD),
        TokenError::ConfidentialTransferAccountNotApproved,
    );
    assert_eq!(
        available_balance(&coin.account(&account), &keys).unwrap(),
        10 * RUSD
    );
}

#[test]
fn full_confidential_lifecycle() {
    let mut coin = Stablecoin::v2();
    let (alice, bob) = (Keypair::new(), Keypair::new());
    let (alice_account, alice_keys) = coin.onboard_confidential(&alice);
    let (bob_account, bob_keys) = coin.onboard_confidential(&bob);
    coin.fund(&alice_account, 1_000 * RUSD);

    // Deposit: public -> pending (two credits).
    deposit(&mut coin.svm, &alice_account, &alice, 250 * RUSD).unwrap();
    deposit(&mut coin.svm, &alice_account, &alice, 350 * RUSD).unwrap();
    let snapshot = coin.account(&alice_account);
    assert_eq!(snapshot.amount, 400 * RUSD);
    assert_eq!(pending_balance(&snapshot, &alice_keys).unwrap(), 600 * RUSD);
    assert_eq!(available_balance(&snapshot, &alice_keys).unwrap(), 0);

    // Apply: pending -> available.
    let available =
        apply_pending_balance(&mut coin.svm, &alice_account, &alice, &alice_keys).unwrap();
    assert_eq!(available, 600 * RUSD);
    let snapshot = coin.account(&alice_account);
    assert_eq!(pending_balance(&snapshot, &alice_keys).unwrap(), 0);
    assert_eq!(
        available_balance(&snapshot, &alice_keys).unwrap(),
        600 * RUSD
    );

    // Confidential transfer with fee.
    let before = coin.svm.receipts.len();
    let sent = transfer(
        &mut coin.svm,
        &alice_account,
        &bob_account,
        &alice,
        &alice_keys,
        100 * RUSD,
    )
    .unwrap();
    let transactions = coin.svm.since(before);
    assert_eq!(
        transactions.len(),
        7,
        "4 proof transactions, 2 record writes, then range proof + transfer + cleanup together"
    );
    assert!(transactions
        .iter()
        .all(|receipt| receipt.size <= PACKET_DATA_SIZE));

    // The fee is the epoch fee, exactly as for a public transfer.
    let config = coin.mint().transfer_fee.unwrap();
    assert_eq!(
        sent.fee,
        config
            .calculate_epoch_fee(coin.svm.epoch(), 100 * RUSD)
            .unwrap()
    );
    let net = 100 * RUSD - sent.fee;

    // Nothing moved in public; the amounts are only visible to the parties.
    assert_eq!(coin.account(&alice_account).amount, 400 * RUSD);
    assert_eq!(coin.account(&bob_account).amount, 0);
    let alice_snapshot = coin.account(&alice_account);
    assert_eq!(
        available_balance(&alice_snapshot, &alice_keys).unwrap(),
        500 * RUSD
    );
    let bob_snapshot = coin.account(&bob_account);
    assert_eq!(pending_balance(&bob_snapshot, &bob_keys).unwrap(), net);
    assert_eq!(available_balance(&bob_snapshot, &bob_keys).unwrap(), 0);
    // The auditor decrypts the amount; the fee authority decrypts the withheld fee.
    assert_eq!(sent.audit(&coin.compliance.auditor).unwrap(), 100 * RUSD);
    assert_eq!(
        withheld_confidential_fee(&bob_snapshot, &coin.compliance.fee_withdraw_elgamal).unwrap(),
        sent.fee
    );
    // Every proof account was closed and its rent refunded.
    assert!(coin
        .svm
        .svm
        .get_program_accounts(&solana_zk_elgamal_proof_interface::id())
        .is_empty());
    assert!(coin
        .svm
        .svm
        .get_program_accounts(&spl_record::id())
        .is_empty());

    // Bob must apply before he can withdraw: pending funds are not spendable.
    match withdraw(&mut coin.svm, &bob_account, &bob, &bob_keys, net) {
        Err(Error::InsufficientConfidentialBalance {
            available: 0,
            requested,
        }) => assert_eq!(requested, net),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(
        apply_pending_balance(&mut coin.svm, &bob_account, &bob, &bob_keys).unwrap(),
        net
    );
    withdraw(&mut coin.svm, &bob_account, &bob, &bob_keys, net).unwrap();
    let bob_snapshot = coin.account(&bob_account);
    assert_eq!(bob_snapshot.amount, net);
    assert_eq!(available_balance(&bob_snapshot, &bob_keys).unwrap(), 0);

    // Alice takes part of hers back to public: one record write, then everything else together.
    let before = coin.svm.receipts.len();
    withdraw(
        &mut coin.svm,
        &alice_account,
        &alice,
        &alice_keys,
        200 * RUSD,
    )
    .unwrap();
    assert_eq!(coin.svm.since(before).len(), 2);
    let alice_snapshot = coin.account(&alice_account);
    assert_eq!(alice_snapshot.amount, 600 * RUSD);
    assert_eq!(
        available_balance(&alice_snapshot, &alice_keys).unwrap(),
        300 * RUSD
    );

    // Conservation: public + confidential + withheld = supply.
    let accounted = alice_snapshot.amount
        + available_balance(&alice_snapshot, &alice_keys).unwrap()
        + bob_snapshot.amount
        + withheld_confidential_fee(&bob_snapshot, &coin.compliance.fee_withdraw_elgamal).unwrap();
    assert_eq!(accounted, coin.mint().supply);
}

#[test]
fn the_chain_rejects_a_withdraw_that_spends_pending_funds() {
    let mut coin = Stablecoin::v2();
    let bob = Keypair::new();
    let (bob_account, bob_keys) = coin.onboard_confidential(&bob);
    coin.fund(&bob_account, 50 * RUSD);
    deposit(&mut coin.svm, &bob_account, &bob, 50 * RUSD).unwrap();

    // Skip the client-side check and build valid proofs over the *pending* ciphertext, which really
    // does hold 50 rUSD. Both proofs verify; Token-2022 then recomputes `available - amount`,
    // finds it differs from the proven ciphertext, and rejects the withdraw.
    let state = coin.account(&bob_account).confidential.unwrap();
    let pending = try_combine_lo_hi_ciphertexts(
        &ElGamalCiphertext::try_from(state.pending_balance_lo).unwrap(),
        &ElGamalCiphertext::try_from(state.pending_balance_hi).unwrap(),
        16,
    )
    .unwrap();
    assert_token_error(
        withdraw_against(
            &mut coin.svm,
            &bob_account,
            &bob,
            &bob_keys,
            &pending,
            50 * RUSD,
            50 * RUSD,
        ),
        TokenError::ConfidentialTransferBalanceMismatch,
    );
    // The failed attempt still closed its proof accounts.
    assert!(coin
        .svm
        .svm
        .get_program_accounts(&solana_zk_elgamal_proof_interface::id())
        .is_empty());
    assert!(coin
        .svm
        .svm
        .get_program_accounts(&spl_record::id())
        .is_empty());

    apply_pending_balance(&mut coin.svm, &bob_account, &bob, &bob_keys).unwrap();
    withdraw(&mut coin.svm, &bob_account, &bob, &bob_keys, 50 * RUSD).unwrap();
    assert_eq!(coin.account(&bob_account).amount, 50 * RUSD);
}

#[test]
fn a_stale_decryptable_balance_is_reported_before_any_proof_is_built() {
    let mut coin = Stablecoin::v2();
    let bob = Keypair::new();
    let (bob_account, bob_keys) = coin.onboard_confidential(&bob);
    coin.fund(&bob_account, 50 * RUSD);
    deposit(&mut coin.svm, &bob_account, &bob, 30 * RUSD).unwrap();
    deposit(&mut coin.svm, &bob_account, &bob, 20 * RUSD).unwrap();

    // Bob's wallet only saw the first deposit when it applied: it claims one credit and a
    // decryptable balance of 30. The program accepts this and records the counter mismatch.
    let apply = apply_pending_balance_instruction(
        &remit::TOKEN_2022_PROGRAM_ID,
        &bob_account,
        1,
        &bob_keys.ae.encrypt(30 * RUSD).into(),
        &bob.pubkey(),
        &[],
    )
    .unwrap();
    coin.svm.send(&[apply], &[&bob]).unwrap();

    let error = available_balance(&coin.account(&bob_account), &bob_keys).unwrap_err();
    assert!(error.to_string().contains("stale"), "{error}");
    assert!(withdraw(&mut coin.svm, &bob_account, &bob, &bob_keys, RUSD).is_err());
}
