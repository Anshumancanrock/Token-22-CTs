# Token-22-CTs

Turbin3 week 4. A Token-2022 remittance stablecoin (rUSD) with a transfer fee, accounts that start frozen until KYC, metadata stored in the mint and a close authority. A second version of the mint adds a permanent delegate and confidential transfers.

It's all Rust. `remit/` is the client library, `programs/remit-agent/` is the on-chain program for the extension challenge, and the tests run the real Token-2022 program (v11) inside LiteSVM with the mainnet feature set.

![tests passing](docs/tests-passing.png)

The screenshot is rendered from a captured `make test` run (`make screenshot` redoes it).

## Running it

```sh
make test     # builds both SBF programs, then cargo test --workspace (44 tests)
make report   # transactions, bytes and compute units per flow
make lint
```

You need Rust 1.89+ and the Solana CLI for `cargo build-sbf` (I used 3.1.10). No validator or network.

## Layout

```text
remit/src/mint.rs          tasks 1 and 5
remit/src/transfer.rs      task 2
remit/src/state.rs         task 3
remit/src/kyc.rs           task 4
remit/src/confidential.rs  task 6, with proofs.rs for getting the ZK proofs on-chain
remit/src/compliance.rs    seizure with the permanent delegate
remit/tests/               one file per task, plus the finding and the extension challenge
programs/remit-agent/      extension challenge
programs/cpi-guard-probe/  test-only program that does what CPI Guard should block
fixtures/spl_record.so     mainnet spl-record program (LiteSVM doesn't ship it)
```

## 1. Mint

`TransferFeeConfig` (25 bps, capped at 2.50 rUSD), `MetadataPointer` pointing at the mint itself, `DefaultAccountState::Frozen` and `MintCloseAuthority`. Every authority is a separate key.

`InitializeMint` only accepts the account if its size is exactly `ExtensionType::try_calculate_account_len` for the extensions initialized so far. So the account is allocated at that size (387 bytes) but funded for 622, because the metadata instruction grows it after `InitializeMint`. `CreateAccount`, the four extension inits and `InitializeMint2` share one transaction. The inits don't need a signature, and if they were split up someone else could initialize the funded account first. The metadata is a second transaction since it needs the mint authority.

The tests caught a sizing bug on the way: `TokenMetadata::tlv_size_of()` counts a 12-byte TLV header, while Token-2022 entries use 4 bytes, so funding with it pays rent for 8 bytes that never get allocated.

## 2. Transfers

`transfer::transfer_with_fee` reads the epoch from the Clock sysvar on every call and passes `calculate_epoch_fee(epoch, amount)` to `transfer_checked_with_fee`. A cached rate goes wrong when the fee changes, because `SetTransferFee` takes effect two epochs later and the old fee applies until then. The test raises the fee and steps through epochs 0 to 2. A cached or early rate gets `FeeMismatch`, and the epoch fee always goes through. `collect_fees` harvests the withheld fees and withdraws them to the treasury.

## 3. State reads

All reads go through `StateWithExtensions` in `state.rs`, and the agent program reads the mint the same way. `Pack::unpack` fails on any account with extensions because it expects exactly 82 or 165 bytes. One test shows that, and another scans the source so a raw unpack can't sneak back in.

## 4. KYC

New accounts start frozen, including ATAs that someone else creates for you. `kyc::approve_kyc` thaws one account with the freeze authority and never touches the mint's default state, so accounts opened later still start frozen. It refuses accounts without `ImmutableOwner` (every ATA has it). Without that check, a verified user could get an account thawed and then hand it to someone else with `SetAuthority`.

## 5. Re-issue

Confidential transfers can't be added to a live mint (the init fails with `AlreadyInUse`), so v2 is a new mint with the same four extensions plus `PermanentDelegate`, `ConfidentialTransferMint` with manual approval and an auditor key, and `ConfidentialTransferFeeConfig`.

The last one is the gap. Token-2022 rejects a fee mint with confidential transfers unless it also has `ConfidentialTransferFeeConfig` (`InvalidExtensionCombination`), since the fee on a hidden amount has to be encrypted as well. The other gap is between the permanent delegate and the confidential balances, covered in the finding below.

## 6. Confidential lifecycle

Anyone can create your ATA, but only you can configure it for confidential transfers: `ConfigureAccount` checks the owner's signature and a proof that the owner knows the ElGamal key. With manual approval, the issuer then has to approve the account before it can send or receive. The main test deposits, applies the pending balance, transfers, applies on the receiving side and withdraws, decrypting every balance along the way. Withdrawing before applying is refused by the client. The chain refuses it too: valid proofs built on the pending ciphertext still get `ConfidentialTransferBalanceMismatch`.

Since the mint charges a fee, the transfer is a `TransferWithFee` with five proofs, which don't fit in one transaction. The four small ones each get a context account, created and verified in the same transaction. The range proof is 1064 bytes, more than any transaction can carry, so it goes into an spl-record account and is verified inside the transfer transaction, which also closes every proof account. A transfer takes 7 transactions and a withdraw 2, all within the 1232-byte limit. LiteSVM doesn't enforce that limit, so the test harness does.

## Finding: a sanctioned user deposits into the confidential balance first

The permanent delegate can't touch the funds after that. The issuer can freeze them in place, but then nobody can move them, and they stay in the supply, so the mint can't be closed unless the owner cooperates. `finding_sanctions_race.rs` walks through it.

The permanent delegate can only move the public `amount`. A single `Deposit`, signed by the owner with no proof needed, moves the balance into the pending balance, encrypted under the owner's ElGamal key. After that, seizing or burning fails with `InsufficientFunds`. The confidential instructions are owner-only, and transfer and withdraw need proofs that only the owner's key can produce, so even a program that accepted the delegate there wouldn't help.

Freezing stops all confidential movement, but that only locks the money. Confidential transfers hide amounts, not addresses. If the funds were already sent on, the issuer can see where, read the amount with the auditor key and freeze that account too. `ApproveAccount` can't be undone, so freezing is the only brake.

If the freeze lands first, the deposit fails with `AccountFrozen`, and `compliance::seize` can thaw, move the funds as the permanent delegate and refreeze in one transaction. The sanctions process has to freeze before anything becomes public.

## Extension challenge

`remit-agent` has one instruction. The user approves a PDA derived from `["mandate", source, destination, amount]`, and after that anyone can call `ExecuteMandate` to pay exactly that amount to exactly that destination until the allowance runs out. The program reads the mint with `StateWithExtensions`, computes the fee with `calculate_epoch_fee` and signs the `TransferCheckedWithFee` CPI as the PDA. The amount is in the seeds so a caller can't send 1-unit payments whose rounded-up fee would eat the allowance.

The test sends the same instruction before and after the user enables CPI Guard, and both succeed. CPI Guard only blocks CPIs where the owner signs, and here the delegate PDA signs. `cpi-guard-probe` shows what it does block: an owner-signed transfer and an approve through CPI both work before the guard and fail after it (`CpiGuardTransferBlocked`, `CpiGuardApproveBlocked`).

The program ID `AgntJP3i95tX9ruhfrkoA5Z12LVug6YMjhFJpBJ4AWAT` is a vanity key that isn't in the repo, so use your own keypair to deploy.
