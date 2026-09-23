# Token-22-CTs

Turbin3 Week 4 assignment: a Token-2022 remittance stablecoin (rUSD) with transfer fees, KYC-gated accounts, on-chain metadata, confidential transfers and a seizure authority.

- `remit/` – Rust client library implementing the six tasks
- `programs/remit-agent/` – on-chain delegate agent (extension challenge)
- Tests run the Token-2022 v11 program in LiteSVM with the mainnet feature set

## Running

```sh
make test     # build SBF programs, run all 44 tests
make report   # transactions, bytes and compute units per flow
make lint     # rustfmt + clippy
```

Requirements: Rust 1.89+, Solana CLI with `cargo build-sbf` (tested with 3.1.10).

## Layout

| Path | Contents |
|---|---|
| `remit/src/mint.rs` | Tasks 1 and 5: mint creation and re-issue |
| `remit/src/transfer.rs` | Task 2: fee-aware transfers |
| `remit/src/state.rs` | Task 3: state decoding |
| `remit/src/kyc.rs` | Task 4: freeze and thaw |
| `remit/src/confidential.rs`, `proofs.rs` | Task 6: confidential lifecycle and proof delivery |
| `remit/src/compliance.rs` | Seizure via the permanent delegate |
| `remit/tests/` | One test file per task, the finding and the extension challenge |
| `programs/cpi-guard-probe/` | Test-only program for CPI Guard negative cases |
| `fixtures/spl_record.so` | Mainnet spl-record program, used for large proofs |

## Task 1: Mint

- Extensions: `TransferFeeConfig` (25 bps, 2.50 rUSD cap), `MetadataPointer` (points to the mint), `DefaultAccountState::Frozen`, `MintCloseAuthority`
- Each authority is a separate key
- Account allocated with `ExtensionType::try_calculate_account_len` (387 bytes) and funded for its final size including metadata (622 bytes)
- `CreateAccount`, all extension inits and `InitializeMint2` are sent in one transaction, since the inits are unsigned and could otherwise be front-run
- Token metadata is written in a second transaction, signed by the mint authority
- Metadata rent uses the 4-byte Token-2022 TLV header; `TokenMetadata::tlv_size_of()` assumes 12 bytes and overfunds

## Task 2: Transfers

- `transfer_with_fee` uses `transfer_checked_with_fee`
- Fee is computed per call with `calculate_epoch_fee(current_epoch, amount)`, epoch read from the Clock sysvar
- A fee change applies two epochs after `SetTransferFee`; tests confirm cached or early rates fail with `FeeMismatch`
- `collect_fees` harvests withheld fees and withdraws them to the treasury

## Task 3: State reads

- All mint and account reads go through `StateWithExtensions`, including in the agent program
- A test shows raw `Pack::unpack` failing on extended accounts; a lint test rejects raw unpack in the source

## Task 4: KYC

- New accounts start frozen, including ATAs created by third parties
- `approve_kyc` thaws a single account with the freeze authority and never changes the mint default
- Accounts without `ImmutableOwner` are refused, since their owner could transfer a KYC-approved account to someone else

## Task 5: Re-issue

- Confidential transfers cannot be added to an existing mint (`AlreadyInUse`), so v2 is a new mint
- v2 = v1 extensions + `PermanentDelegate` + `ConfidentialTransferMint` (manual approval, auditor key) + `ConfidentialTransferFeeConfig`
- Gap 1: a fee mint with confidential transfers requires `ConfidentialTransferFeeConfig`, otherwise `InvalidExtensionCombination`
- Gap 2: the permanent delegate cannot reach confidential balances (see Finding)

## Task 6: Confidential lifecycle

- `ConfigureAccount` is owner-only, while ATA creation is open to anyone
- Accounts must be approved by the issuer before they can send or receive
- Covered end to end: configure, approve, deposit, apply pending, transfer with fee, apply, withdraw
- Withdrawing pending funds is rejected by the client and by the chain (`ConfidentialTransferBalanceMismatch`)
- Proof delivery:
  - Small proofs: context account created and verified in one transaction
  - Range proof (1064 bytes): written to an spl-record account and verified inside the transfer transaction
  - Transfer: 7 transactions, withdraw: 2, all within the 1232-byte limit (enforced by the test harness)

## Finding: sanctioned user deposits into the confidential balance first

- The permanent delegate only controls the public balance; after `Deposit`, seizure and burn fail with `InsufficientFunds`
- Confidential instructions are owner-only and require proofs from the owner's ElGamal key
- The issuer can freeze the account, which locks the funds but does not recover them
- The funds remain in supply, so the mint cannot be closed without the owner's cooperation
- Confidential transfers hide amounts, not addresses: onward transfers can be traced (amounts via the auditor key) and frozen
- Account approval cannot be revoked; freezing is the only control
- If the freeze lands first, the deposit fails and `compliance::seize` performs thaw, transfer and refreeze atomically
- Recommendation: freeze before any public action
- Reproduced in `remit/tests/finding_sanctions_race.rs`

## Extension challenge

- `remit-agent` exposes one instruction, `ExecuteMandate`
- The user approves a PDA derived from `["mandate", source, destination, amount]`
- Anyone can trigger a payment; recipient and amount are fixed by the seeds, the total by the allowance
- Fee computed on-chain with `calculate_epoch_fee`, transfer via `TransferCheckedWithFee` signed by the PDA
- The same instruction succeeds before and after the user enables CPI Guard, since the delegate signs, not the owner
- `cpi-guard-probe` confirms CPI Guard blocks owner-signed transfers and approvals through CPI
- Program ID `AgntJP3i95tX9ruhfrkoA5Z12LVug6YMjhFJpBJ4AWAT`; deploying requires your own keypair
