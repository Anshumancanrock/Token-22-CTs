//! # remit
//!
//! Client library for **rUSD**, a Token-2022 remittance stablecoin.
//!
//! | Assignment task | Module |
//! |---|---|
//! | 1. Mint with `TransferFeeConfig` + `MetadataPointer` (→ itself) + `DefaultAccountState(Frozen)` + `MintCloseAuthority` | [`mint`] |
//! | 2. Transfers through `transfer_checked_with_fee`, fee from `calculate_epoch_fee(current_epoch, amount)` | [`transfer`] |
//! | 3. State read only through `StateWithExtensions` | [`state`] |
//! | 4. KYC unfreeze path (`ThawAccount`, never the mint default) | [`kyc`] |
//! | 5. Re-issue with `PermanentDelegate` + confidential transfers (manual approval) | [`mint`] |
//! | 6. Confidential lifecycle: configure, approve, deposit, apply, transfer, withdraw | [`confidential`], [`proofs`] |
//!
//! Every flow talks to the chain through the [`Cluster`] trait, so the same code runs against
//! LiteSVM (the test-suite) or an RPC node.

pub mod cluster;
pub mod error;
pub mod mint;
pub mod state;
pub mod token;

pub use {
    cluster::{Cluster, Receipt, PACKET_DATA_SIZE},
    error::{Error, Result},
    spl_token_2022_interface::ID as TOKEN_2022_PROGRAM_ID,
};
