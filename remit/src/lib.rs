//! Client library for the rUSD Token-2022 stablecoin.

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
