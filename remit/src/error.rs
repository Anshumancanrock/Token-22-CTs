//! Error type shared by every flow.

use {
    num_traits::FromPrimitive,
    solana_address::Address,
    solana_instruction::error::InstructionError,
    solana_program_error::ProgramError,
    solana_transaction_error::TransactionError,
    spl_token_2022_interface::error::TokenError,
};

/// Result alias used across the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong in a flow.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The cluster executed the transaction and it failed.
    #[error("transaction failed: {err}")]
    Transaction {
        /// Runtime error, including the index of the failing instruction.
        err: TransactionError,
        /// Program logs.
        logs: Vec<String>,
    },
    /// The transaction would not fit in a network packet.
    #[error("transaction is {size} bytes; the packet limit is {limit}")]
    TransactionTooLarge {
        /// Serialized size.
        size: usize,
        /// Limit it exceeded.
        limit: usize,
    },
    /// An account the flow needs does not exist.
    #[error("account {0} not found")]
    AccountNotFound(Address),
    /// Decoding or instruction-building error from a program interface crate.
    #[error("program error: {0}")]
    Program(#[from] ProgramError),
    /// Zero-knowledge proof generation or ciphertext decryption failed.
    #[error("confidential transfer crypto: {0}")]
    Crypto(String),
    /// The owner's decrypted confidential balance cannot cover the request.
    #[error("confidential available balance is {available}, cannot move {requested}")]
    InsufficientConfidentialBalance {
        /// Decrypted available balance.
        available: u64,
        /// Amount requested.
        requested: u64,
    },
    /// Precondition violated before anything was sent.
    #[error("{0}")]
    Invalid(String),
}

impl Error {
    /// `(instruction index, error)` when a transaction failed inside an instruction.
    pub fn instruction_error(&self) -> Option<(u8, &InstructionError)> {
        match self {
            Error::Transaction {
                err: TransactionError::InstructionError(index, err),
                ..
            } => Some((*index, err)),
            _ => None,
        }
    }

    /// Custom program error code, if the failing instruction returned one.
    pub fn custom_code(&self) -> Option<u32> {
        match self.instruction_error()? {
            (_, InstructionError::Custom(code)) => Some(*code),
            _ => None,
        }
    }

    /// The Token-2022 error, when the failing instruction was a Token-2022 instruction.
    pub fn token_error(&self) -> Option<TokenError> {
        self.custom_code().and_then(TokenError::from_u32)
    }

    /// Program logs of a failed transaction (empty otherwise).
    pub fn logs(&self) -> &[String] {
        match self {
            Error::Transaction { logs, .. } => logs,
            _ => &[],
        }
    }
}
