//! The I/O boundary. Flows only read accounts, read the clock, and send transactions, so they are
//! written against this small trait instead of a concrete client.

use {
    crate::Result, solana_address::Address,
    solana_compute_budget_interface::ComputeBudgetInstruction, solana_instruction::Instruction,
    solana_keypair::Keypair, solana_message::Message,
};

/// Largest serialized transaction the network accepts (1280-byte IPv6 MTU minus headers).
pub const PACKET_DATA_SIZE: usize = 1232;

/// What a landed transaction cost.
#[derive(Clone, Debug, Default)]
pub struct Receipt {
    /// Compute units consumed.
    pub compute_units: u64,
    /// Serialized size in bytes.
    pub size: usize,
    /// Program logs.
    pub logs: Vec<String>,
}

/// A Solana cluster, as seen by this crate.
pub trait Cluster {
    /// Fee payer for every transaction sent through [`Cluster::send`]. Flows also use it as the
    /// rent payer and as the authority of short-lived proof accounts.
    fn payer(&self) -> Address;

    /// Raw account data, or `None` when the account does not exist.
    fn account_data(&self, address: &Address) -> Option<Vec<u8>>;

    /// Lamport balance (`0` when the account does not exist).
    fn lamports(&self, address: &Address) -> u64;

    /// Current epoch, read from the Clock sysvar on every call. Never cache it: transfer fees are
    /// epoch-dependent.
    fn epoch(&self) -> u64;

    /// Minimum balance for a rent-exempt account holding `data_len` bytes.
    fn minimum_balance_for_rent_exemption(&self, data_len: usize) -> u64;

    /// Sign with the fee payer plus `signers`, submit, and wait for the outcome.
    ///
    /// `signers` are the signatures the instructions require besides the fee payer's. Flows pass
    /// exactly those; an implementation may skip a signer that equals the fee payer.
    ///
    /// Implementations must refuse transactions above [`PACKET_DATA_SIZE`], so that every flow that
    /// passes the tests also fits on a real cluster.
    fn send(&mut self, instructions: &[Instruction], signers: &[&Keypair]) -> Result<Receipt>;
}

/// Serialized size of a legacy transaction carrying `instructions`, paid by `payer`.
pub fn transaction_size(instructions: &[Instruction], payer: &Address) -> usize {
    let message = Message::new(instructions, Some(payer));
    let signatures = usize::from(message.header.num_required_signatures);
    // compact-u16 signature count (one byte below 128) + 64-byte signatures + message
    1 + signatures * 64 + message.serialize().len()
}

/// Whether `instructions` fit in a single transaction.
pub fn fits_in_one_transaction(instructions: &[Instruction], payer: &Address) -> bool {
    transaction_size(instructions, payer) <= PACKET_DATA_SIZE
}

/// Prepend a `SetComputeUnitLimit` instruction.
pub fn with_compute_unit_limit(units: u32, instructions: Vec<Instruction>) -> Vec<Instruction> {
    let mut all = Vec::with_capacity(instructions.len() + 1);
    all.push(ComputeBudgetInstruction::set_compute_unit_limit(units));
    all.extend(instructions);
    all
}
