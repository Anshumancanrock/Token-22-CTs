//! # remit-agent
//!
//! A minimal on-chain "automation agent" for the remittance stablecoin.
//!
//! A user hands the agent an allowance with an ordinary, top-level `ApproveChecked` whose delegate
//! is the **mandate PDA** `["mandate", source, destination, amount]`. After that, anyone (a keeper,
//! a cron job) can call [`AgentInstruction::ExecuteMandate`] and the program moves exactly `amount`
//! from `source` to `destination` by signing the CPI as that PDA.
//!
//! * The seeds bind the recipient and the size of each payment, so the allowance can only ever pay
//!   the recipient the user chose, in the amount the user chose. The caller decides only when a
//!   payment happens. Nothing needs to be stored on-chain for these guarantees.
//! * The token program enforces the allowance ceiling (`delegated_amount`) and revocation, so the
//!   number of payments is at most `allowance / amount`.
//! * The transfer goes through `TransferCheckedWithFee`, with the fee computed from the mint's
//!   `TransferFeeConfig` for the *current* epoch (`calculate_epoch_fee`), read through
//!   `StateWithExtensions`.
//!
//! Because the PDA signs as the account's **delegate**, the path keeps working after the user turns
//! on CPI Guard: CPI Guard only blocks CPIs where the *owner* is the signing authority.

#![deny(missing_docs)]

use {
    solana_account_info::{next_account_info, AccountInfo},
    solana_address::Address,
    solana_program_error::{ProgramError, ProgramResult},
    spl_token_2022_interface::{
        extension::{
            transfer_fee::{instruction::transfer_checked_with_fee, TransferFeeConfig},
            BaseStateWithExtensions, StateWithExtensions,
        },
        state::Mint,
    },
};

solana_address::declare_id!("AgntJP3i95tX9ruhfrkoA5Z12LVug6YMjhFJpBJ4AWAT");

/// Seed prefix of the mandate PDA.
pub const MANDATE_SEED: &[u8] = b"mandate";

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

/// Errors specific to the agent, encoded as `ProgramError::Custom(code)`.
///
/// The codes start at 6000 so they never collide with the Token-2022 errors that reach the caller
/// through the CPI (`TokenError` uses 0..=64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AgentError {
    /// The token program account is not Token-2022.
    WrongTokenProgram = 6000,
    /// The delegate account is not the mandate PDA for `(source, destination, amount)`.
    MandateMismatch = 6001,
    /// The mint account is not owned by Token-2022.
    MintNotOwnedByToken2022 = 6002,
    /// Fee arithmetic overflowed.
    FeeOverflow = 6003,
}

impl From<AgentError> for ProgramError {
    fn from(error: AgentError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

/// Instructions understood by the agent. Wire format: a one-byte tag followed by a little-endian
/// `u64` amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentInstruction {
    /// Move `amount` from `source` to `destination`, signing as the mandate PDA (the delegate).
    ///
    /// Accounts:
    /// 0. `[writable]` source token account
    /// 1. `[]` mint
    /// 2. `[writable]` destination token account
    /// 3. `[]` mandate PDA `["mandate", source, destination, amount]`
    /// 4. `[]` Token-2022 program
    ExecuteMandate {
        /// Gross amount, in base units, that leaves the source account. Part of the PDA seeds.
        amount: u64,
    },
}

impl AgentInstruction {
    /// Serialize to instruction data.
    pub fn pack(&self) -> Vec<u8> {
        let Self::ExecuteMandate { amount } = *self;
        let mut data = Vec::with_capacity(9);
        data.push(0);
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    /// Deserialize from instruction data.
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        match data {
            [0, amount @ ..] => amount
                .try_into()
                .map(|amount| Self::ExecuteMandate {
                    amount: u64::from_le_bytes(amount),
                })
                .map_err(|_| ProgramError::InvalidInstructionData),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Derive the mandate PDA (the delegate a user approves) for paying `amount` from `source` to
/// `destination`.
pub fn mandate_address(source: &Address, destination: &Address, amount: u64) -> (Address, u8) {
    Address::find_program_address(
        &[
            MANDATE_SEED,
            source.as_ref(),
            destination.as_ref(),
            &amount.to_le_bytes(),
        ],
        &ID,
    )
}

/// Program entrypoint.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let AgentInstruction::ExecuteMandate { amount } = AgentInstruction::unpack(instruction_data)?;
    let accounts = &mut accounts.iter();
    let source = next_account_info(accounts)?;
    let mint = next_account_info(accounts)?;
    let destination = next_account_info(accounts)?;
    let mandate = next_account_info(accounts)?;
    let token_program = next_account_info(accounts)?;

    if *token_program.key != spl_token_2022_interface::ID {
        return Err(AgentError::WrongTokenProgram.into());
    }
    let amount_seed = amount.to_le_bytes();
    let (expected, bump) = Address::find_program_address(
        &[
            MANDATE_SEED,
            source.key.as_ref(),
            destination.key.as_ref(),
            &amount_seed,
        ],
        program_id,
    );
    if *mandate.key != expected {
        return Err(AgentError::MandateMismatch.into());
    }

    let (decimals, fee_config) = read_mint(mint)?;
    let fee = epoch_fee(fee_config.as_ref(), amount)?;
    solana_msg::msg!(
        "remit-agent: mandate transfer amount={} fee={}",
        amount,
        fee
    );
    let transfer = transfer_checked_with_fee(
        token_program.key,
        source.key,
        mint.key,
        destination.key,
        mandate.key,
        &[],
        amount,
        decimals,
        fee,
    )?;
    solana_cpi::invoke_signed(
        &transfer,
        &[
            source.clone(),
            mint.clone(),
            destination.clone(),
            mandate.clone(),
            token_program.clone(),
        ],
        &[&[
            MANDATE_SEED,
            source.key.as_ref(),
            destination.key.as_ref(),
            &amount_seed,
            &[bump],
        ]],
    )
}

/// Read decimals and the transfer-fee config from a Token-2022 mint via `StateWithExtensions`.
///
/// Token-2022 re-checks everything read here (the mint must be the source's mint, the decimals
/// and the fee must match), so a forged mint account can only make the CPI fail.
fn read_mint(mint: &AccountInfo) -> Result<(u8, Option<TransferFeeConfig>), ProgramError> {
    if *mint.owner != spl_token_2022_interface::ID {
        return Err(AgentError::MintNotOwnedByToken2022.into());
    }
    let data = mint.try_borrow_data()?;
    let state = StateWithExtensions::<Mint>::unpack(&data)?;
    let fee_config = state.get_extension::<TransferFeeConfig>().ok().copied();
    Ok((state.base.decimals, fee_config))
}

/// Fee for `amount` at the current epoch. Token-2022 recomputes the same value and rejects the
/// transfer with `FeeMismatch` if they differ, so this must use the live epoch.
fn epoch_fee(fee_config: Option<&TransferFeeConfig>, amount: u64) -> Result<u64, ProgramError> {
    use solana_sysvar::Sysvar;
    match fee_config {
        None => Ok(0),
        Some(config) => {
            let epoch = solana_clock::Clock::get()?.epoch;
            config
                .calculate_epoch_fee(epoch, amount)
                .ok_or_else(|| AgentError::FeeOverflow.into())
        }
    }
}

/// Instruction builder for clients.
pub mod instruction {
    use {
        super::*,
        solana_instruction::{AccountMeta, Instruction},
    };

    /// Build [`AgentInstruction::ExecuteMandate`]. No signer is needed: the PDA signs on-chain.
    pub fn execute_mandate(
        source: &Address,
        mint: &Address,
        destination: &Address,
        amount: u64,
    ) -> Instruction {
        let (mandate, _) = mandate_address(source, destination, amount);
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(mandate, false),
                AccountMeta::new_readonly(spl_token_2022_interface::ID, false),
            ],
            data: AgentInstruction::ExecuteMandate { amount }.pack(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_data_round_trips() {
        for amount in [0, 1, u64::MAX] {
            let ix = AgentInstruction::ExecuteMandate { amount };
            assert_eq!(AgentInstruction::unpack(&ix.pack()).unwrap(), ix);
        }
        assert!(AgentInstruction::unpack(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(AgentInstruction::unpack(&[0, 1]).is_err());
        assert!(AgentInstruction::unpack(&[]).is_err());
    }

    #[test]
    fn mandate_is_bound_to_destination_and_amount() {
        let (source, destination) = (Address::from([1; 32]), Address::from([2; 32]));
        let (base, _) = mandate_address(&source, &destination, 100);
        assert_ne!(
            base,
            mandate_address(&source, &Address::from([3; 32]), 100).0
        );
        assert_ne!(base, mandate_address(&source, &destination, 1).0);
    }
}
