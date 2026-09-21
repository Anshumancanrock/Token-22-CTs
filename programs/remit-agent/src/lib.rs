//! # remit-agent
//!
//! A minimal on-chain "automation agent" for the remittance stablecoin.
//!
//! A user hands the agent an allowance with an ordinary, top-level `ApproveChecked` whose delegate
//! is the **mandate PDA** `["mandate", source, destination]`. After that, anyone (a keeper, a cron
//! job) can call [`AgentInstruction::ExecuteMandate`] and the program moves tokens from `source` to
//! `destination` by signing the CPI as that PDA.
//!
//! * The PDA seeds bind the destination, so the allowance can only ever pay the recipient the user
//!   chose. Nothing needs to be stored on-chain for that guarantee.
//! * The token program enforces the allowance ceiling (`delegated_amount`) and revocation.
//! * The transfer goes through `TransferCheckedWithFee`, with the fee computed from the mint's
//!   `TransferFeeConfig` for the *current* epoch (`calculate_epoch_fee`), read through
//!   `StateWithExtensions`.
//!
//! Because the PDA signs as the account's **delegate**, the path keeps working after the user turns
//! on CPI Guard: CPI Guard only blocks CPIs where the *owner* is the signing authority.
//!
//! Instructions 1 and 2 are negative controls for the CPI Guard tests. They are the two patterns a
//! malicious or careless program would use once it holds the user's signature: forwarding the owner
//! signature into a transfer, and approving a delegate through CPI. CPI Guard blocks both.

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
        instruction::approve_checked,
        state::Mint,
    },
};

solana_address::declare_id!("AgntJP3i95tX9ruhfrkoA5Z12LVug6YMjhFJpBJ4AWAT");

/// Seed prefix of the mandate PDA.
pub const MANDATE_SEED: &[u8] = b"mandate";

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

/// Errors specific to the agent. Encoded as `ProgramError::Custom(code)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AgentError {
    /// The token program account is not Token-2022.
    WrongTokenProgram = 0,
    /// The delegate account is not the mandate PDA for `(source, destination)`.
    MandateMismatch = 1,
    /// The mint account is not owned by Token-2022.
    MintNotOwnedByToken2022 = 2,
    /// Fee arithmetic overflowed.
    FeeOverflow = 3,
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
    /// 3. `[]` mandate PDA `["mandate", source, destination]`
    /// 4. `[]` Token-2022 program
    ExecuteMandate {
        /// Gross amount, in base units, that leaves the source account.
        amount: u64,
    },
    /// Negative control: forward the *owner's* signature into a transfer CPI.
    ///
    /// Accounts:
    /// 0. `[writable]` source token account
    /// 1. `[]` mint
    /// 2. `[writable]` destination token account
    /// 3. `[signer]` owner of the source account
    /// 4. `[]` Token-2022 program
    ForwardOwnerTransfer {
        /// Gross amount, in base units.
        amount: u64,
    },
    /// Negative control: approve a delegate through CPI.
    ///
    /// Accounts:
    /// 0. `[writable]` source token account
    /// 1. `[]` mint
    /// 2. `[]` delegate to approve
    /// 3. `[signer]` owner of the source account
    /// 4. `[]` Token-2022 program
    ForwardApprove {
        /// Allowance to grant, in base units.
        amount: u64,
    },
}

impl AgentInstruction {
    /// Serialize to instruction data.
    pub fn pack(&self) -> Vec<u8> {
        let (tag, amount) = match *self {
            Self::ExecuteMandate { amount } => (0u8, amount),
            Self::ForwardOwnerTransfer { amount } => (1, amount),
            Self::ForwardApprove { amount } => (2, amount),
        };
        let mut data = Vec::with_capacity(9);
        data.push(tag);
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    /// Deserialize from instruction data.
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        let amount = rest
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        match tag {
            0 => Ok(Self::ExecuteMandate { amount }),
            1 => Ok(Self::ForwardOwnerTransfer { amount }),
            2 => Ok(Self::ForwardApprove { amount }),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Derive the mandate PDA (the delegate a user approves) for a `(source, destination)` pair.
pub fn mandate_address(source: &Address, destination: &Address) -> (Address, u8) {
    Address::find_program_address(
        &[MANDATE_SEED, source.as_ref(), destination.as_ref()],
        &ID,
    )
}

/// Program entrypoint.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts = &mut accounts.iter();
    let source = next_account_info(accounts)?;
    let mint = next_account_info(accounts)?;
    let third = next_account_info(accounts)?;
    let authority = next_account_info(accounts)?;
    let token_program = next_account_info(accounts)?;

    if *token_program.key != spl_token_2022_interface::ID {
        return Err(AgentError::WrongTokenProgram.into());
    }
    let (decimals, fee_config) = read_mint(mint)?;

    match AgentInstruction::unpack(instruction_data)? {
        AgentInstruction::ExecuteMandate { amount } => {
            let destination = third;
            let (mandate, bump) = Address::find_program_address(
                &[MANDATE_SEED, source.key.as_ref(), destination.key.as_ref()],
                program_id,
            );
            if *authority.key != mandate {
                return Err(AgentError::MandateMismatch.into());
            }
            let fee = epoch_fee(fee_config.as_ref(), amount)?;
            solana_msg::msg!("remit-agent: mandate transfer amount={} fee={}", amount, fee);
            let transfer = transfer_checked_with_fee(
                token_program.key,
                source.key,
                mint.key,
                destination.key,
                authority.key,
                &[],
                amount,
                decimals,
                fee,
            )?;
            solana_cpi::invoke_signed(
                &transfer,
                &[source.clone(), mint.clone(), destination.clone(), authority.clone()],
                &[&[MANDATE_SEED, source.key.as_ref(), destination.key.as_ref(), &[bump]]],
            )
        }
        AgentInstruction::ForwardOwnerTransfer { amount } => {
            let destination = third;
            let fee = epoch_fee(fee_config.as_ref(), amount)?;
            let transfer = transfer_checked_with_fee(
                token_program.key,
                source.key,
                mint.key,
                destination.key,
                authority.key,
                &[],
                amount,
                decimals,
                fee,
            )?;
            solana_cpi::invoke(
                &transfer,
                &[source.clone(), mint.clone(), destination.clone(), authority.clone()],
            )
        }
        AgentInstruction::ForwardApprove { amount } => {
            let delegate = third;
            let approve = approve_checked(
                token_program.key,
                source.key,
                mint.key,
                delegate.key,
                authority.key,
                &[],
                amount,
                decimals,
            )?;
            solana_cpi::invoke(
                &approve,
                &[source.clone(), mint.clone(), delegate.clone(), authority.clone()],
            )
        }
    }
}

/// Read decimals and the transfer-fee config from a Token-2022 mint via `StateWithExtensions`.
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

/// Instruction builders for clients.
pub mod instruction {
    use {
        super::*,
        solana_instruction::{AccountMeta, Instruction},
    };

    fn build(accounts: Vec<AccountMeta>, instruction: AgentInstruction) -> Instruction {
        Instruction {
            program_id: ID,
            accounts,
            data: instruction.pack(),
        }
    }

    /// Build [`AgentInstruction::ExecuteMandate`]. No signer is needed: the PDA signs on-chain.
    pub fn execute_mandate(
        source: &Address,
        mint: &Address,
        destination: &Address,
        amount: u64,
    ) -> Instruction {
        let (mandate, _) = mandate_address(source, destination);
        build(
            vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(mandate, false),
                AccountMeta::new_readonly(spl_token_2022_interface::ID, false),
            ],
            AgentInstruction::ExecuteMandate { amount },
        )
    }

    /// Build [`AgentInstruction::ForwardOwnerTransfer`] (negative control).
    pub fn forward_owner_transfer(
        source: &Address,
        mint: &Address,
        destination: &Address,
        owner: &Address,
        amount: u64,
    ) -> Instruction {
        build(
            vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(spl_token_2022_interface::ID, false),
            ],
            AgentInstruction::ForwardOwnerTransfer { amount },
        )
    }

    /// Build [`AgentInstruction::ForwardApprove`] (negative control).
    pub fn forward_approve(
        source: &Address,
        mint: &Address,
        delegate: &Address,
        owner: &Address,
        amount: u64,
    ) -> Instruction {
        build(
            vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(*delegate, false),
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(spl_token_2022_interface::ID, false),
            ],
            AgentInstruction::ForwardApprove { amount },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_data_round_trips() {
        for ix in [
            AgentInstruction::ExecuteMandate { amount: 1 },
            AgentInstruction::ForwardOwnerTransfer { amount: u64::MAX },
            AgentInstruction::ForwardApprove { amount: 42 },
        ] {
            assert_eq!(AgentInstruction::unpack(&ix.pack()).unwrap(), ix);
        }
        assert!(AgentInstruction::unpack(&[9, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(AgentInstruction::unpack(&[0, 1]).is_err());
    }

    #[test]
    fn mandate_is_bound_to_destination() {
        let source = Address::from([1; 32]);
        let (a, _) = mandate_address(&source, &Address::from([2; 32]));
        let (b, _) = mandate_address(&source, &Address::from([3; 32]));
        assert_ne!(a, b);
    }
}
