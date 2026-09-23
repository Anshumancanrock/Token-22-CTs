//! # cpi-guard-probe
//!
//! Test fixture, not meant for deployment. It does what a malicious or careless program can do
//! once a user signs one of its instructions: forward the owner's signature into a Token-2022
//! transfer, or approve a delegate through CPI. The CPI Guard tests use it to show that both work
//! before the user enables CPI Guard and fail after, while the `remit-agent` delegated path keeps
//! working.

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

solana_address::declare_id!("PrbYbnB8WGBgCumTLHbUzWUe8hks2bA4KYHYaQXGTKW");

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

/// Probe instructions. Wire format: a one-byte tag followed by a little-endian `u64` amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeInstruction {
    /// Forward the owner's signature into a `TransferCheckedWithFee` CPI.
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
    /// Approve a delegate through CPI, with the owner's forwarded signature.
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

impl ProbeInstruction {
    /// Serialize to instruction data.
    pub fn pack(&self) -> Vec<u8> {
        let (tag, amount) = match *self {
            Self::ForwardOwnerTransfer { amount } => (0u8, amount),
            Self::ForwardApprove { amount } => (1, amount),
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
            0 => Ok(Self::ForwardOwnerTransfer { amount }),
            1 => Ok(Self::ForwardApprove { amount }),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// Program entrypoint.
pub fn process_instruction(
    _program_id: &Address,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = ProbeInstruction::unpack(instruction_data)?;
    let accounts = &mut accounts.iter();
    let source = next_account_info(accounts)?;
    let mint = next_account_info(accounts)?;
    let target = next_account_info(accounts)?;
    let owner = next_account_info(accounts)?;
    let token_program = next_account_info(accounts)?;
    let account_infos = [
        source.clone(),
        mint.clone(),
        target.clone(),
        owner.clone(),
        token_program.clone(),
    ];

    let (decimals, fee_config) = {
        let data = mint.try_borrow_data()?;
        let state = StateWithExtensions::<Mint>::unpack(&data)?;
        let fee_config = state.get_extension::<TransferFeeConfig>().ok().copied();
        (state.base.decimals, fee_config)
    };
    // The instruction builders reject any program id other than Token-2022.
    match instruction {
        ProbeInstruction::ForwardOwnerTransfer { amount } => {
            let fee = match fee_config {
                None => 0,
                Some(config) => {
                    use solana_sysvar::Sysvar;
                    config
                        .calculate_epoch_fee(solana_clock::Clock::get()?.epoch, amount)
                        .ok_or(ProgramError::ArithmeticOverflow)?
                }
            };
            let transfer = transfer_checked_with_fee(
                token_program.key,
                source.key,
                mint.key,
                target.key,
                owner.key,
                &[],
                amount,
                decimals,
                fee,
            )?;
            solana_cpi::invoke(&transfer, &account_infos)
        }
        ProbeInstruction::ForwardApprove { amount } => {
            let approve = approve_checked(
                token_program.key,
                source.key,
                mint.key,
                target.key,
                owner.key,
                &[],
                amount,
                decimals,
            )?;
            solana_cpi::invoke(&approve, &account_infos)
        }
    }
}

/// Instruction builders for the tests.
pub mod instruction {
    use {
        super::*,
        solana_instruction::{AccountMeta, Instruction},
    };

    fn build(target: AccountMeta, accounts: [&Address; 3], data: ProbeInstruction) -> Instruction {
        let [source, mint, owner] = accounts;
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                target,
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(spl_token_2022_interface::ID, false),
            ],
            data: data.pack(),
        }
    }

    /// Build [`ProbeInstruction::ForwardOwnerTransfer`].
    pub fn forward_owner_transfer(
        source: &Address,
        mint: &Address,
        destination: &Address,
        owner: &Address,
        amount: u64,
    ) -> Instruction {
        build(
            AccountMeta::new(*destination, false),
            [source, mint, owner],
            ProbeInstruction::ForwardOwnerTransfer { amount },
        )
    }

    /// Build [`ProbeInstruction::ForwardApprove`].
    pub fn forward_approve(
        source: &Address,
        mint: &Address,
        delegate: &Address,
        owner: &Address,
        amount: u64,
    ) -> Instruction {
        build(
            AccountMeta::new_readonly(*delegate, false),
            [source, mint, owner],
            ProbeInstruction::ForwardApprove { amount },
        )
    }
}
