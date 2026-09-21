//! **Task 3: state is read only through `StateWithExtensions`.**
//!
//! This module is the one place where mint and token-account bytes are decoded, and it decodes them
//! only with [`StateWithExtensions::<Mint>::unpack`] and [`StateWithExtensions::<Account>::unpack`].
//! A raw `Mint::unpack` / `Account::unpack` (the SPL `Pack` trait) is wrong for Token-2022 in two
//! ways:
//!
//! 1. `Pack::unpack` requires `data.len() == Mint::LEN` (82) or `Account::LEN` (165). Every account
//!    that carries an extension is longer, so it fails with `InvalidAccountData`.
//! 2. Even where it did decode, it would read the base struct and skip the TLV area. The caller
//!    would never see the transfer fee, the frozen default state, the permanent delegate, CPI Guard
//!    or the encrypted balances, which are the fields a stablecoin client has to respect.
//!
//! The snapshots copy out what the rest of the crate needs. Each field comes from `base` or from
//! `get_extension` / `get_variable_len_extension` on a `StateWithExtensions`.

use {
    crate::{Cluster, Error, Result},
    solana_address::Address,
    solana_program_error::ProgramError,
    spl_token_2022_interface::{
        extension::{
            confidential_transfer::{ConfidentialTransferAccount, ConfidentialTransferMint},
            confidential_transfer_fee::{
                ConfidentialTransferFeeAmount, ConfidentialTransferFeeConfig,
            },
            cpi_guard::CpiGuard,
            default_account_state::DefaultAccountState,
            metadata_pointer::MetadataPointer,
            mint_close_authority::MintCloseAuthority,
            permanent_delegate::PermanentDelegate,
            transfer_fee::{TransferFeeAmount, TransferFeeConfig},
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        },
        state::{Account, AccountState, Mint},
    },
    spl_token_metadata_interface::state::TokenMetadata,
};

/// Fetch raw account bytes, failing if the account does not exist.
pub fn fetch(cluster: &impl Cluster, address: &Address) -> Result<Vec<u8>> {
    cluster
        .account_data(address)
        .ok_or(Error::AccountNotFound(*address))
}

/// A decoded Token-2022 mint with the extensions this project uses.
#[derive(Clone, Debug)]
pub struct MintSnapshot {
    /// Mint address.
    pub address: Address,
    /// Decimals.
    pub decimals: u8,
    /// Total supply, public and confidential balances included.
    pub supply: u64,
    /// Mint authority.
    pub mint_authority: Option<Address>,
    /// Freeze authority (the KYC desk).
    pub freeze_authority: Option<Address>,
    /// Extension types, in TLV order.
    pub extensions: Vec<ExtensionType>,
    /// `TransferFeeConfig`.
    pub transfer_fee: Option<TransferFeeConfig>,
    /// `MetadataPointer`.
    pub metadata_pointer: Option<MetadataPointer>,
    /// `DefaultAccountState`.
    pub default_account_state: Option<AccountState>,
    /// `MintCloseAuthority`.
    pub close_authority: Option<Address>,
    /// `PermanentDelegate`.
    pub permanent_delegate: Option<Address>,
    /// `ConfidentialTransferMint`.
    pub confidential: Option<ConfidentialTransferMint>,
    /// `ConfidentialTransferFeeConfig`.
    pub confidential_fee: Option<ConfidentialTransferFeeConfig>,
    /// `TokenMetadata`, the variable-length extension stored in the mint itself.
    pub metadata: Option<TokenMetadata>,
    /// Account data length.
    pub data_len: usize,
    /// Lamport balance.
    pub lamports: u64,
}

impl MintSnapshot {
    /// Decode mint bytes.
    pub fn decode(address: Address, data: &[u8], lamports: u64) -> Result<Self> {
        let mint = StateWithExtensions::<Mint>::unpack(data)?;
        let default_account_state = mint
            .get_extension::<DefaultAccountState>()
            .ok()
            .map(|extension| AccountState::try_from(extension.state))
            .transpose()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        Ok(Self {
            address,
            decimals: mint.base.decimals,
            supply: mint.base.supply,
            mint_authority: mint.base.mint_authority.into(),
            freeze_authority: mint.base.freeze_authority.into(),
            extensions: mint.get_extension_types()?,
            transfer_fee: mint.get_extension::<TransferFeeConfig>().ok().copied(),
            metadata_pointer: mint.get_extension::<MetadataPointer>().ok().copied(),
            default_account_state,
            close_authority: mint
                .get_extension::<MintCloseAuthority>()
                .ok()
                .and_then(|extension| extension.close_authority.get()),
            permanent_delegate: mint
                .get_extension::<PermanentDelegate>()
                .ok()
                .and_then(|extension| extension.delegate.get()),
            confidential: mint.get_extension::<ConfidentialTransferMint>().ok().copied(),
            confidential_fee: mint
                .get_extension::<ConfidentialTransferFeeConfig>()
                .ok()
                .copied(),
            metadata: mint.get_variable_len_extension::<TokenMetadata>().ok(),
            data_len: data.len(),
            lamports,
        })
    }

    /// The transfer fee config, or an error if the mint has none.
    pub fn require_transfer_fee(&self) -> Result<&TransferFeeConfig> {
        self.transfer_fee
            .as_ref()
            .ok_or_else(|| Error::Invalid(format!("mint {} has no TransferFeeConfig", self.address)))
    }
}

/// A decoded Token-2022 token account with the extensions this project uses.
#[derive(Clone, Debug)]
pub struct AccountSnapshot {
    /// Token account address.
    pub address: Address,
    /// Mint.
    pub mint: Address,
    /// Owner (wallet).
    pub owner: Address,
    /// Public (non-confidential) balance.
    pub amount: u64,
    /// Initialized or frozen.
    pub state: AccountState,
    /// Delegate, if any.
    pub delegate: Option<Address>,
    /// Remaining delegated allowance.
    pub delegated_amount: u64,
    /// Extension types, in TLV order.
    pub extensions: Vec<ExtensionType>,
    /// `TransferFeeAmount::withheld_amount`: fees withheld on public transfers into this account.
    pub withheld_fee: Option<u64>,
    /// `CpiGuard::lock_cpi`.
    pub cpi_guard: Option<bool>,
    /// `ConfidentialTransferAccount`.
    pub confidential: Option<ConfidentialTransferAccount>,
    /// `ConfidentialTransferFeeAmount`: encrypted fees withheld on confidential transfers.
    pub confidential_withheld: Option<ConfidentialTransferFeeAmount>,
    /// Account data length.
    pub data_len: usize,
    /// Lamport balance.
    pub lamports: u64,
}

impl AccountSnapshot {
    /// Decode token-account bytes.
    pub fn decode(address: Address, data: &[u8], lamports: u64) -> Result<Self> {
        let account = StateWithExtensions::<Account>::unpack(data)?;
        Ok(Self {
            address,
            mint: account.base.mint,
            owner: account.base.owner,
            amount: account.base.amount,
            state: account.base.state,
            delegate: account.base.delegate.into(),
            delegated_amount: account.base.delegated_amount,
            extensions: account.get_extension_types()?,
            withheld_fee: account
                .get_extension::<TransferFeeAmount>()
                .ok()
                .map(|extension| u64::from(extension.withheld_amount)),
            cpi_guard: account
                .get_extension::<CpiGuard>()
                .ok()
                .map(|extension| bool::from(extension.lock_cpi)),
            confidential: account
                .get_extension::<ConfidentialTransferAccount>()
                .ok()
                .copied(),
            confidential_withheld: account
                .get_extension::<ConfidentialTransferFeeAmount>()
                .ok()
                .copied(),
            data_len: data.len(),
            lamports,
        })
    }

    /// Whether the freeze authority has frozen the account.
    pub fn is_frozen(&self) -> bool {
        self.state == AccountState::Frozen
    }

    /// The confidential extension, or an error if the account is not configured.
    pub fn require_confidential(&self) -> Result<&ConfidentialTransferAccount> {
        self.confidential.as_ref().ok_or_else(|| {
            Error::Invalid(format!(
                "token account {} is not configured for confidential transfers",
                self.address
            ))
        })
    }
}

/// Fetch and decode a mint.
pub fn load_mint(cluster: &impl Cluster, address: &Address) -> Result<MintSnapshot> {
    let data = fetch(cluster, address)?;
    MintSnapshot::decode(*address, &data, cluster.lamports(address))
}

/// Fetch and decode a token account.
pub fn load_account(cluster: &impl Cluster, address: &Address) -> Result<AccountSnapshot> {
    let data = fetch(cluster, address)?;
    AccountSnapshot::decode(*address, &data, cluster.lamports(address))
}
