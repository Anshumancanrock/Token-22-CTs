//! **Task 1: creating the mint.**
//!
//! ## Sizing
//! `InitializeMint` rejects the account (`InvalidAccountData`) unless its length is exactly
//! `ExtensionType::try_calculate_account_len::<Mint>(&extensions)` for the extensions initialized so
//! far. The account is therefore allocated for the fixed-size extensions only. `TokenMetadata` is
//! variable-length; the token-metadata `Initialize` instruction grows the mint in place after
//! `InitializeMint`. Growth does not bring lamports with it, so the account is *funded* up front
//! for its final size: fixed extensions plus the metadata TLV entry.
//!
//! ## Ordering
//! Extension-init instructions only accept an uninitialized mint, and `InitializeMint` checks that
//! every allocated byte belongs to an initialized extension. Every extension init therefore comes
//! before `InitializeMint`. None of those inits needs a signature, so `CreateAccount`, the inits and
//! `InitializeMint` go in one transaction. Split across transactions, anyone could initialize the
//! funded, empty account with their own fee authority or freeze authority first. The metadata
//! instructions come after `InitializeMint` because they need the mint authority's signature.

use {
    crate::{Cluster, Result, TOKEN_2022_PROGRAM_ID},
    solana_address::Address,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_program_error::ProgramError,
    solana_signer::Signer,
    solana_system_interface::instruction::create_account,
    spl_token_2022_interface::{
        extension::{
            default_account_state::instruction::initialize_default_account_state, metadata_pointer,
            transfer_fee::instruction::initialize_transfer_fee_config, ExtensionType,
        },
        instruction::{close_account, initialize_mint2, initialize_mint_close_authority},
        state::{AccountState, Mint},
    },
    spl_token_metadata_interface::{
        instruction::{initialize as initialize_metadata, update_field},
        state::{Field, TokenMetadata},
    },
};

/// Extensions of the v1 mint (task 1), in initialization order.
pub const V1_EXTENSIONS: [ExtensionType; 4] = [
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
];

/// Every authority on the mint. Each power has its own key, so each can be held, rotated or
/// revoked on its own.
pub struct Authorities {
    /// Mints new supply.
    pub mint: Keypair,
    /// Freeze authority, i.e. the KYC desk: thaws accounts once KYC clears, freezes sanctioned ones.
    pub freeze: Keypair,
    /// `TransferFeeConfig` authority: can change the fee (effective two epochs later).
    pub fee_config: Keypair,
    /// Withdraw-withheld authority: the treasury that collects fee revenue.
    pub fee_withdraw: Keypair,
    /// `MintCloseAuthority`: can close the mint once its supply is zero.
    pub close: Keypair,
    /// Update authority of the `MetadataPointer` and the `TokenMetadata`.
    pub metadata: Keypair,
}

impl Authorities {
    /// Fresh random keys for every role.
    pub fn generate() -> Self {
        Self {
            mint: Keypair::new(),
            freeze: Keypair::new(),
            fee_config: Keypair::new(),
            fee_withdraw: Keypair::new(),
            close: Keypair::new(),
            metadata: Keypair::new(),
        }
    }
}

/// Business parameters of the stablecoin.
#[derive(Clone, Debug)]
pub struct StablecoinParams {
    /// Decimals.
    pub decimals: u8,
    /// Transfer fee in basis points.
    pub transfer_fee_basis_points: u16,
    /// Cap on the fee of a single transfer, in base units.
    pub maximum_fee: u64,
    /// Token name.
    pub name: String,
    /// Ticker.
    pub symbol: String,
    /// URI of the off-chain JSON (logo etc.). Everything a wallet must trust lives on-chain.
    pub uri: String,
    /// Extra on-chain key/value metadata.
    pub additional_metadata: Vec<(String, String)>,
}

impl Default for StablecoinParams {
    fn default() -> Self {
        Self {
            decimals: 6,
            transfer_fee_basis_points: 25,
            maximum_fee: 2_500_000,
            name: "Remit USD".into(),
            symbol: "rUSD".into(),
            uri: "https://example.com/rusd/metadata.json".into(),
            additional_metadata: vec![
                ("issuer".into(), "Remit Labs Ltd.".into()),
                ("peg".into(), "1 rUSD = 1 USD".into()),
                ("kyc".into(), "required; new accounts start frozen".into()),
            ],
        }
    }
}

impl StablecoinParams {
    /// The `TokenMetadata` stored in the mint.
    pub fn token_metadata(&self, mint: &Address, update_authority: &Address) -> Result<TokenMetadata> {
        Ok(TokenMetadata {
            update_authority: Some(*update_authority)
                .try_into()
                .map_err(|_| ProgramError::InvalidArgument)?,
            mint: *mint,
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            uri: self.uri.clone(),
            additional_metadata: self.additional_metadata.clone(),
        })
    }
}

/// An extension-init instruction tagged with the extension it initializes.
pub type ExtensionInit = (ExtensionType, Instruction);

/// Everything needed to create a mint, computed before anything is sent.
#[derive(Clone, Debug)]
pub struct MintPlan {
    /// Mint address.
    pub mint: Address,
    /// Fixed-size extensions allocated by `CreateAccount`, in initialization order.
    pub extensions: Vec<ExtensionType>,
    /// `try_calculate_account_len::<Mint>(&extensions)`: the allocation `InitializeMint` demands.
    pub space: usize,
    /// Bytes the `TokenMetadata` TLV entry adds when the metadata is initialized.
    pub metadata_len: usize,
    /// Rent-exempt balance for the final size, `space + metadata_len`.
    pub lamports: u64,
    /// Transaction 1 (atomic): `CreateAccount`, every extension init, then `InitializeMint2`.
    pub initialize: Vec<Instruction>,
    /// Transaction 2: token-metadata `Initialize`, then one `UpdateField` per extra field.
    pub metadata: Vec<Instruction>,
}

/// Extension inits of the v1 mint (task 1).
pub fn v1_extension_inits(
    mint: &Address,
    authorities: &Authorities,
    params: &StablecoinParams,
) -> Result<Vec<ExtensionInit>> {
    Ok(vec![
        (
            ExtensionType::TransferFeeConfig,
            initialize_transfer_fee_config(
                &TOKEN_2022_PROGRAM_ID,
                mint,
                Some(&authorities.fee_config.pubkey()),
                Some(&authorities.fee_withdraw.pubkey()),
                params.transfer_fee_basis_points,
                params.maximum_fee,
            )?,
        ),
        (
            ExtensionType::MetadataPointer,
            // The pointer targets the mint itself: the metadata lives in the mint account, so no
            // off-chain or third-party registry has to be trusted.
            metadata_pointer::instruction::initialize(
                &TOKEN_2022_PROGRAM_ID,
                mint,
                Some(authorities.metadata.pubkey()),
                Some(*mint),
            )?,
        ),
        (
            ExtensionType::DefaultAccountState,
            initialize_default_account_state(&TOKEN_2022_PROGRAM_ID, mint, &AccountState::Frozen)?,
        ),
        (
            ExtensionType::MintCloseAuthority,
            initialize_mint_close_authority(
                &TOKEN_2022_PROGRAM_ID,
                mint,
                Some(&authorities.close.pubkey()),
            )?,
        ),
    ])
}

/// Build a [`MintPlan`] from a list of extension inits.
pub fn plan_from_inits(
    cluster: &impl Cluster,
    mint: &Address,
    authorities: &Authorities,
    params: &StablecoinParams,
    inits: Vec<ExtensionInit>,
) -> Result<MintPlan> {
    let extensions: Vec<ExtensionType> = inits.iter().map(|(extension, _)| *extension).collect();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&extensions)?;
    let metadata_len = params
        .token_metadata(mint, &authorities.metadata.pubkey())?
        .tlv_size_of()?;
    let lamports = cluster.minimum_balance_for_rent_exemption(space + metadata_len);

    let mut initialize = Vec::with_capacity(inits.len() + 2);
    initialize.push(create_account(
        &cluster.payer(),
        mint,
        lamports,
        space as u64,
        &TOKEN_2022_PROGRAM_ID,
    ));
    initialize.extend(inits.into_iter().map(|(_, instruction)| instruction));
    initialize.push(initialize_mint2(
        &TOKEN_2022_PROGRAM_ID,
        mint,
        &authorities.mint.pubkey(),
        // DefaultAccountState::Frozen requires a freeze authority, or InitializeMint fails with
        // MintCannotFreeze.
        Some(&authorities.freeze.pubkey()),
        params.decimals,
    )?);

    let mut metadata = vec![initialize_metadata(
        &TOKEN_2022_PROGRAM_ID,
        mint,
        &authorities.metadata.pubkey(),
        mint,
        &authorities.mint.pubkey(),
        params.name.clone(),
        params.symbol.clone(),
        params.uri.clone(),
    )];
    metadata.extend(params.additional_metadata.iter().map(|(key, value)| {
        update_field(
            &TOKEN_2022_PROGRAM_ID,
            mint,
            &authorities.metadata.pubkey(),
            Field::Key(key.clone()),
            value.clone(),
        )
    }));

    Ok(MintPlan {
        mint: *mint,
        extensions,
        space,
        metadata_len,
        lamports,
        initialize,
        metadata,
    })
}

/// Plan the v1 mint (task 1).
pub fn plan_v1(
    cluster: &impl Cluster,
    mint: &Address,
    authorities: &Authorities,
    params: &StablecoinParams,
) -> Result<MintPlan> {
    let inits = v1_extension_inits(mint, authorities, params)?;
    plan_from_inits(cluster, mint, authorities, params, inits)
}

/// Execute a plan: the atomic initialization transaction, then the metadata transaction.
pub fn create_mint(
    cluster: &mut impl Cluster,
    plan: &MintPlan,
    mint: &Keypair,
    authorities: &Authorities,
) -> Result<()> {
    cluster.send(&plan.initialize, &[mint])?;
    cluster.send(&plan.metadata, &[&authorities.mint, &authorities.metadata])?;
    Ok(())
}

/// Plan and create the v1 mint (task 1).
pub fn create_v1(
    cluster: &mut impl Cluster,
    mint: &Keypair,
    authorities: &Authorities,
    params: &StablecoinParams,
) -> Result<MintPlan> {
    let plan = plan_v1(cluster, &mint.pubkey(), authorities, params)?;
    create_mint(cluster, &plan, mint, authorities)?;
    Ok(plan)
}

/// Decommission the mint: close it and reclaim its rent. Token-2022 only allows this while the
/// supply is zero (`MintHasSupply` otherwise).
pub fn close_mint(
    cluster: &mut impl Cluster,
    mint: &Address,
    close_authority: &Keypair,
    destination: &Address,
) -> Result<()> {
    let instruction = close_account(
        &TOKEN_2022_PROGRAM_ID,
        mint,
        destination,
        &close_authority.pubkey(),
        &[],
    )?;
    cluster.send(&[instruction], &[close_authority])?;
    Ok(())
}
