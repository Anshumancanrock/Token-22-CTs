//! Task 3: account and mint state is read only through `StateWithExtensions`.

mod common;

use {
    common::*,
    remit::state::fetch,
    solana_keypair::Keypair,
    solana_program_error::ProgramError,
    spl_token_2022_interface::{
        extension::{
            transfer_fee::TransferFeeAmount, BaseStateWithExtensions, ExtensionType,
            StateWithExtensions,
        },
        state::{Account, Mint},
    },
    std::path::Path,
};

#[test]
fn raw_pack_unpack_cannot_read_token_2022_accounts() {
    // Negative control, kept out of the library on purpose: this is the mistake task 3 forbids.
    use solana_program_pack::Pack;

    let mut coin = Stablecoin::v1();
    let account = coin.onboard(&Keypair::new());
    let mint_data = fetch(&coin.svm, &coin.mint).unwrap();
    let account_data = fetch(&coin.svm, &account).unwrap();

    assert_eq!(
        Mint::unpack(&mint_data),
        Err(ProgramError::InvalidAccountData)
    );
    assert_eq!(
        Account::unpack(&account_data),
        Err(ProgramError::InvalidAccountData)
    );

    // StateWithExtensions reads the base state and the TLV extensions.
    let mint = StateWithExtensions::<Mint>::unpack(&mint_data).unwrap();
    assert_eq!(mint.base.decimals, 6);
    assert!(mint
        .get_extension_types()
        .unwrap()
        .contains(&ExtensionType::TransferFeeConfig));
    let token = StateWithExtensions::<Account>::unpack(&account_data).unwrap();
    assert_eq!(token.base.mint, coin.mint);
    assert_eq!(
        u64::from(
            token
                .get_extension::<TransferFeeAmount>()
                .unwrap()
                .withheld_amount
        ),
        0
    );
}

#[test]
fn account_snapshot_exposes_the_extensions_the_mint_imposes() {
    let mut coin = Stablecoin::v1();
    let account = coin.onboard(&Keypair::new());
    let snapshot = coin.account(&account);
    // TransferFeeConfig on the mint forces TransferFeeAmount on every account; the ATA program adds
    // ImmutableOwner.
    for extension in [
        ExtensionType::TransferFeeAmount,
        ExtensionType::ImmutableOwner,
    ] {
        assert!(snapshot.extensions.contains(&extension), "{extension:?}");
    }
    assert_eq!(snapshot.withheld_fee, Some(0));
    assert_eq!(snapshot.cpi_guard, None);
    assert!(snapshot.confidential.is_none());
}

/// Lint: no source file of the library or the program decodes state with the `Pack` trait.
#[test]
fn no_raw_unpack_anywhere_in_the_codebase() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let forbidden = [
        "solana_program_pack",
        "Pack::unpack",
        "Mint::unpack",
        "Account::unpack",
        "unpack_unchecked",
        "unpack_from_slice",
    ];
    let mut decoders = 0;
    for dir in [
        "remit/src",
        "programs/remit-agent/src",
        "programs/cpi-guard-probe/src",
    ] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            // Code only: the docs are allowed to name what they forbid.
            let source: String = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for pattern in forbidden {
                assert!(
                    !source.contains(pattern),
                    "{} uses `{pattern}`",
                    path.display()
                );
            }
            decoders += source.matches("StateWithExtensions::<").count();
        }
    }
    assert!(decoders >= 3, "state is decoded with StateWithExtensions");
}
