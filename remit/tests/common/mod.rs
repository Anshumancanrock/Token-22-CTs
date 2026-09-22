//! Shared test harness: an in-process cluster (LiteSVM) and a stablecoin fixture.
//!
//! `LiteSVM::new()` runs the mainnet feature set with the Token-2022 v11 program, the ATA program
//! and the ZK ElGamal Proof program built in. On top of that the harness loads the mainnet
//! `spl-record` binary (`fixtures/spl_record.so`) and, for the CPI Guard tests, the `remit-agent`
//! program built with `cargo build-sbf`.

#![allow(dead_code)]

use {
    litesvm::LiteSVM,
    remit::{
        cluster::transaction_size,
        confidential::{self, ConfidentialKeys},
        kyc::approve_kyc,
        mint::{self, Authorities, ComplianceAuthorities, MintPlan, StablecoinParams},
        state::{load_account, load_mint, AccountSnapshot, MintSnapshot},
        token::{create_token_account, mint_to},
        Cluster, Error, Receipt, Result, PACKET_DATA_SIZE,
    },
    solana_address::Address,
    solana_clock::Clock,
    solana_instruction::{error::InstructionError, Instruction},
    solana_keypair::Keypair,
    solana_message::Message,
    solana_signer::Signer,
    solana_transaction::Transaction,
    spl_token_2022_interface::error::TokenError,
    std::{fmt::Debug, path::PathBuf},
};

/// One rUSD in base units (6 decimals).
pub const RUSD: u64 = 1_000_000;

/// LiteSVM behind the library's [`Cluster`] trait.
pub struct Svm {
    pub svm: LiteSVM,
    payer: Keypair,
    /// Every landed transaction, in order.
    pub receipts: Vec<Receipt>,
}

impl Svm {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program(
            spl_record::id(),
            include_bytes!("../../../fixtures/spl_record.so"),
        )
        .expect("load spl-record");
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000)
            .expect("airdrop");
        Self {
            svm,
            payer,
            receipts: Vec::new(),
        }
    }

    /// Also load the `remit-agent` SBF program.
    pub fn with_agent(mut self) -> Self {
        let path = std::env::var("REMIT_AGENT_SO")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/remit_agent.so")
            });
        let bytes = std::fs::read(&path).unwrap_or_else(|_| {
            panic!(
                "{} not found: build the program first with `cargo build-sbf --manifest-path \
                 programs/remit-agent/Cargo.toml` (or `make test`)",
                path.display()
            )
        });
        self.svm
            .add_program(remit_agent::ID, &bytes)
            .expect("load remit-agent");
        self
    }

    pub fn airdrop(&mut self, address: &Address, lamports: u64) {
        self.svm.airdrop(address, lamports).expect("airdrop");
    }

    /// Jump to `epoch` (only the Clock sysvar changes; enough for epoch-dependent fees).
    pub fn warp_to_epoch(&mut self, epoch: u64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.epoch = epoch;
        clock.leader_schedule_epoch = epoch + 1;
        self.svm.set_sysvar(&clock);
    }

    /// Transactions landed since receipt index `from`.
    pub fn since(&self, from: usize) -> &[Receipt] {
        &self.receipts[from..]
    }
}

impl Cluster for Svm {
    fn payer(&self) -> Address {
        self.payer.pubkey()
    }

    fn account_data(&self, address: &Address) -> Option<Vec<u8>> {
        self.svm
            .get_account(address)
            .filter(|account| account.lamports > 0)
            .map(|account| account.data)
    }

    fn lamports(&self, address: &Address) -> u64 {
        self.svm.get_balance(address).unwrap_or(0)
    }

    fn epoch(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().epoch
    }

    fn minimum_balance_for_rent_exemption(&self, data_len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(data_len)
    }

    fn send(&mut self, instructions: &[Instruction], signers: &[&Keypair]) -> Result<Receipt> {
        let payer = self.payer.pubkey();
        let size = transaction_size(instructions, &payer);
        if size > PACKET_DATA_SIZE {
            return Err(Error::TransactionTooLarge {
                size,
                limit: PACKET_DATA_SIZE,
            });
        }
        let message = Message::new(instructions, Some(&payer));
        let required = &message.account_keys[..usize::from(message.header.num_required_signatures)];
        let mut keypairs: Vec<&Keypair> = vec![&self.payer];
        for signer in signers {
            let key = signer.pubkey();
            if required.contains(&key) && !keypairs.iter().any(|k| k.pubkey() == key) {
                keypairs.push(signer);
            }
        }
        let mut transaction = Transaction::new_unsigned(message);
        transaction
            .try_sign(&keypairs, self.svm.latest_blockhash())
            .map_err(|error| Error::Invalid(format!("signing failed: {error}")))?;

        let result = self.svm.send_transaction(transaction);
        // A fresh blockhash per transaction, so identical instructions can be sent again.
        self.svm.expire_blockhash();
        match result {
            Ok(meta) => {
                let receipt = Receipt {
                    compute_units: meta.compute_units_consumed,
                    size,
                    logs: meta.logs,
                };
                self.receipts.push(receipt.clone());
                Ok(receipt)
            }
            Err(failed) => {
                if std::env::var_os("REMIT_LOGS").is_some() {
                    eprintln!("{}", failed.meta.logs.join("\n"));
                }
                Err(Error::Transaction {
                    err: failed.err,
                    logs: failed.meta.logs,
                })
            }
        }
    }
}

/// A deployed rUSD mint plus the keys that run it.
pub struct Stablecoin {
    pub svm: Svm,
    pub authorities: Authorities,
    pub compliance: ComplianceAuthorities,
    pub params: StablecoinParams,
    pub mint: Address,
    pub plan: MintPlan,
}

impl Stablecoin {
    /// Task 1 mint.
    pub fn v1() -> Self {
        Self::deploy(Svm::new(), false)
    }

    /// Task 5 mint (confidential transfers, permanent delegate).
    pub fn v2() -> Self {
        Self::deploy(Svm::new(), true)
    }

    pub fn deploy(mut svm: Svm, confidential: bool) -> Self {
        let authorities = Authorities::generate();
        let compliance = ComplianceAuthorities::generate();
        let params = StablecoinParams::default();
        let mint = Keypair::new();
        let plan = if confidential {
            mint::create_v2(&mut svm, &mint, &authorities, &compliance, &params)
        } else {
            mint::create_v1(&mut svm, &mint, &authorities, &params)
        }
        .expect("create mint");
        Self {
            svm,
            authorities,
            compliance,
            params,
            mint: mint.pubkey(),
            plan,
        }
    }

    pub fn mint(&self) -> MintSnapshot {
        load_mint(&self.svm, &self.mint).expect("load mint")
    }

    pub fn account(&self, address: &Address) -> AccountSnapshot {
        load_account(&self.svm, address).expect("load account")
    }

    /// Create `owner`'s token account (paid by the harness payer, not the owner) and clear KYC.
    pub fn onboard(&mut self, owner: &Keypair) -> Address {
        let account = create_token_account(&mut self.svm, &owner.pubkey(), &self.mint)
            .expect("create token account");
        approve_kyc(&mut self.svm, &account, &self.authorities.freeze).expect("kyc");
        account
    }

    pub fn fund(&mut self, account: &Address, amount: u64) {
        mint_to(
            &mut self.svm,
            &self.mint,
            account,
            &self.authorities.mint,
            amount,
        )
        .expect("mint_to");
    }

    /// v2 only: onboard, configure (owner) and approve (issuer) for confidential transfers.
    pub fn onboard_confidential(&mut self, owner: &Keypair) -> (Address, ConfidentialKeys) {
        let account = self.onboard(owner);
        let keys = ConfidentialKeys::derive(owner, &account).expect("derive keys");
        confidential::configure_account(&mut self.svm, &account, owner, &keys).expect("configure");
        confidential::approve_account(&mut self.svm, &account, &self.compliance.confidential)
            .expect("approve");
        (account, keys)
    }
}

/// A wallet with some SOL (for when a test user pays for something themselves).
pub fn wallet(svm: &mut Svm) -> Keypair {
    let keypair = Keypair::new();
    svm.airdrop(&keypair.pubkey(), 10_000_000_000);
    keypair
}

#[track_caller]
pub fn assert_token_error<T: Debug>(result: Result<T>, expected: TokenError) {
    let error = result.expect_err("expected the transaction to fail");
    assert_eq!(
        error.token_error(),
        Some(expected.clone()),
        "expected {expected:?}, got: {error}\n{}",
        error.logs().join("\n")
    );
}

#[track_caller]
pub fn assert_instruction_error<T: Debug>(
    result: Result<T>,
    index: u8,
    expected: InstructionError,
) {
    let error = result.expect_err("expected the transaction to fail");
    assert_eq!(
        error.instruction_error(),
        Some((index, &expected)),
        "got: {error}\n{}",
        error.logs().join("\n")
    );
}
