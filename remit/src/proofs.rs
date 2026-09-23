//! Moving zero-knowledge proofs on-chain within the 1232-byte packet limit.
//!
//! Every confidential debit (transfer, withdraw) needs proofs that are too large to travel inside
//! the Token-2022 instruction's transaction. A proof is verified by the ZK ElGamal Proof program
//! into a **context-state account**, which stores the verified statement, and the Token-2022
//! instruction references that account (`ProofLocation::ContextStateAccount`). Afterwards the
//! accounts are closed and their rent goes back to the payer.
//!
//! How each proof travels depends on its size:
//!
//! | proof | bytes | delivery |
//! |---|---|---|
//! | pubkey validity (configure) | 96 | inline in the `ConfigureAccount` transaction |
//! | ciphertext-commitment equality, withdraw | 320 | inline in the `Withdraw` transaction |
//! | ciphertext-commitment equality, transfer | 320 | own transaction: create context + verify |
//! | grouped-ciphertext validity (2 / 3 handles) | 416 / 544 | own transaction: create context + verify |
//! | percentage-with-cap (fee) | 360 | own transaction: create context + verify |
//! | batched range proof U64 (withdraw) | 936 | record account, verified inside the `Withdraw` transaction |
//! | batched range proof U256 (transfer with fee) | 1064 | record account, verified inside the `TransferWithFee` transaction |
//!
//! A context account is always created and verified **in the same transaction**. The two range
//! proofs do not fit next to a `CreateAccount` (the U256 one does not fit in any transaction at
//! all), and splitting creation and verification would leave an empty, proof-program-owned
//! account on-chain between two transactions. Anyone could verify their own proof into it, make
//! themselves its authority, and later close it and collect the rent. So range proofs are written
//! into an `spl-record` account instead, and [`ProofAccounts::consume`] creates their context,
//! verifies them from the record, runs the Token-2022 instruction and closes every proof account,
//! all in one transaction.
//!
//! The ZK ElGamal Proof program is a builtin. Without a `SetComputeUnitLimit`, each builtin
//! instruction gets only 3,000 CU, which is less than every verification costs (even closing a
//! context costs 3,300). Every transaction here therefore sets an explicit limit.

use {
    crate::{
        cluster::{fits_in_one_transaction, with_compute_unit_limit},
        Cluster, Error, Receipt, Result,
    },
    bytemuck::Pod,
    solana_address::Address,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_system_interface::instruction::create_account,
    solana_zk_elgamal_proof_interface::{
        instruction::{close_context_state, ContextStateInfo, ProofInstruction},
        proof_data::ZkProofData,
        state::ProofContextState,
    },
    spl_record::state::RecordData,
};

/// Headroom for the system-program and compute-budget instructions sharing a transaction.
const OVERHEAD_UNITS: u32 = 2_000;
/// Budget for one `spl-record` `CloseAccount` (measured at about 850 CU).
const RECORD_CLOSE_UNITS: u32 = 5_000;
/// Budget for one `spl-record` `Write` riding in the consuming transaction (measured at about 650 CU).
const RECORD_WRITE_UNITS: u32 = 2_000;

/// Compute units the ZK ElGamal Proof program charges for `instruction`.
pub fn compute_units(instruction: ProofInstruction) -> u32 {
    use ProofInstruction::*;
    match instruction {
        CloseContextState => 3_300,
        VerifyZeroCiphertext => 6_000,
        VerifyCiphertextCiphertextEquality => 8_000,
        VerifyCiphertextCommitmentEquality => 6_400,
        VerifyPubkeyValidity => 2_600,
        VerifyPercentageWithCap => 6_500,
        VerifyBatchedRangeProofU64 => 111_000,
        VerifyBatchedRangeProofU128 => 200_000,
        VerifyBatchedRangeProofU256 => 368_000,
        VerifyGroupedCiphertext2HandlesValidity => 6_400,
        VerifyBatchedGroupedCiphertext2HandlesValidity => 13_000,
        VerifyGroupedCiphertext3HandlesValidity => 8_100,
        VerifyBatchedGroupedCiphertext3HandlesValidity => 16_400,
    }
}

/// A record-backed proof whose verification waits for the consuming transaction.
struct Staged {
    context: Keypair,
    /// The last record chunk, if it has not been written yet.
    tail_write: Option<Instruction>,
    create: Instruction,
    verify: Instruction,
    units: u32,
}

/// The proof accounts of one confidential operation.
///
/// Call [`verify`](Self::verify) or [`stage_from_record`](Self::stage_from_record) for each proof,
/// then [`consume`](Self::consume) with the Token-2022 instruction. If anything fails before
/// `consume`, call [`close_after`](Self::close_after) so the accounts created so far are closed.
#[derive(Default)]
pub struct ProofAccounts {
    /// Verified context-state accounts (owned by the ZK ElGamal Proof program).
    contexts: Vec<Address>,
    /// Record accounts holding raw proof bytes (owned by `spl-record`).
    records: Vec<Address>,
    staged: Vec<Staged>,
}

impl ProofAccounts {
    /// Create a context-state account and verify `proof` into it, in one transaction.
    pub fn verify<T, U>(
        &mut self,
        cluster: &mut impl Cluster,
        instruction: ProofInstruction,
        proof: &T,
    ) -> Result<Address>
    where
        T: Pod + ZkProofData<U>,
        U: Pod,
    {
        let payer = cluster.payer();
        let context = Keypair::new();
        let transaction = with_compute_unit_limit(
            compute_units(instruction) + OVERHEAD_UNITS,
            vec![
                create_context_account::<U>(cluster, &context.pubkey()),
                instruction
                    .encode_verify_proof(Some(context_info(&context.pubkey(), &payer)), proof),
            ],
        );
        if !fits_in_one_transaction(&transaction, &payer) {
            return Err(Error::Invalid(format!(
                "{instruction:?} does not fit next to its CreateAccount; use stage_from_record"
            )));
        }
        cluster.send(&transaction, &[&context])?;
        self.contexts.push(context.pubkey());
        Ok(context.pubkey())
    }

    /// Write `proof` into a new record account now, and verify it from there inside the consuming
    /// transaction. Returns the address its context-state account will have.
    ///
    /// The record is created, initialized and filled with as many bytes as fit in the first
    /// transaction. The last chunk is kept back so [`consume`](Self::consume) can carry it when
    /// there is room.
    pub fn stage_from_record<T, U>(
        &mut self,
        cluster: &mut impl Cluster,
        instruction: ProofInstruction,
        proof: &T,
    ) -> Result<Address>
    where
        T: Pod + ZkProofData<U>,
        U: Pod,
    {
        let payer = cluster.payer();
        let bytes = bytemuck::bytes_of(proof);
        let record = Keypair::new();
        let space = RecordData::WRITABLE_START_INDEX + bytes.len();
        let create = create_account(
            &payer,
            &record.pubkey(),
            cluster.minimum_balance_for_rent_exemption(space),
            space as u64,
            &spl_record::id(),
        );
        let initialize = spl_record::instruction::initialize(&record.pubkey(), &payer);
        let write = |offset: usize, chunk: &[u8]| {
            spl_record::instruction::write(&record.pubkey(), &payer, offset as u64, chunk)
        };

        let mut offset = largest_chunk(&payer, bytes, |chunk| {
            vec![create.clone(), initialize.clone(), write(0, chunk)]
        });
        cluster.send(
            &[
                create.clone(),
                initialize.clone(),
                write(0, &bytes[..offset]),
            ],
            &[&record],
        )?;
        self.records.push(record.pubkey());

        // Write full chunks until the rest fits in a single write, and keep that one back.
        let mut tail_write = None;
        while offset < bytes.len() {
            let rest = &bytes[offset..];
            let len = largest_chunk(&payer, rest, |chunk| vec![write(offset, chunk)]);
            if len == 0 {
                return Err(Error::Invalid(
                    "record write does not fit a transaction".into(),
                ));
            }
            if len == rest.len() {
                tail_write = Some(write(offset, rest));
                break;
            }
            cluster.send(&[write(offset, &rest[..len])], &[])?;
            offset += len;
        }

        let context = Keypair::new();
        let address = context.pubkey();
        self.staged.push(Staged {
            create: create_context_account::<U>(cluster, &address),
            verify: instruction.encode_verify_proof_from_account(
                Some(context_info(&address, &payer)),
                &record.pubkey(),
                RecordData::WRITABLE_START_INDEX as u32,
            ),
            units: compute_units(instruction),
            tail_write,
            context,
        });
        Ok(address)
    }

    /// Send `instructions` (the Token-2022 instruction that uses the proofs) in one transaction
    /// together with the staged verifications before it and the closing of every proof account
    /// after it. `units` is the compute budget of `instructions`.
    ///
    /// Staged record tails ride along if they fit and are written just before otherwise. If the
    /// transaction fails, the proof accounts are closed in a separate transaction and the original
    /// error is returned.
    pub fn consume(
        mut self,
        cluster: &mut impl Cluster,
        instructions: Vec<Instruction>,
        signers: &[&Keypair],
        units: u32,
    ) -> Result<Receipt> {
        let payer = cluster.payer();
        let build = |this: &Self, with_tails: bool| {
            let mut all = Vec::new();
            let mut total = units + OVERHEAD_UNITS;
            for staged in &this.staged {
                if let (true, Some(tail)) = (with_tails, &staged.tail_write) {
                    all.push(tail.clone());
                    total += RECORD_WRITE_UNITS;
                }
                all.push(staged.create.clone());
                all.push(staged.verify.clone());
                total += staged.units;
            }
            all.extend(instructions.iter().cloned());
            let staged_contexts: Vec<Address> = this
                .staged
                .iter()
                .map(|staged| staged.context.pubkey())
                .collect();
            for context in this.contexts.iter().chain(&staged_contexts) {
                all.push(close_context_state(context_info(context, &payer), &payer));
                total += compute_units(ProofInstruction::CloseContextState);
            }
            for record in &this.records {
                all.push(spl_record::instruction::close_account(
                    record, &payer, &payer,
                ));
                total += RECORD_CLOSE_UNITS;
            }
            with_compute_unit_limit(total, all)
        };

        let mut transaction = build(&self, true);
        if !fits_in_one_transaction(&transaction, &payer) {
            let tails: Vec<Instruction> = self
                .staged
                .iter_mut()
                .filter_map(|staged| staged.tail_write.take())
                .collect();
            for tail in tails {
                if let Err(error) = cluster.send(&[tail], &[]) {
                    return self.close_after(cluster, Err(error));
                }
            }
            transaction = build(&self, false);
        }
        if !fits_in_one_transaction(&transaction, &payer) {
            let error = Error::Invalid("proofs and instruction do not fit one transaction".into());
            return self.close_after(cluster, Err(error));
        }

        let mut keypairs = signers.to_vec();
        keypairs.extend(self.staged.iter().map(|staged| &staged.context));
        let result = cluster.send(&transaction, &keypairs);
        if result.is_err() {
            // The failed transaction created none of the staged contexts; close the rest.
            self.staged.clear();
            return self.close_after(cluster, result);
        }
        result
    }

    /// Close every account created so far, then hand back `result`, so a failed operation does not
    /// strand rent in proof accounts.
    pub fn close_after<T>(mut self, cluster: &mut impl Cluster, result: Result<T>) -> Result<T> {
        // Staged contexts only exist inside the consuming transaction.
        self.staged.clear();
        let closed = self.close(cluster);
        let value = result?;
        closed?;
        Ok(value)
    }

    fn close(self, cluster: &mut impl Cluster) -> Result<()> {
        let payer = cluster.payer();
        let mut pending: Vec<(Instruction, u32)> = self
            .contexts
            .iter()
            .map(|context| {
                (
                    close_context_state(context_info(context, &payer), &payer),
                    compute_units(ProofInstruction::CloseContextState),
                )
            })
            .collect();
        pending.extend(self.records.iter().map(|record| {
            (
                spl_record::instruction::close_account(record, &payer, &payer),
                RECORD_CLOSE_UNITS,
            )
        }));

        // Greedily pack the close instructions into as few transactions as fit.
        let mut batch: Vec<(Instruction, u32)> = Vec::new();
        for item in pending {
            batch.push(item);
            if batch.len() > 1 && !fits_in_one_transaction(&budgeted(&batch), &payer) {
                let overflow = batch.pop().expect("just pushed");
                cluster.send(&budgeted(&batch), &[])?;
                batch = vec![overflow];
            }
        }
        if !batch.is_empty() {
            cluster.send(&budgeted(&batch), &[])?;
        }
        Ok(())
    }
}

fn budgeted(batch: &[(Instruction, u32)]) -> Vec<Instruction> {
    let units = batch.iter().map(|(_, units)| units).sum::<u32>() + OVERHEAD_UNITS;
    with_compute_unit_limit(units, batch.iter().map(|(ix, _)| ix.clone()).collect())
}

fn context_info<'a>(context: &'a Address, authority: &'a Address) -> ContextStateInfo<'a> {
    ContextStateInfo {
        context_state_account: context,
        context_state_authority: authority,
    }
}

fn create_context_account<U: Pod>(cluster: &impl Cluster, context: &Address) -> Instruction {
    let space = std::mem::size_of::<ProofContextState<U>>();
    create_account(
        &cluster.payer(),
        context,
        cluster.minimum_balance_for_rent_exemption(space),
        space as u64,
        &solana_zk_elgamal_proof_interface::id(),
    )
}

/// Largest prefix of `data` for which `build(prefix)` still fits in one transaction.
fn largest_chunk(payer: &Address, data: &[u8], build: impl Fn(&[u8]) -> Vec<Instruction>) -> usize {
    let (mut low, mut high) = (0, data.len());
    while low < high {
        let mid = (low + high).div_ceil(2);
        if fits_in_one_transaction(&build(&data[..mid]), payer) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{cluster::transaction_size, PACKET_DATA_SIZE},
        bytemuck::Zeroable,
        solana_zk_elgamal_proof_interface::proof_data::{
            BatchedGroupedCiphertext2HandlesValidityProofData,
            BatchedGroupedCiphertext3HandlesValidityProofData, BatchedRangeProofU256Data,
            BatchedRangeProofU64Data, CiphertextCommitmentEqualityProofData,
            PercentageWithCapProofData, PubkeyValidityProofData,
        },
        std::mem::size_of,
    };

    /// The sizes quoted in the module docs.
    #[test]
    fn proof_sizes() {
        assert_eq!(size_of::<PubkeyValidityProofData>(), 96);
        assert_eq!(size_of::<CiphertextCommitmentEqualityProofData>(), 320);
        assert_eq!(
            size_of::<BatchedGroupedCiphertext2HandlesValidityProofData>(),
            416
        );
        assert_eq!(
            size_of::<BatchedGroupedCiphertext3HandlesValidityProofData>(),
            544
        );
        assert_eq!(size_of::<PercentageWithCapProofData>(), 360);
        assert_eq!(size_of::<BatchedRangeProofU64Data>(), 936);
        assert_eq!(size_of::<BatchedRangeProofU256Data>(), 1064);
    }

    fn payer() -> Address {
        Address::from([1; 32])
    }

    /// Size of `[SetComputeUnitLimit, (CreateAccount,) Verify-into-context]`.
    fn verify_size<T: Pod + ZkProofData<U>, U: Pod>(
        instruction: ProofInstruction,
        with_create: bool,
    ) -> usize {
        let (payer, context) = (payer(), Address::from([2; 32]));
        let verify =
            instruction.encode_verify_proof(Some(context_info(&context, &payer)), &T::zeroed());
        let mut instructions = vec![verify];
        if with_create {
            instructions.insert(
                0,
                create_account(
                    &payer,
                    &context,
                    1,
                    1,
                    &solana_zk_elgamal_proof_interface::id(),
                ),
            );
        }
        transaction_size(&with_compute_unit_limit(1, instructions), &payer)
    }

    /// Why the U64 range proof goes through a record: verifying it right after its CreateAccount does
    /// not fit, and the alternative (create, then verify in a later transaction) leaves an empty
    /// context account that anyone can take over.
    #[test]
    fn u64_range_proof_fits_alone_but_not_next_to_create_account() {
        let alone = verify_size::<BatchedRangeProofU64Data, _>(
            ProofInstruction::VerifyBatchedRangeProofU64,
            false,
        );
        let with_create = verify_size::<BatchedRangeProofU64Data, _>(
            ProofInstruction::VerifyBatchedRangeProofU64,
            true,
        );
        assert!(alone <= PACKET_DATA_SIZE, "{alone}");
        assert!(with_create > PACKET_DATA_SIZE, "{with_create}");
    }

    #[test]
    fn u256_range_proof_fits_no_transaction_at_all() {
        // Even the smallest possible carrier (fee payer only, no context account, no compute
        // budget) is over the limit, so the proof has to come from an account.
        let bare = ProofInstruction::VerifyBatchedRangeProofU256
            .encode_verify_proof(None, &BatchedRangeProofU256Data::zeroed());
        let size = transaction_size(&[bare], &payer());
        assert!(size > PACKET_DATA_SIZE, "{size}");
    }
}
