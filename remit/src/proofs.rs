//! Moving zero-knowledge proofs on-chain within the 1232-byte packet limit.
//!
//! Every confidential debit (transfer, withdraw) needs proofs that are too large to travel inside
//! the Token-2022 instruction's transaction. Each proof is first verified by the ZK ElGamal Proof
//! program into a **context-state account**, which then stores the verified statement. The
//! Token-2022 instruction references that account (`ProofLocation::ContextStateAccount`). Afterwards
//! the accounts are closed and their rent is refunded.
//!
//! How each proof is delivered depends on its size:
//!
//! | proof | bytes | delivery |
//! |---|---|---|
//! | pubkey validity (configure) | 96 | inline, same transaction as `ConfigureAccount` |
//! | ciphertext-commitment equality | 320 | create context + verify, one transaction |
//! | grouped-ciphertext validity (2 / 3 handles) | 416 / 544 | create context + verify, one transaction |
//! | percentage-with-cap (fee) | 360 | create context + verify, one transaction |
//! | batched range proof U64 (withdraw) | 936 | create context, then verify: two transactions |
//! | batched range proof U256 (transfer with fee) | 1064 | written to an `spl-record` account in chunks, then verified from the account |
//!
//! The U256 range proof is larger than any transaction can carry once the signature, the account
//! keys and a compute-budget instruction are added. So it is written into a record account first,
//! and the proof program reads it from there (`encode_verify_proof_from_account`).
//!
//! The ZK ElGamal Proof program is a builtin. Without a `SetComputeUnitLimit`, each builtin
//! instruction gets only 3,000 CU, which is less than every verification costs (even closing a
//! context costs 3,300). Every transaction here therefore sets an explicit limit.

use {
    crate::{
        cluster::{fits_in_one_transaction, with_compute_unit_limit},
        Cluster, Error, Result,
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
/// Budget for one `spl-record` `CloseAccount` (a small SBF program).
const RECORD_CLOSE_UNITS: u32 = 10_000;

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

/// Context-state and record accounts created for one operation, closed together afterwards.
#[derive(Debug, Default)]
pub struct ProofAccounts {
    /// Context-state accounts (owned by the ZK ElGamal Proof program).
    pub contexts: Vec<Address>,
    /// Record accounts holding raw proof bytes (owned by `spl-record`).
    pub records: Vec<Address>,
}

impl ProofAccounts {
    /// Verify `proof` into a new context-state account and remember it for cleanup.
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
        let create = create_context_account::<U>(cluster, &context.pubkey());
        let verify =
            instruction.encode_verify_proof(Some(context_info(&context.pubkey(), &payer)), proof);
        let units = compute_units(instruction) + OVERHEAD_UNITS;

        let together = with_compute_unit_limit(units, vec![create.clone(), verify.clone()]);
        if fits_in_one_transaction(&together, &payer) {
            cluster.send(&together, &[&context])?;
        } else {
            // Fits alone but not next to CreateAccount (the U64 range proof): two transactions.
            cluster.send(&[create], &[&context])?;
            cluster.send(&with_compute_unit_limit(units, vec![verify]), &[])?;
        }
        // Tracked only once verified: an uninitialized context cannot be closed.
        self.contexts.push(context.pubkey());
        Ok(context.pubkey())
    }

    /// Write `proof` into a record account in chunks, then verify it from there into a new
    /// context-state account. For proofs no transaction can carry (the U256 range proof).
    pub fn verify_via_record<T, U>(
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

        // First transaction: create + initialize + as much of the proof as fits.
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
        while offset < bytes.len() {
            let rest = &bytes[offset..];
            let len = largest_chunk(&payer, rest, |chunk| vec![write(offset, chunk)]);
            if len == 0 {
                return Err(Error::Invalid(
                    "record write does not fit a transaction".into(),
                ));
            }
            cluster.send(&[write(offset, &rest[..len])], &[])?;
            offset += len;
        }

        let context = Keypair::new();
        let create_context = create_context_account::<U>(cluster, &context.pubkey());
        let verify = instruction.encode_verify_proof_from_account(
            Some(context_info(&context.pubkey(), &payer)),
            &record.pubkey(),
            RecordData::WRITABLE_START_INDEX as u32,
        );
        cluster.send(
            &with_compute_unit_limit(
                compute_units(instruction) + OVERHEAD_UNITS,
                vec![create_context, verify],
            ),
            &[&context],
        )?;
        self.contexts.push(context.pubkey());
        Ok(context.pubkey())
    }

    /// Close every account, then hand back `result`. Cleanup runs whether or not the operation that
    /// used the proofs succeeded, so a failed transfer does not strand rent in proof accounts.
    pub fn close_after<T>(self, cluster: &mut impl Cluster, result: Result<T>) -> Result<T> {
        let closed = self.close(cluster);
        let value = result?;
        closed?;
        Ok(value)
    }

    /// Close every account and refund the rent to the cluster payer.
    pub fn close(self, cluster: &mut impl Cluster) -> Result<()> {
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
            if !fits_in_one_transaction(&budgeted(&batch), &payer) {
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
