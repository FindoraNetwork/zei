use crate::anon_xfr::circuits::{
    build_eq_committed_vals_cs, build_multi_xfr_cs, AMultiXfrPubInputs, AMultiXfrWitness,
};
use crate::setup::{NodeParams, UserParams};
use algebra::bls12_381::BLSScalar;
use algebra::jubjub::JubjubPoint;
use crypto::basics::commitments::pedersen::PedersenGens;
use merlin::Transcript;
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use poly_iops::plonk::protocol::prover::{prover, verifier, PlonkPf};
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use utils::errors::ZeiError;
use std::time::SystemTime;

const ANON_XFR_TRANSCRIPT: &[u8] = b"Anon Xfr";
const N_INPUTS_TRANSCRIPT: &[u8] = b"Number of input ABARs";
const N_OUTPUTS_TRANSCRIPT: &[u8] = b"Number of output ABARs";
const EQ_COMM_TRANSCRIPT: &[u8] = b"Equal committed values proof";

pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;

/// I generates the plonk proof for a multi-inputs/outputs anonymous transaction.
/// * `rng` - pseudo-random generator.
/// * `params` - System params
/// * `secret_inputs` - input to generate witness of the constraint system
pub(crate) fn prove_xfr<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &UserParams,
    secret_inputs: AMultiXfrWitness,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
    transcript.append_u64(
        N_INPUTS_TRANSCRIPT,
        secret_inputs.payers_secrets.len() as u64,
    );
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        secret_inputs.payees_secrets.len() as u64,
    );

    println!(" Before CS {:#?}", SystemTime::now());
    let (mut cs, _) = build_multi_xfr_cs(secret_inputs);
    let witness = cs.get_and_clear_witness();
    println!(" After CS {:#?}", SystemTime::now());
    prover(
        rng,
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(ZeiError::AXfrProofError))
}

/// I verify the plonk proof for a multi-input/output anonymous transaction.
/// * `params` - System parameters including KZG params and the constraint system
/// * `pub_inputs` - the public inputs of the transaction.
/// * `proof` - the proof
pub(crate) fn verify_xfr(
    params: &NodeParams,
    pub_inputs: &AMultiXfrPubInputs,
    proof: &AXfrPlonkPf,
) -> Result<()> {
    let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
    transcript.append_u64(N_INPUTS_TRANSCRIPT, pub_inputs.payers_inputs.len() as u64);
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        pub_inputs.payees_commitments.len() as u64,
    );
    let online_inputs = pub_inputs.to_vec();
    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(ZeiError::ZKProofVerificationError))
}

/// I generates the plonk proof for equality of values in a Pedersen commitment and a Rescue commitment.
/// * `rng` - pseudo-random generator.
/// * `params` - System params
/// * `amount` - transaction amount
/// * `asset_type` - asset type
/// * `blind_pc` - blinding factor for the Pedersen commitment
/// * `blind_hash` - blinding factor for the Rescue commitment
/// * `pc_gens` - the Pedersen commitment instance
/// * Return the plonk proof if the witness is valid, return an error otherwise.
pub(crate) fn prove_eq_committed_vals<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &UserParams,
    amount: BLSScalar,
    asset_type: BLSScalar,
    blind_pc: BLSScalar,
    blind_hash: BLSScalar,
    pc_gens: &PedersenGens<JubjubPoint>,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(EQ_COMM_TRANSCRIPT);
    let (mut cs, _) =
        build_eq_committed_vals_cs(amount, asset_type, blind_pc, blind_hash, pc_gens);
    let witness = cs.get_and_clear_witness();

    prover(
        rng,
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(ZeiError::AXfrProofError))
}

/// I verify the plonk proof for equality of values in a Pedersen commitment and a Rescue commitment.
/// * `params` - System parameters including KZG params and the constraint system
/// * `hash_comm` - the Rescue commitment
/// * `ped_comm` - the Pedersen commitment
/// * `proof` - the proof
/// * Returns Ok() if the verification succeeds, returns an error otherwise.
pub(crate) fn verify_eq_committed_vals(
    params: &NodeParams,
    hash_comm: BLSScalar,
    ped_comm: &JubjubPoint,
    proof: &AXfrPlonkPf,
) -> Result<()> {
    let mut transcript = Transcript::new(EQ_COMM_TRANSCRIPT);
    let online_inputs = vec![hash_comm, ped_comm.get_x(), ped_comm.get_y()];
    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(ZeiError::ZKProofVerificationError))
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::circuits::tests::new_multi_xfr_witness_for_test;
    use crate::anon_xfr::circuits::AMultiXfrPubInputs;
    use crate::anon_xfr::proofs::{
        prove_eq_committed_vals, prove_xfr, verify_eq_committed_vals, verify_xfr,
    };
    use crate::setup::{NodeParams, UserParams, DEFAULT_BP_NUM_GENS};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{Group, GroupArithmetic, One, Scalar, Zero};
    use algebra::jubjub::{JubjubPoint, JubjubScalar};
    use crypto::basics::commitments::pedersen::PedersenGens;
    use crypto::basics::commitments::rescue::HashCommitment;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_single_asset() {
        // single asset type
        let zero = BLSScalar::zero();
        // (n, m) = (3, 6)
        let inputs = vec![
            (/*amount=*/ 30, /*asset_type=*/ zero),
            (20, zero),
            (10, zero),
        ];
        let outputs = vec![
            (5, zero),
            (15, zero),
            (22, zero),
            (11, zero),
            (0, zero),
            (7, zero),
        ];
        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_3out_single_asset() {
        let zero = BLSScalar::zero();
        // (n, m) = (3, 3)
        let inputs = vec![(30, zero), (20, zero), (0, zero)];
        let outputs = vec![(5, zero), (17, zero), (28, zero)];
        test_anon_xfr_proof(outputs, inputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_1in_2out_single_asset() {
        let zero = BLSScalar::zero();
        // (n, m) = (1, 2)
        let inputs = vec![(30, zero)];
        let outputs = vec![(13, zero), (17, zero)];
        test_anon_xfr_proof(inputs.to_vec(), outputs.to_vec());
    }

    #[test]
    fn test_anon_multi_xfr_proof_2in_1out_single_asset() {
        let zero = BLSScalar::zero();
        let inputs = vec![(30, zero)];
        let outputs = vec![(13, zero), (17, zero)];
        // (n, m) = (2, 1)
        test_anon_xfr_proof(outputs, inputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_1in_1out_single_asset() {
        let zero = BLSScalar::zero();
        // (n, m) = (1, 1)
        let inputs = vec![(10, zero)];
        let outputs = vec![(10, zero)];
        test_anon_xfr_proof(outputs, inputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_multi_asset() {
        let zero = BLSScalar::zero();
        // multiple asset types
        // (n, m) = (3, 6)
        let one = BLSScalar::one();
        let inputs = vec![
            (/*amount=*/ 50, /*asset_type=*/ zero),
            (60, one),
            (20, zero),
        ];
        let outputs = vec![
            (19, one),
            (15, zero),
            (1, one),
            (35, zero),
            (20, zero),
            (40, one),
        ];
        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_3out_multi_asset() {
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        // (n, m) = (3, 3)
        let inputs = vec![(23, zero), (20, one), (7, zero)];
        let outputs = vec![(5, one), (30, zero), (15, one)];
        test_anon_xfr_proof(outputs, inputs);
    }

    fn test_anon_xfr_proof(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar)>,
    ) {
        let n_payers = inputs.len();
        let n_payees = outputs.len();

        // build cs
        let secret_inputs =
            new_multi_xfr_witness_for_test(inputs.to_vec(), outputs.to_vec(), [0u8; 32]);
        let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);
        let params = UserParams::from_file_if_exists(
            n_payers,
            n_payees,
            Some(1),
            DEFAULT_BP_NUM_GENS,
            None,
        )
        .unwrap();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let proof = prove_xfr(&mut prng, &params, secret_inputs).unwrap();

        // A bad proof should fail the verification
        let bad_secret_inputs =
            new_multi_xfr_witness_for_test(inputs, outputs, [1u8; 32]);
        let bad_proof = prove_xfr(&mut prng, &params, bad_secret_inputs).unwrap();

        // verify good witness
        let node_params = NodeParams::from(params);
        assert!(verify_xfr(&node_params, &pub_inputs, &proof).is_ok());

        // verify bad witness
        assert!(verify_xfr(&node_params, &pub_inputs, &bad_proof).is_err());
    }

    #[test]
    fn test_eq_committed_vals_proof() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let params = UserParams::eq_committed_vals_params();
        let (proof, hash_comm, ped_comm) = {
            // prover scope
            // compute Rescue commitment
            let comm = HashCommitment::new();
            let amount = BLSScalar::from_u32(71);
            let asset_type = BLSScalar::from_u32(52);
            let blind_hash = BLSScalar::random(&mut prng);
            let hash_comm = comm.commit(&blind_hash, &[amount, asset_type]).unwrap(); // safe unwrap

            // compute Pedersen commitment
            let pc_gens_jubjub = PedersenGens::<JubjubPoint>::new(2);
            let amount_jj = JubjubScalar::from_u32(71);
            let at_jj = JubjubScalar::from_u32(52);
            let blind_pc = JubjubScalar::random(&mut prng);
            let ped_comm = pc_gens_jubjub
                .commit(&[amount_jj, at_jj], &blind_pc)
                .unwrap(); // safe unwrap

            // compute the proof
            let proof = prove_eq_committed_vals(
                &mut prng,
                &params,
                amount,
                asset_type,
                BLSScalar::from(&blind_pc),
                blind_hash,
                &pc_gens_jubjub,
            )
            .unwrap(); // safe unwrap
            (proof, hash_comm, ped_comm)
        };
        {
            // verifier scope
            let node_params = NodeParams::from(params);
            assert!(verify_eq_committed_vals(
                &node_params,
                hash_comm,
                &ped_comm,
                &proof
            )
            .is_ok());
            let bad_hash_comm = BLSScalar::one();
            assert!(verify_eq_committed_vals(
                &node_params,
                bad_hash_comm,
                &ped_comm,
                &proof
            )
            .is_err());
            let bad_ped_comm = ped_comm.add(&JubjubPoint::get_base());
            assert!(verify_eq_committed_vals(
                &node_params,
                hash_comm,
                &bad_ped_comm,
                &proof
            )
            .is_err());
        }
    }
}
