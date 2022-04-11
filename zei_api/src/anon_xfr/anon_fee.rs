use crate::anon_xfr::circuits::{
    add_payees_secrets, add_payers_secrets, commit, compute_merkle_root, nullify,
    AMultiXfrPubInputs, AccElemVars, NullifierInputVars, PayeeSecret, PayerSecret,
    TurboPlonkCS, AMOUNT_LEN, SK_LEN,
};
use crate::anon_xfr::config::FEE_TYPE;
use crate::anon_xfr::proofs::AXfrPlonkPf;
use crate::anon_xfr::structs::SnarkProof;
use crate::anon_xfr::{
    keys::{AXfrKeyPair, AXfrPubKey, AXfrSignature},
    nullifier,
    structs::{AXfrProof, AnonBlindAssetRecord, Nullifier, OpenAnonBlindAssetRecord},
};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::structs::OwnerMemo;
use algebra::bls12_381::BLSScalar;
use algebra::groups::{Group, One, Scalar, ScalarArithmetic, Zero};
use algebra::jubjub::{JubjubPoint, JubjubScalar};
use merlin::Transcript;
use poly_iops::plonk::{
    constraint_system::{TurboConstraintSystem, VarIndex},
    prover::prover,
    verifier::verifier,
};
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use std::borrow::Borrow;
use utils::errors::ZeiError;

const ANON_FEE_TRANSCRIPT: &[u8] = b"Anon Fee";
pub const ANON_FEE_MIN: u64 = 10_000;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeNote {
    pub body: AnonFeeBody,
    pub signature: AXfrSignature,
}

impl AnonFeeNote {
    pub fn generate_note_from_body(
        body: AnonFeeBody,
        keypair: AXfrKeyPair,
    ) -> Result<AnonFeeNote> {
        let msg: Vec<u8> = bincode::serialize(&body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        Ok(AnonFeeNote {
            body,
            signature: keypair.sign(msg.as_slice()),
        })
    }

    pub fn verify_signatures(&self) -> Result<()> {
        let msg: Vec<u8> = bincode::serialize(&self.body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        self.body
            .input
            .1
            .verify(msg.as_slice(), &self.signature)
            .c(d!("AXfrNote signature verification failed"))?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeBody {
    pub input: (Nullifier, AXfrPubKey),
    pub output: AnonBlindAssetRecord,
    pub proof: AXfrProof,
    pub owner_memo: OwnerMemo,
}

/// Build an anonymous fee structure AnonFeeBody. It also returns randomized signature keys to sign the transfer,
/// * `rng` - pseudo-random generator.
/// * `params` - User parameters
/// * `input` - Open source asset records
/// * `output` - Description of output asset records.
#[allow(unused_variables)]
pub fn gen_anon_fee_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    input: &OpenAnonBlindAssetRecord,
    output: &OpenAnonBlindAssetRecord,
    input_keypair: &AXfrKeyPair,
) -> Result<(AnonFeeBody, AXfrKeyPair)> {
    if input.pub_key.ne(input_keypair.pub_key().borrow()) {
        return Err(eg!(ZeiError::ParameterError));
    }
    check_fee_asset_amount(input, output).c(d!())?;

    let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
    let rand_input_keypair = input_keypair.randomize(&input.key_rand_factor);
    let diversifier = JubjubScalar::random(prng);
    let nullifier_and_signing_key = (
        nullifier(
            &rand_input_keypair,
            input.amount,
            &input.asset_type,
            mt_leaf_info.uid,
        ),
        rand_input_keypair.pub_key().randomize(&diversifier),
    );

    let payers_secret = PayerSecret {
        sec_key: rand_input_keypair.get_secret_scalar(),
        diversifier,
        uid: mt_leaf_info.uid,
        amount: input.amount,
        asset_type: input.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: input.blind,
    };
    let payees_secrets = PayeeSecret {
        amount: output.amount,
        blind: output.blind,
        asset_type: output.asset_type.as_scalar(),
    };

    let proof = prove_anon_fee(prng, params, payers_secret, payees_secrets).c(d!())?;

    Ok((
        AnonFeeBody {
            input: nullifier_and_signing_key,
            output: AnonBlindAssetRecord::from_oabar(output),
            proof: AXfrProof {
                snark_proof: proof,
                merkle_root: mt_leaf_info.root,
                merkle_root_version: mt_leaf_info.root_version,
            },
            owner_memo: output
                .owner_memo
                .clone()
                .c(d!(ZeiError::ParameterError))
                .c(d!())?,
        },
        rand_input_keypair.randomize(&diversifier),
    ))
}

fn check_fee_asset_amount(
    input: &OpenAnonBlindAssetRecord,
    output: &OpenAnonBlindAssetRecord,
) -> Result<()> {
    if input.asset_type != FEE_TYPE {
        return Err(eg!("Incorrect input type for fee"));
    }
    if output.asset_type != FEE_TYPE {
        return Err(eg!("Incorrect output type for fee"));
    }
    if input.amount != output.amount + ANON_FEE_MIN {
        return Err(eg!("Incorrect anon fee amount"));
    }

    Ok(())
}

/// Verifies an anonymous transfer structure AXfrBody.
/// * `params` - Verifier parameters
/// * `body` - Transfer structure to verify
/// * `accumulator` - candidate state of the accumulator. It must match body.proof.merkle_root, otherwise it returns ZeiError::AXfrVerification Error.
#[allow(unused_variables)]
pub fn verify_anon_fee_body(
    params: &NodeParams,
    body: &AnonFeeBody,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != body.proof.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let pub_inputs = AMultiXfrPubInputs {
        payers_inputs: vec![body.input.clone()],
        payees_commitments: vec![body.output.amount_type_commitment],
        merkle_root: *merkle_root,
    };

    verify_anon_fee(params, &pub_inputs, &body.proof.snark_proof)
        .c(d!(ZeiError::AXfrVerificationError))
}

/// Proof for an AXfrBody correctness
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeProof {
    pub snark_proof: SnarkProof,
    pub merkle_root: BLSScalar,
    pub merkle_root_version: usize,
}

fn prove_anon_fee<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &UserParams,
    input_secret: PayerSecret,
    remainder_secret: PayeeSecret,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ANON_FEE_TRANSCRIPT);

    let fee_type = FEE_TYPE.as_scalar();

    let (mut cs, _) = build_anon_fee_cs(input_secret, remainder_secret, fee_type);
    let witness = cs.get_and_clear_witness();

    prover(
        rng,
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(ZeiError::AnonFeeProofError))
}

/// Returns the constraint system (and associated number of constraints) for a anon fee operation.
/// A prover can provide honest `secret_inputs` and obtain the cs witness by calling `cs.get_and_clear_witness()`.
/// One provide an empty secret_inputs to get the constraint system `cs` for verification only.
/// This one also takes fee parameters as input.
pub(crate) fn build_anon_fee_cs(
    payer_secret: PayerSecret,
    payee_secret: PayeeSecret,
    fee_type: BLSScalar,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboConstraintSystem::new();

    let payers_secrets = add_payers_secrets(&mut cs, vec![payer_secret].as_slice());
    let payees_secrets = add_payees_secrets(&mut cs, vec![payee_secret].as_slice());

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from_u64(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;
    for payer in &payers_secrets {
        // prove knowledge of payer's secret key: pk = base^{sk}
        let (pk_var, pk_point) = cs.scalar_mul(base, payer.sec_key, SK_LEN);
        let pk_x = pk_var.get_x();
        let pk_y = pk_var.get_y();

        // prove knowledge of diversifier: pk_sign = pk^{diversifier}
        let (pk_sign_var, _) =
            cs.var_base_scalar_mul(pk_var, pk_point, payer.diversifier, SK_LEN);

        // commitments
        let com_abar_in_var =
            commit(&mut cs, payer.blind, payer.amount, payer.asset_type);

        // prove pre-image of the nullifier
        // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
        let uid_amount = cs.linear_combine(
            &[payer.uid, payer.amount, zero_var, zero_var],
            pow_2_64,
            one,
            zero,
            zero,
        );
        let nullifier_input_vars = NullifierInputVars {
            uid_amount,
            asset_type: payer.asset_type,
            pub_key_x: pk_x,
            pub_key_y: pk_y,
        };
        let nullifier_var = nullify(&mut cs, payer.sec_key, nullifier_input_vars);

        // Merkle path authentication
        let acc_elem = AccElemVars {
            uid: payer.uid,
            commitment: com_abar_in_var,
            pub_key_x: pk_x,
            pub_key_y: pk_y,
        };
        let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payer.path);

        if let Some(root) = root_var {
            cs.equal(root, tmp_root_var);
        } else {
            root_var = Some(tmp_root_var);
        }

        // prepare public inputs variables
        cs.prepare_io_variable(nullifier_var);
        cs.prepare_io_point_variable(pk_sign_var);
    }
    // prepare the publc input for merkle_root
    cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

    for payee in &payees_secrets {
        // commitment
        let com_abar_out_var =
            commit(&mut cs, payee.blind, payee.amount, payee.asset_type);

        // Range check `amount`
        // Note we don't need to range-check payers' `amount`, because those amounts are bound
        // to payers' accumulated abars, whose underlying amounts have already been range-checked
        // in the transactions that created the payers' abars.
        cs.range_check(payee.amount, AMOUNT_LEN);

        // prepare the public input for the output commitment
        cs.prepare_io_variable(com_abar_out_var);
    }

    // Initialize a constant value `fee_type_val`
    let fee_type_val = cs.new_variable(fee_type);
    cs.equal(fee_type_val, payers_secrets[0].asset_type);
    cs.equal(payers_secrets[0].asset_type, payees_secrets[0].asset_type);

    let fee_var = cs.new_variable(BLSScalar::from_u64(ANON_FEE_MIN));
    let output_amount_var = cs.add(payees_secrets[0].amount, fee_var);
    cs.equal(payers_secrets[0].amount, output_amount_var);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size.clone();
    (cs, n_constraints)
}

/// I verify the plonk proof for a multi-input/output anonymous transaction.
/// * `params` - System parameters including KZG params and the constraint system
/// * `pub_inputs` - the public inputs of the transaction.
/// * `proof` - the proof
pub(crate) fn verify_anon_fee(
    params: &NodeParams,
    pub_inputs: &AMultiXfrPubInputs,
    proof: &AXfrPlonkPf,
) -> Result<()> {
    let mut transcript = Transcript::new(ANON_FEE_TRANSCRIPT);
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

#[cfg(test)]
mod tests {
    use crate::anon_xfr::anon_fee::{
        gen_anon_fee_body, verify_anon_fee_body, AnonFeeNote, ANON_FEE_MIN,
    };
    use crate::anon_xfr::config::FEE_TYPE;
    use crate::anon_xfr::hash_abar;
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::{
        AnonBlindAssetRecord, OpenAnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder,
    };
    use crate::anon_xfr::tests::create_mt_leaf_info;
    use crate::setup::{NodeParams, UserParams};
    use crate::xfr::structs::AssetType;
    use accumulators::merkle_tree::{PersistentMerkleTree, TREE_DEPTH};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::Scalar;
    use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};
    use std::sync::Arc;
    use std::thread;
    use storage::db::TempRocksDB;
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;

    #[test]
    fn test_anon_fee_happy_path() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let user_params = UserParams::anon_fee_params(TREE_DEPTH).unwrap();

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + ANON_FEE_MIN;

        // simulate input abar
        let (mut oabar, keypair_in, _dec_key_in, _) =
            gen_oabar_and_keys(&mut prng, input_amount, FEE_TYPE);
        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());
        let rand_keypair_in = keypair_in.randomize(&oabar.get_key_rand_factor());
        assert_eq!(rand_keypair_in.pub_key(), abar.public_key);
        let _owner_memo = oabar.get_owner_memo().unwrap();

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        let store = PrefixedStore::new("mystore", &mut state);
        let mut pmt = PersistentMerkleTree::new(store).unwrap();

        let id = pmt
            .add_commitment_hash(hash_abar(pmt.entry_count(), &abar))
            .unwrap();
        assert!(pmt.commit().is_ok());
        let proof = pmt.generate_proof(id).unwrap();
        let mt_leaf_info = create_mt_leaf_info(proof);
        oabar.update_mt_leaf_info(mt_leaf_info);

        // output keys
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
            .amount(output_amount)
            .asset_type(FEE_TYPE)
            .pub_key(keypair_out.pub_key())
            .finalize(&mut prng, &enc_key_out)
            .unwrap()
            .build()
            .unwrap();

        let (body, key_pairs) =
            gen_anon_fee_body(&mut prng, &user_params, &oabar, &oabar_out, &keypair_in)
                .unwrap();

        {
            // verifier scope
            let verifier_params = NodeParams::anon_fee_params().unwrap();
            assert!(verify_anon_fee_body(
                &verifier_params,
                &body,
                &pmt.get_root().unwrap()
            )
            .is_ok());
            assert!(verify_anon_fee_body(
                &verifier_params,
                &body,
                &BLSScalar::from_u64(123u64)
            )
            .is_err());

            let note = AnonFeeNote::generate_note_from_body(body, key_pairs).unwrap();
            assert!(note.verify_signatures().is_ok());
        }
        {
            let user_params = UserParams::anon_fee_params(TREE_DEPTH).unwrap();
            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount + 1)
                .asset_type(FEE_TYPE)
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            assert!(gen_anon_fee_body(
                &mut prng,
                &user_params,
                &oabar,
                &oabar_out,
                &keypair_in,
            )
            .is_err());
        }
        {
            let user_params = UserParams::anon_fee_params(TREE_DEPTH).unwrap();
            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount)
                .asset_type(AssetType::from_identical_byte(4u8))
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            assert!(gen_anon_fee_body(
                &mut prng,
                &user_params,
                &oabar,
                &oabar_out,
                &keypair_in,
            )
            .is_err());
        }
    }

    #[test]
    fn test_anon_fee_bad_input() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let user_params = UserParams::anon_fee_params(TREE_DEPTH).unwrap();

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + ANON_FEE_MIN;

        // simulate input abar
        let (mut oabar, keypair_in, _dec_key_in, _) = gen_oabar_and_keys(
            &mut prng,
            input_amount,
            AssetType::from_identical_byte(3u8),
        );
        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());
        let rand_keypair_in = keypair_in.randomize(&oabar.get_key_rand_factor());
        assert_eq!(rand_keypair_in.pub_key(), abar.public_key);
        let _owner_memo = oabar.get_owner_memo().unwrap();

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        let store = PrefixedStore::new("mystore", &mut state);
        let mut pmt = PersistentMerkleTree::new(store).unwrap();

        let id = pmt
            .add_commitment_hash(hash_abar(pmt.entry_count(), &abar))
            .unwrap();
        assert!(pmt.commit().is_ok());
        let proof = pmt.generate_proof(id).unwrap();
        let mt_leaf_info = create_mt_leaf_info(proof);
        oabar.update_mt_leaf_info(mt_leaf_info);

        // output keys
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
            .amount(output_amount)
            .asset_type(FEE_TYPE)
            .pub_key(keypair_out.pub_key())
            .finalize(&mut prng, &enc_key_out)
            .unwrap()
            .build()
            .unwrap();

        assert!(gen_anon_fee_body(
            &mut prng,
            &user_params,
            &oabar,
            &oabar_out,
            &keypair_in,
        )
        .is_err());
    }

    fn gen_oabar_and_keys<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        asset_type: AssetType,
    ) -> (
        OpenAnonBlindAssetRecord,
        AXfrKeyPair,
        XSecretKey,
        XPublicKey,
    ) {
        let keypair = AXfrKeyPair::generate(prng);
        let dec_key = XSecretKey::new(prng);
        let enc_key = XPublicKey::from(&dec_key);
        let oabar = OpenAnonBlindAssetRecordBuilder::new()
            .amount(amount)
            .asset_type(asset_type)
            .pub_key(keypair.pub_key())
            .finalize(prng, &enc_key)
            .unwrap()
            .build()
            .unwrap();
        (oabar, keypair, dec_key, enc_key)
    }
}
