use crate::anon_xfr::keys::AXfrPubKey;
use crate::anon_xfr::proofs::{
    prove_eq_committed_vals, verify_eq_committed_vals, AXfrPlonkPf,
};
use crate::anon_xfr::structs::{
    AnonBlindAssetRecord, OpenAnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder,
};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::sig::{XfrKeyPair, XfrPublicKey, XfrSignature};
use crate::xfr::structs::{
    BlindAssetRecord, OpenAssetRecord, OwnerMemo, XfrAmount, XfrAssetType,
};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{GroupArithmetic, Scalar, ScalarArithmetic, Zero};
use algebra::jubjub::JubjubScalar;
use algebra::ristretto::{RistrettoPoint, RistrettoScalar};
use crypto::basics::commitments::pedersen::PedersenGens;
use crypto::basics::hash::rescue::RescueInstance;
use crypto::basics::hybrid_encryption::XPublicKey;
use crypto::pc_eq_rescue_split_verifier_zk_part::{
    prove_pc_eq_rescue_split_verifier_zk_part,
    verify_pc_eq_rescue_split_verifier_zk_part, ZKPartProof,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use utils::errors::ZeiError;

pub const TWO_POW_32: u64 = 1 << 32;

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ConvertBarAbarProof {
    commitment_eq_proof: ZKPartProof,
    pc_rescue_commitments_eq_proof: AXfrPlonkPf,
}

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct BarToAbarBody {
    pub input: BlindAssetRecord,
    pub output: AnonBlindAssetRecord,
    pub proof: ConvertBarAbarProof,
    pub memo: OwnerMemo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbarToBarBody {
    pub input: AnonBlindAssetRecord,
    pub output: BlindAssetRecord,
    pub proof: ConvertBarAbarProof,
}

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct BarToAbarNote {
    pub body: BarToAbarBody,
    pub signature: XfrSignature,
}

/// Generate Bar To Abar conversion note body
/// Returns note Body and ABAR opening keys
pub fn gen_bar_to_abar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    record: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
    fee: u64,
) -> Result<(BarToAbarBody, JubjubScalar)> {
    let (open_abar, proof) =
        bar_to_abar(prng, params, record, abar_pubkey, enc_key, fee).c(d!())?;
    let body = BarToAbarBody {
        input: record.blind_asset_record.clone(),
        output: AnonBlindAssetRecord::from_oabar(&open_abar),
        proof,
        memo: open_abar.owner_memo.unwrap(),
    };
    Ok((body, open_abar.key_rand_factor))
}

/// Generate BlindAssetRecord To AnonymousBlindAssetRecord conversion note: body + spending input signature
/// Returns conversion note and output AnonymousBlindAssetRecord opening keys
pub fn gen_bar_to_abar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    record: &OpenAssetRecord,
    bar_keypair: &XfrKeyPair,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
    fee: u64,
) -> Result<BarToAbarNote> {
    let (body, _r) =
        gen_bar_to_abar_body(prng, params, record, &abar_pubkey, enc_key, fee)
            .c(d!())?;
    let msg = bincode::serialize(&body)
        .map_err(|_| ZeiError::SerializationError)
        .c(d!())?;
    let signature = bar_keypair.sign(&msg);
    let note = BarToAbarNote { body, signature };
    Ok(note)
}

/// Verifies BlindAssetRecord To AnonymousBlindAssetRecord conversion body
/// Warning: This function doesn't check that input owner has signed the body
pub fn verify_bar_to_abar_body(
    params: &NodeParams,
    body: &BarToAbarBody,
    fee: u64,
) -> Result<()> {
    verify_bar_to_abar(params, &body.input, &body.output, &body.proof, fee).c(d!())
}

/// Verifies BlindAssetRecord To AnonymousBlindAssetRecord conversion note by verifying proof of conversion
/// and signature by input owner key
pub fn verify_bar_to_abar_note(
    params: &NodeParams,
    note: &BarToAbarNote,
    bar_pub_key: &XfrPublicKey,
    fee: u64,
) -> Result<()> {
    verify_bar_to_abar_body(params, &note.body, fee).c(d!())?;
    let msg = bincode::serialize(&note.body).c(d!(ZeiError::SerializationError))?;
    bar_pub_key.verify(&msg, &note.signature).c(d!())
}

pub(crate) fn bar_to_abar<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    obar: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
    fee: u64,
) -> Result<(OpenAnonBlindAssetRecord, ConvertBarAbarProof)> {
    let obar_amount = obar.amount - fee;

    let pc_gens =
        PedersenGens::<RistrettoPoint>::from(bulletproofs::PedersenGens::default());

    // 1. Construct ABAR.
    let oabar = OpenAnonBlindAssetRecordBuilder::new()
        .amount(obar_amount)
        .asset_type(obar.asset_type)
        .pub_key(*abar_pubkey)
        .finalize(prng, &enc_key)
        .c(d!())?
        .build()
        .c(d!())?;

    // 2. Reconstruct the points.
    let x = RistrettoScalar::from_u64(obar_amount);
    let y: RistrettoScalar = obar.asset_type.as_scalar();
    let gamma = obar.amount_blinds.0.add(
        &obar
            .amount_blinds
            .1
            .mul(&RistrettoScalar::from_u64(TWO_POW_32)),
    );
    let delta = obar.type_blind;
    let point_p = pc_gens.commit(&[x], &gamma).c(d!())?;
    let point_q = pc_gens.commit(&[y], &delta).c(d!())?;

    let z_randomizer = oabar.blind;
    let z_instance = RescueInstance::<BLSScalar>::new();

    let x_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&x.to_bytes()));
    let y_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&y.to_bytes()));

    let z = z_instance.rescue_hash(&[
        z_randomizer,
        x_in_bls12_381,
        y_in_bls12_381,
        BLSScalar::zero(),
    ])[0];

    // 2. compute the ZK part of the proof
    let (commitment_eq_proof, non_zk_state, beta) =
        prove_pc_eq_rescue_split_verifier_zk_part(
            prng, &x, &gamma, &y, &delta, &pc_gens, &point_p, &point_q, &z,
        )
        .c(d!())?;

    // 3. prove abar correctness
    let pc_rescue_commitments_eq_proof = prove_eq_committed_vals(
        prng,
        params,
        x_in_bls12_381,
        y_in_bls12_381,
        oabar.blind,
        &commitment_eq_proof,
        &non_zk_state,
        &beta,
    )
    .c(d!())?;

    Ok((
        oabar,
        ConvertBarAbarProof {
            commitment_eq_proof,
            pc_rescue_commitments_eq_proof,
        },
    ))
}

pub(crate) fn verify_bar_to_abar(
    params: &NodeParams,
    bar: &BlindAssetRecord,
    abar: &AnonBlindAssetRecord,
    proof: &ConvertBarAbarProof,
    fee: u64,
) -> Result<()> {
    let pc_gens =
        PedersenGens::<RistrettoPoint>::from(bulletproofs::PedersenGens::default());

    // 1. get commitments
    // 1.1 reconstruct total amount commitment from bar object
    let (com_low, com_high) = match bar.amount {
        XfrAmount::Confidential((low, high)) => (
            low.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
            high.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
        ),
        XfrAmount::NonConfidential(amount) => {
            // fake commitment
            let (l, h) = utils::u64_to_u32_pair(amount - fee);
            (
                pc_gens
                    .commit(&[RistrettoScalar::from_u32(l)], &RistrettoScalar::zero())
                    .c(d!())?,
                pc_gens
                    .commit(&[RistrettoScalar::from_u32(h)], &RistrettoScalar::zero())
                    .c(d!())?,
            )
        }
    };

    // 1.2 get asset type commitment
    let com_amount = com_low.add(&com_high.mul(&RistrettoScalar::from_u64(TWO_POW_32)));
    let com_asset_type = match bar.asset_type {
        XfrAssetType::Confidential(a) => a
            .decompress()
            .ok_or(ZeiError::DecompressElementError)
            .c(d!())?,
        XfrAssetType::NonConfidential(a) => {
            // fake commitment
            pc_gens
                .commit(&[a.as_scalar()], &RistrettoScalar::zero())
                .c(d!())?
        }
    };

    // 2. verify equality of commited values
    let beta = verify_pc_eq_rescue_split_verifier_zk_part(
        &pc_gens,
        &com_amount,
        &com_asset_type,
        &abar.amount_type_commitment,
        &proof.commitment_eq_proof,
    )
    .c(d!())?;

    // 3. verify PLONK proof
    verify_eq_committed_vals(
        params,
        abar.amount_type_commitment,
        &proof.commitment_eq_proof,
        &proof.pc_rescue_commitments_eq_proof,
        &beta,
    )
    .c(d!())
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::bar_to_from_abar::{
        gen_bar_to_abar_note, verify_bar_to_abar_note,
    };
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::{
        AnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder,
    };
    use crate::setup::{NodeParams, UserParams};
    use crate::xfr::asset_record::{
        build_blind_asset_record, open_blind_asset_record, AssetRecordType,
    };
    use crate::xfr::sig::{XfrKeyPair, XfrPublicKey};
    use crate::xfr::structs::{
        AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo,
    };
    use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
    use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    // helper function
    fn build_bar(
        pubkey: &XfrPublicKey,
        prng: &mut ChaChaRng,
        pc_gens: &RistrettoPedersenGens,
        amt: u64,
        asset_type: AssetType,
        ar_type: AssetRecordType,
    ) -> (BlindAssetRecord, Option<OwnerMemo>) {
        let ar = AssetRecordTemplate::with_no_asset_tracing(
            amt, asset_type, ar_type, *pubkey,
        );
        let (bar, _, memo) = build_blind_asset_record(prng, &pc_gens, &ar, vec![]);
        (bar, memo)
    }

    #[test]
    fn test_bar_to_abar() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = RistrettoPedersenGens::default();
        let bar_keypair = XfrKeyPair::generate(&mut prng);
        let abar_keypair = AXfrKeyPair::generate(&mut prng);
        let dec_key = XSecretKey::new(&mut prng);
        let enc_key = XPublicKey::from(&dec_key);
        // proving
        let params = UserParams::eq_committed_vals_params();
        // confidential case
        let (bar_conf, memo) = build_bar(
            &bar_keypair.pub_key,
            &mut prng,
            &pc_gens,
            10u64,
            AssetType::from_identical_byte(1u8),
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar_conf, &memo, &bar_keypair).unwrap();
        let (oabar_conf, proof_conf) = super::bar_to_abar(
            &mut prng,
            &params,
            &obar,
            &abar_keypair.pub_key(),
            &enc_key,
            0,
        )
        .unwrap();
        let abar_conf = AnonBlindAssetRecord::from_oabar(&oabar_conf);
        // non confidential case
        let (bar_non_conf, memo) = build_bar(
            &bar_keypair.pub_key,
            &mut prng,
            &pc_gens,
            10u64,
            AssetType::from_identical_byte(1u8),
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar_non_conf, &memo, &bar_keypair).unwrap();
        let (oabar_non_conf, proof_non_conf) = super::bar_to_abar(
            &mut prng,
            &params,
            &obar,
            &abar_keypair.pub_key(),
            &enc_key,
            0,
        )
        .unwrap();
        let abar_non_conf = AnonBlindAssetRecord::from_oabar(&oabar_non_conf);

        // verifications
        let node_params = NodeParams::from(params);
        // confidential case
        assert!(super::verify_bar_to_abar(
            &node_params,
            &bar_conf,
            &abar_conf,
            &proof_conf,
            0
        )
        .is_ok());
        // non confidential case
        assert!(super::verify_bar_to_abar(
            &node_params,
            &bar_non_conf,
            &abar_non_conf,
            &proof_non_conf,
            0
        )
        .is_ok());
    }

    #[test]
    fn test_bar_to_abar_xfr_note() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let bar_keypair = XfrKeyPair::generate(&mut prng);
        let abar_keypair = AXfrKeyPair::generate(&mut prng);
        let dec_key = XSecretKey::new(&mut prng);
        let enc_key = XPublicKey::from(&dec_key);
        let pc_gens = RistrettoPedersenGens::default();
        let amount = 10;
        let asset_type = AssetType::from_identical_byte(1u8);
        let (bar, memo) = build_bar(
            &bar_keypair.pub_key,
            &mut prng,
            &pc_gens,
            amount,
            asset_type,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar, &memo, &bar_keypair).unwrap();
        let params = UserParams::eq_committed_vals_params();
        let note = gen_bar_to_abar_note(
            &mut prng,
            &params,
            &obar,
            &bar_keypair,
            &abar_keypair.pub_key(),
            &enc_key,
            0,
        )
        .unwrap();

        // 1. check that abar_keypair opens the note
        let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
            &note.body.output,
            note.body.memo.clone(),
            &abar_keypair,
            &dec_key,
        )
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(oabar.amount, amount);
        assert_eq!(oabar.asset_type, asset_type);
        assert_eq!(
            abar_keypair.pub_key().randomize(&oabar.key_rand_factor),
            note.body.output.public_key
        );

        let node_params = NodeParams::from(params);
        assert!(
            verify_bar_to_abar_note(&node_params, &note, &bar_keypair.pub_key, 0)
                .is_ok()
        );

        let mut note = note;
        let message = b"anymesage";
        let bad_sig = bar_keypair.sign(message);
        note.signature = bad_sig;
        assert!(
            verify_bar_to_abar_note(&node_params, &note, &bar_keypair.pub_key, 0)
                .is_err()
        )
    }

    #[test]
    fn test_bar_to_abar_with_fee() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let params = UserParams::eq_committed_vals_params();
        let pc_gens = RistrettoPedersenGens::default();

        let key = XfrKeyPair::generate(&mut prng);
        let (bar, memo) = build_bar(
            &key.pub_key,
            &mut prng,
            &pc_gens,
            10_000_000u64,
            AssetType::from_identical_byte(0),
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
        let oar = open_blind_asset_record(&bar, &memo, &key).unwrap();

        let axfr_key_pair = AXfrKeyPair::generate(&mut prng);
        let dec_key = XSecretKey::new(&mut prng);
        let note = gen_bar_to_abar_note(
            &mut prng,
            &params,
            &oar,
            &key,
            &axfr_key_pair.pub_key(),
            &XPublicKey::from(&dec_key),
            1000,
        )
        .unwrap();

        verify_bar_to_abar_note(&NodeParams::from(params), &note, &key.pub_key, 1000)
            .unwrap();

        let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
            &note.body.output,
            note.body.memo,
            &axfr_key_pair,
            &dec_key,
        )
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(oabar.amount, oar.amount - 1_000);
    }
}
