use crate::basics::elgamal::{
    elgamal_decrypt_elem, elgamal_encrypt, elgamal_key_gen, ElGamalCiphertext,
    ElGamalDecKey, ElGamalEncKey,
};
use crate::basics::signatures::pointcheval_sanders::{
    ps_gen_keys, ps_randomize_sig, ps_sign_scalar, PSPublicKey, PSSecretKey, PSSignature,
};
use algebra::groups::{Group, GroupArithmetic, Scalar, ScalarArithmetic};
use algebra::pairing::Pairing;
use ruc::*;
use utils::errors::ZeiError;

use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

/// The public key of the group manager contains a public signing key `ver_key`
/// and an Elgamal encryption public key `enc_key`.
pub struct GroupPublicKey<P: Pairing> {
    ver_key: PSPublicKey<P::G2>,
    enc_key: ElGamalEncKey<P::G1>,
}

/// The secret key of the group manager contains a private signing key `sig_key`
/// and a private Elgamal encryption key `dec_key`.
pub struct GroupSecretKey<P: Pairing> {
    sig_key: PSSecretKey<P::ScalarField>,
    dec_key: ElGamalDecKey<P::ScalarField>,
}

/// A group signature contains a Pointcheval-Sanders signature `cert`,
/// an Elgamal ciphertext `enc` containing the encryption of the identity of the signer
/// and a proof-of-knowledge `PoK` to prove that the identity of the signer corresponds
/// to the private key used to produce `cert`.
pub struct GroupSignature<P: Pairing> {
    cert: PSSignature<P::G1>,
    enc: ElGamalCiphertext<P::G1>,
    spok: PoK<P>,
}

/// I generate the private and public parameters for the Group manager.
/// * `prng` - source of randomness
/// * `returns` - a group public key and a group secret key
pub fn gpsig_setup<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
) -> (GroupPublicKey<P>, GroupSecretKey<P>) {
    let (ver_key, sig_key) = ps_gen_keys::<R, P>(prng);
    let (dec_key, enc_key) = elgamal_key_gen::<_, P::G1>(prng, &P::G1::get_base());
    (
        GroupPublicKey { ver_key, enc_key },
        GroupSecretKey { sig_key, dec_key },
    )
}

/// When a user joins the group, the Group Manager sends him a certificate
/// that will enable the user to prove he his part of the group when signing.
pub struct JoinCert<P: Pairing> {
    pub tag: P::ScalarField,
    pub sig: PSSignature<P::G1>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagKey<G1>(G1);

/// I produce a join certificate for a new user.
/// This algorithm is run by the Group Manager.
/// * `prng` - source of randomness
/// * `msk` - group secret key
/// * `return` join certificate for user and tag key for the manager
pub fn gpsig_join_cert<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    msk: &GroupSecretKey<P>,
) -> (JoinCert<P>, TagKey<P::G1>) {
    let tag = P::ScalarField::random(prng);
    let sig = ps_sign_scalar::<R, P>(prng, &msk.sig_key, &tag);
    let tag_key = TagKey(P::G1::get_base().mul(&tag));
    (JoinCert { tag, sig }, tag_key)
}

/// I produce a group signature.
/// This algorithm is run by a user.
/// * `prng` - source of randomness
/// * `gpk` - group public key
/// * `join_cert` - join certificate
/// * `msg` - message to be signed
pub fn gpsig_sign<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    gpk: &GroupPublicKey<P>,
    join_cert: &JoinCert<P>,
    msg: &[u8],
) -> GroupSignature<P> {
    let g1_base = P::G1::get_base();

    // 1. randomize signature
    let (_, rsig) = ps_randomize_sig::<R, P>(prng, &join_cert.sig);

    // 2. Encrypt tag
    let r = P::ScalarField::random(prng);
    let enc = elgamal_encrypt(&g1_base, &join_cert.tag, &r, &gpk.enc_key);

    // 3. Signature proof of knowledge of r and tag such that ps_verify(rsig, tag) = 1 and enc = ElGamal(tag, r)
    let spok = signature_proof_of_knowledge(prng, gpk, &join_cert.tag, &r, msg);

    GroupSignature {
        cert: rsig,
        enc,
        spok,
    }
}

/// Proof of knowledge containing the commitments and the responses.
pub(crate) struct PoK<P: Pairing> {
    commitments_g1: Vec<P::G1>,
    commitments_g2: Vec<P::G2>,
    responses: Vec<P::ScalarField>,
}

/// I compute a signature of knowledge
/// * `prng` - source of randomness
/// * `gpk`- group public key
/// * `tag` - identity of the user
/// * `r` - randomness of the ciphertext
/// * `msg` - message to be signed
fn signature_proof_of_knowledge<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    gpk: &GroupPublicKey<P>,
    tag: &P::ScalarField,
    r: &P::ScalarField,
    msg: &[u8],
) -> PoK<P> {
    let g1_base = P::G1::get_base();
    let g2_base = P::G2::get_base();

    // 1. Sample blindings
    let blind_tag = P::ScalarField::random(prng);
    let blind_r = P::ScalarField::random(prng);

    // 2. Compute proof commitments
    let com_yy_blind_tag = gpk.ver_key.yy.mul(&blind_tag); // commitment of tag under Y
    let com_g1_blind_tag = g1_base.mul(&blind_tag); // commitment of tag under g1
    let com_pk_blind_r = gpk.enc_key.0.mul(&blind_r); // commitment of r under PK
    let com_g1_blind_r = g1_base.mul(&blind_r); // commitment of r under g1
    let commitments_g1 = vec![com_g1_blind_tag, com_pk_blind_r, com_g1_blind_r];
    let commitments_g2 = vec![com_yy_blind_tag];

    // 3. Compute the challenge
    let challenge = compute_signature_pok_challenge(
        &g1_base,
        &g2_base,
        gpk,
        commitments_g1.as_slice(),
        commitments_g2.as_slice(),
        msg,
    );

    // 4. compute the response
    let tag_response = tag.mul(&challenge).add(&blind_tag);
    let r_response = r.mul(&challenge).add(&blind_r);

    PoK {
        commitments_g1,
        commitments_g2,
        responses: vec![tag_response, r_response],
    }
}

/// I compute the challenge based on the transcript
/// * `g1` - base of group G1
/// * `g2` - base of group G2
/// * `gpk` - group public key
/// * `commitments_g1` - commitments from group G1
/// * `commitments_g2` - commmitments from group G2
/// * `msg` - message
fn compute_signature_pok_challenge<P: Pairing>(
    g1: &P::G1,
    g2: &P::G2,
    gpk: &GroupPublicKey<P>,
    commitments_g1: &[P::G1],
    commitments_g2: &[P::G2],
    msg: &[u8],
) -> P::ScalarField {
    let mut hasher = Sha512::new();
    hasher.update(b"spok traceable group signature");
    hasher.update(g1.to_compressed_bytes());
    hasher.update(g2.to_compressed_bytes());
    hasher.update(gpk.enc_key.0.to_compressed_bytes());
    hasher.update(gpk.ver_key.xx.to_compressed_bytes());
    hasher.update(gpk.ver_key.yy.to_compressed_bytes());
    for e1 in commitments_g1 {
        hasher.update(e1.to_compressed_bytes());
    }
    for e2 in commitments_g2 {
        hasher.update(e2.to_compressed_bytes());
    }
    hasher.update(msg);
    P::ScalarField::from_hash(hasher)
}

/// I verify a signature of knowledge
/// * `gpk` - group public key
/// * `sig` - group signature on message `msg`
/// * `msg` - message
fn verify_signature_pok<P: Pairing>(
    gpk: &GroupPublicKey<P>,
    sig: &GroupSignature<P>,
    msg: &[u8],
) -> Result<()> {
    let g1_base = P::G1::get_base();
    let g2_base = P::G2::get_base();
    let commitments_g1 = &sig.spok.commitments_g1;
    let commitments_g2 = &sig.spok.commitments_g2;
    let challenge = compute_signature_pok_challenge(
        &g1_base,
        &g2_base,
        gpk,
        commitments_g1.as_slice(),
        commitments_g2.as_slice(),
        msg,
    );

    // 1 Verify ps_signature
    let xx = &gpk.ver_key.xx;
    let yy = &gpk.ver_key.yy;
    let com_yy_blind_tag = &commitments_g2[0];
    let response_tag = &sig.spok.responses[0];
    let elem = xx
        .mul(&challenge)
        .add(&yy.mul(response_tag))
        .sub(com_yy_blind_tag);
    let p1 = P::pairing(&sig.cert.s1, &elem);
    let p2 = P::pairing(&sig.cert.s2.mul(&challenge), &g2_base);

    if p1 != p2 {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    // 2 Verify tag encryption
    let com_g1_blind_tag = &sig.spok.commitments_g1[0];
    let com_pk_blind_r = &sig.spok.commitments_g1[1];
    let com_g1_blind_r = &sig.spok.commitments_g1[2];
    let response_r = &sig.spok.responses[1];
    let e1 = &sig.enc.e1;
    let e2 = &sig.enc.e2;

    // Check e1 correctness: e1 = r * G1
    if e1.mul(&challenge) != g1_base.mul(response_r).sub(com_g1_blind_r) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    // Check e2 correctness: e2 = tag * G1 + r * PK
    let a = g1_base.mul(response_tag).sub(com_g1_blind_tag);
    let b = gpk.enc_key.0.mul(response_r).sub(com_pk_blind_r);
    if e2.mul(&challenge) != a.add(&b) {
        return Err(eg!(ZeiError::ZKProofVerificationError));
    }

    Ok(())
}

/// I verify a group signature
/// * `gpk` - group public key
/// * `sig` - group signature
/// * `msg` - message
#[inline(always)]
pub fn gpsig_verify<P: Pairing>(
    gpk: &GroupPublicKey<P>,
    sig: &GroupSignature<P>,
    msg: &[u8],
) -> Result<()> {
    verify_signature_pok(gpk, sig, msg).c(d!())
}

/// I recover the identity of the producer of a group signature.
/// This algorithm is run by the Group Manager.
/// * `sig` - signature
/// * `gp_sk` - group secret key
/// ```
pub fn gpsig_open<P: Pairing>(
    sig: &GroupSignature<P>,
    gp_sk: &GroupSecretKey<P>,
) -> TagKey<P::G1> {
    TagKey(elgamal_decrypt_elem(&sig.enc, &gp_sk.dec_key))
}

#[cfg(test)]

mod tests {
    use super::{gpsig_join_cert, gpsig_open, gpsig_setup, gpsig_sign, gpsig_verify};
    use algebra::bls12_381::{BLSScalar, Bls12381, BLSG1, BLSG2};
    use algebra::groups::{Group, GroupArithmetic};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use utils::errors::ZeiError;

    #[test]
    fn group_manager_keys_are_consistent() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (gpk, msk) = gpsig_setup::<_, Bls12381>(&mut prng);

        // Check the signature keys
        let pub_sig_key = &gpk.ver_key;
        let priv_sig_key = &msk.sig_key;

        // Signing keys
        let g2_base = BLSG2::get_base();
        assert_eq!(pub_sig_key.xx, g2_base.mul(&priv_sig_key.x));

        // Encryption keys
        let pub_enc_key = gpk.enc_key.0;
        let priv_enc_key: BLSScalar = msk.dec_key.0;

        let g1_base = BLSG1::get_base();
        let recomputed_pub_enc_key = g1_base.mul(&priv_enc_key);

        assert_eq!(pub_enc_key, recomputed_pub_enc_key);
    }

    #[test]
    fn group_signatures_are_computed_correctly() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (gpk, msk) = gpsig_setup::<_, Bls12381>(&mut prng);

        // Correct signature
        let (join_cert, _) = gpsig_join_cert(&mut prng, &msk);
        let sig = gpsig_sign(&mut prng, &gpk, &join_cert, b"Some message");
        assert!(gpsig_verify(&gpk, &sig, b"Some message").is_ok());

        // Incorrect message
        msg_eq!(
            ZeiError::ZKProofVerificationError,
            gpsig_verify(&gpk, &sig, b"Wrong message").unwrap_err()
        );

        // Use of another group public key
        let (another_gpk, _) = gpsig_setup(&mut prng);
        let sig = gpsig_sign(&mut prng, &gpk, &join_cert, b"Some message");
        msg_eq!(
            ZeiError::ZKProofVerificationError,
            gpsig_verify(&another_gpk, &sig, b"Some message").unwrap_err()
        );
    }

    #[test]
    fn user_identity_can_be_recovered_by_group_manager() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (gpk, msk) = gpsig_setup::<_, Bls12381>(&mut prng);

        let (join_cert, tag_key) = gpsig_join_cert(&mut prng, &msk);
        let sig = gpsig_sign(&mut prng, &gpk, &join_cert, b"Some message");

        let tag_group_element_recovered = gpsig_open(&sig, &msk);

        assert_eq!(tag_group_element_recovered, tag_key);
    }
}
