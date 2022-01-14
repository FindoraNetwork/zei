use crate::anon_creds::{
    ac_do_challenge_check_commitment, ac_randomize, ACCommitment, ACIssuerPublicKey,
    ACKey, ACPoK, ACUserSecretKey, Attribute, Credential, SOK_LABEL,
};
use crate::basics::elgamal::{elgamal_encrypt, ElGamalCiphertext, ElGamalEncKey};
use crate::sigma::{SigmaTranscript, SigmaTranscriptPairing};
use algebra::groups::{Group, GroupArithmetic, Scalar, ScalarArithmetic};
use algebra::pairing::Pairing;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use utils::errors::ZeiError;

const CAC_REVEAL_PROOF_DOMAIN: &[u8] = b"Confidential AC Reveal PoK";
const CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE: &[u8] =
    b"Confidential AC Reveal PoK New Instance";

trait CACTranscript: SigmaTranscriptPairing {
    fn cac_init<P: Pairing>(
        &mut self,
        ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
        enc_key: &ElGamalEncKey<P::G1>,
        sig_commitment: &ACCommitment<P::G1>,
        ctexts: &[ElGamalCiphertext<P::G1>],
    );
    fn append_issuer_pk<P: Pairing>(
        &mut self,
        ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
    );
    fn append_encryption_key<P: Pairing>(&mut self, key: &ElGamalEncKey<P::G1>);
    fn append_ciphertext<P: Pairing>(&mut self, ctext: &ElGamalCiphertext<P::G1>);
    fn append_ac_sig_commitment<P: Pairing>(
        &mut self,
        ac_sig_commitment: &ACCommitment<P::G1>,
    );
}

impl CACTranscript for Transcript {
    fn cac_init<P: Pairing>(
        &mut self,
        ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
        enc_key: &ElGamalEncKey<P::G1>,
        sig_commitment: &ACCommitment<P::G1>,
        ctexts: &[ElGamalCiphertext<P::G1>],
    ) {
        self.append_message(b"New Domain", CAC_REVEAL_PROOF_DOMAIN);
        self.append_group_element(b"G1", &P::G1::get_base());
        self.append_group_element(b"G2", &P::G2::get_base());
        self.append_issuer_pk::<P>(ac_issuer_pk);
        self.append_encryption_key::<P>(enc_key);
        self.append_ac_sig_commitment::<P>(sig_commitment);
        for ctext in ctexts.iter() {
            self.append_ciphertext::<P>(ctext);
        }
    }
    fn append_issuer_pk<P: Pairing>(
        &mut self,
        ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
    ) {
        self.append_group_element(b"issuer_pk.G2", &ac_issuer_pk.gen2);
        self.append_group_element(b"issuer_pk.Z1", &ac_issuer_pk.zz1);
        self.append_group_element(b"issuer_pk.Z2", &ac_issuer_pk.zz2);
        self.append_group_element(b"issuer_pk.X2", &ac_issuer_pk.xx2);
        for y2 in ac_issuer_pk.yy2.iter() {
            self.append_group_element(b"issuer_pk.Y2", y2);
        }
    }
    fn append_encryption_key<P: Pairing>(&mut self, key: &ElGamalEncKey<P::G1>) {
        self.append_group_element(b"encription key", key.get_point_ref());
    }
    fn append_ciphertext<P: Pairing>(&mut self, ctext: &ElGamalCiphertext<P::G1>) {
        self.append_group_element(b"ctext.e1", &ctext.e1);
        self.append_group_element(b"ctext.e2", &ctext.e2);
    }
    fn append_ac_sig_commitment<P: Pairing>(
        &mut self,
        sig_commitment: &ACCommitment<P::G1>,
    ) {
        self.append_group_element(b"sigma1", &sig_commitment.0.sigma1);
        self.append_group_element(b"sigma2", &sig_commitment.0.sigma2);
    }
}

/// Confidential anonymous credential reveal proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACPoK<G1, G2, S> {
    pub ac_pok: ACPoK<G2, S>,
    pub commitment_ctexts: Vec<ElGamalCiphertext<G1>>, //this can be aggregated
    pub response_rands: Vec<S>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAC<G1, G2, S> {
    pub ctexts: Vec<ElGamalCiphertext<G1>>,
    pub pok: CACPoK<G1, G2, S>,
}

impl<G1, G2, S> ConfidentialAC<G1, G2, S> {
    pub fn get_fields(self) -> (Vec<ElGamalCiphertext<G1>>, CACPoK<G1, G2, S>) {
        (self.ctexts, self.pok)
    }
}

#[allow(clippy::type_complexity)]
pub fn ac_confidential_open_commitment<R: CryptoRng + RngCore, P: Pairing>(
    prng: &mut R,
    user_sk: &ACUserSecretKey<P::ScalarField>,
    credential: &Credential<P::G1, P::G2, P::ScalarField>,
    key: &ACKey<P::ScalarField>,
    reveal_map: &[bool],
    enc_key: &ElGamalEncKey<P::G1>,
    msg: &[u8],
) -> Result<ConfidentialAC<P::G1, P::G2, P::ScalarField>> {
    // 1. create ciphertext for all revealed attributes
    let mut ctexts = vec![];
    let mut rands = vec![];
    let base = P::G1::get_base();
    let mut revealed_attrs = vec![];
    if credential.attributes.len() != reveal_map.len() {
        return Err(eg!(ZeiError::ParameterError));
    }
    for (attr, b) in credential.attributes.iter().zip(reveal_map.iter()) {
        if *b {
            let r = P::ScalarField::random(prng);
            let ctext = elgamal_encrypt::<P::G1>(&base, attr, &r, enc_key);
            rands.push(r);
            ctexts.push(ctext);
            revealed_attrs.push(*attr);
        }
    }
    // 2. Recover credential commitment
    let sig_commitment = ac_randomize::<P>(&credential.signature, key);
    // 3. Do Pok
    let mut attributes = vec![];
    for (attr, b) in credential.attributes.iter().zip(reveal_map.iter()) {
        if *b {
            attributes.push(Attribute::Revealed(attr));
        } else {
            attributes.push(Attribute::Hidden(Some(attr)));
        }
    }
    let mut transcript = Transcript::new(CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);
    let pok_attrs = ac_confidential_sok_prove::<_, P>(
        &mut transcript,
        prng,
        user_sk,
        &credential.issuer_pub_key,
        &key.t,
        attributes.as_slice(),
        &sig_commitment,
        enc_key,
        ctexts.as_slice(),
        rands.as_slice(),
        msg,
    );

    Ok(ConfidentialAC {
        ctexts,
        pok: pok_attrs,
    })
}

pub fn ac_confidential_open_verify<P: Pairing>(
    issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
    enc_key: &ElGamalEncKey<P::G1>,
    reveal_map: &[bool],
    sig_commitment: &ACCommitment<P::G1>,
    ctexts: &[ElGamalCiphertext<P::G1>],
    cac_pok: &CACPoK<P::G1, P::G2, P::ScalarField>,
    msg: &[u8],
) -> Result<()> {
    // 1. error checking
    let n = ctexts.len();
    let revealed_count = reveal_map
        .iter()
        .fold(0, |sum, b| if *b { sum + 1 } else { sum });
    if reveal_map.len() != issuer_pk.num_attrs() {
        return Err(eg!(ZeiError::ParameterError));
    }
    if n > issuer_pk.num_attrs()
        || n != cac_pok.commitment_ctexts.len()
        || n != cac_pok.response_rands.len()
        || n != revealed_count
    {
        return Err(eg!(ZeiError::IdentityRevealVerifyError));
    }

    let mut transcript = Transcript::new(CAC_REVEAL_PROOF_NEW_TRANSCRIPT_INSTANCE);

    ac_confidential_sok_verify::<P>(
        &mut transcript,
        issuer_pk,
        enc_key,
        sig_commitment,
        ctexts,
        cac_pok,
        reveal_map,
        msg,
    )
    .c(d!())
}

#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn ac_confidential_sok_prove<R: CryptoRng + RngCore, P: Pairing>(
    transcript: &mut Transcript,
    prng: &mut R,
    user_sk: &ACUserSecretKey<P::ScalarField>,
    issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
    t: &P::ScalarField,
    attrs: &[Attribute<&P::ScalarField>],
    sig_commitment: &ACCommitment<P::G1>,
    enc_key: &ElGamalEncKey<P::G1>,
    ctexts: &[ElGamalCiphertext<P::G1>],
    rands: &[P::ScalarField],
    msg: &[u8],
) -> CACPoK<P::G1, P::G2, P::ScalarField> {
    transcript.cac_init::<P>(issuer_pk, enc_key, sig_commitment, ctexts);
    transcript.append_message(SOK_LABEL, msg); // SoK
    let r_t = P::ScalarField::random(prng);
    let r_sk = P::ScalarField::random(prng);
    let mut r_attrs = vec![];
    let mut r_rands = vec![];
    let mut commitment = issuer_pk.gen2.mul(&r_t).add(&issuer_pk.zz2.mul(&r_sk));
    let mut ctext_coms = vec![];
    for (Y2_i, attr) in issuer_pk.yy2.iter().zip(attrs.iter()) {
        let r_attr = P::ScalarField::random(prng);
        let elem = Y2_i.mul(&r_attr);
        commitment = commitment.add(&elem);
        if let Attribute::Revealed(_) = attr {
            let r_rand = P::ScalarField::random(prng);
            let ctext_com =
                elgamal_encrypt(&P::G1::get_base(), &r_attr, &r_rand, enc_key);
            transcript.append_proof_commitment(&ctext_com.e1);
            transcript.append_proof_commitment(&ctext_com.e2);
            ctext_coms.push(ctext_com);
            r_rands.push(r_rand);
        };
        r_attrs.push(r_attr);
    }
    transcript.append_proof_commitment(&commitment);
    let challenge = transcript.get_challenge::<P::ScalarField>();
    let response_t = challenge.mul(t).add(&r_t); // challente*t + beta1
    let response_sk = challenge.mul(&user_sk.0).add(&r_sk);
    let mut response_attrs = vec![];
    for (attr_enum, r_attr) in attrs.iter().zip(r_attrs.iter()) {
        match attr_enum {
            Attribute::Hidden(Some(attr)) => {
                let response_attr = challenge.mul(attr).add(r_attr);
                response_attrs.push(response_attr);
            }
            Attribute::Revealed(attr) => {
                let response_attr = challenge.mul(attr).add(r_attr);
                response_attrs.push(response_attr);
            }
            _ => {}
        }
    }
    let mut response_rands = vec![];
    for (rand, r_rand) in rands.iter().zip(r_rands.iter()) {
        let response_rand = challenge.mul(rand).add(r_rand);
        response_rands.push(response_rand);
    }
    CACPoK {
        ac_pok: ACPoK {
            commitment,
            response_t,
            response_sk,
            response_attrs,
        },
        commitment_ctexts: ctext_coms,
        response_rands,
    }
}

#[allow(clippy::too_many_arguments)]
fn ac_confidential_sok_verify<P: Pairing>(
    transcript: &mut Transcript,
    ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
    enc_key: &ElGamalEncKey<P::G1>,
    sig_commitment: &ACCommitment<P::G1>,
    ctexts: &[ElGamalCiphertext<P::G1>],
    cac_pok: &CACPoK<P::G1, P::G2, P::ScalarField>,
    bitmap: &[bool], // indicates which hidden attributes are encrypted under enc_key
    msg: &[u8],
) -> Result<()> {
    transcript.cac_init::<P>(ac_issuer_pub_key, enc_key, sig_commitment, ctexts);
    transcript.append_message(SOK_LABEL, msg); // SoK
                                               // 1. compute challenge
    for ctext in cac_pok.commitment_ctexts.iter() {
        transcript.append_proof_commitment(&ctext.e1);
        transcript.append_proof_commitment(&ctext.e2);
    }
    transcript.append_proof_commitment(&cac_pok.ac_pok.commitment);

    let challenge = transcript.get_challenge::<P::ScalarField>();
    // 2. verify ciphertexts
    //    need to select attributes that are encrypted
    let mut attr_resps = vec![];
    for (z_attr, b) in cac_pok.ac_pok.response_attrs.iter().zip(bitmap.iter()) {
        if *b {
            attr_resps.push(z_attr);
        }
    }

    verify_ciphertext::<P>(
        &challenge,
        ctexts,
        cac_pok.commitment_ctexts.as_slice(),
        attr_resps.as_slice(),
        cac_pok.response_rands.as_slice(),
        enc_key,
    )
    .c(d!())?;

    // 3. verify credential proof
    let hidden_attributes = vec![Attribute::Hidden(None); ac_issuer_pub_key.num_attrs()];
    ac_do_challenge_check_commitment::<P>(
        ac_issuer_pub_key,
        sig_commitment,
        &cac_pok.ac_pok,
        hidden_attributes.as_slice(),
        &challenge,
    )
    .c(d!())
}

fn verify_ciphertext<P: Pairing>(
    challenge: &P::ScalarField,
    ctexts: &[ElGamalCiphertext<P::G1>],
    ctexts_coms: &[ElGamalCiphertext<P::G1>],
    attrs_resp: &[&P::ScalarField],
    rands_resps: &[P::ScalarField],
    enc_key: &ElGamalEncKey<P::G1>,
) -> Result<()> {
    for (ctext, ctext_com, attr_resp, rand_resp) in izip!(
        ctexts.iter(),
        ctexts_coms.iter(),
        attrs_resp.iter(),
        rands_resps.iter()
    ) {
        let enc = elgamal_encrypt(&P::G1::get_base(), attr_resp, rand_resp, enc_key);
        if enc.e1 != ctext.e1.mul(challenge).add(&ctext_com.e1) {
            return Err(eg!(ZeiError::IdentityRevealVerifyError));
        }
        if enc.e2 != ctext.e2.mul(challenge).add(&ctext_com.e2) {
            return Err(eg!(ZeiError::IdentityRevealVerifyError));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_helper {
    use crate::anon_creds::{
        ac_commit, ac_keygen_issuer, ac_sign, ac_user_key_gen, ac_verify_commitment,
        Credential,
    };
    use crate::basics::elgamal::elgamal_key_gen;
    use crate::conf_cred_reveal::{
        ac_confidential_open_commitment, ac_confidential_open_verify,
    };
    use algebra::groups::{Group, Scalar};
    use algebra::pairing::Pairing;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use utils::errors::ZeiError;

    pub(super) fn byte_slice_to_scalar<S: Scalar>(slice: &[u8]) -> S {
        use digest::Digest;
        use sha2::Sha512;
        let mut hasher = Sha512::new();
        hasher.update(slice);
        S::from_hash(hasher)
    }

    pub fn test_confidential_ac_reveal<P: Pairing>(reveal_bitmap: &[bool]) {
        let proof_message = b"Some message";
        let credential_addr = b"Some address";
        let num_attr = reveal_bitmap.len();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (issuer_pk, issuer_sk) = ac_keygen_issuer::<_, P>(&mut prng, num_attr);
        let (user_pk, user_sk) = ac_user_key_gen::<_, P>(&mut prng, &issuer_pk);
        let (_, enc_key) = elgamal_key_gen::<_, P::G1>(&mut prng, &P::G1::get_base());

        let mut attrs = Vec::new();
        for i in 0..num_attr {
            attrs.push(byte_slice_to_scalar(format!("attr{}!", i).as_bytes()));
        }

        let ac_sig =
            ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, &attrs[..]).unwrap();
        let credential = Credential {
            signature: ac_sig,
            attributes: attrs,
            issuer_pub_key: issuer_pk.clone(),
        };
        let output =
            ac_commit::<_, P>(&mut prng, &user_sk, &credential, credential_addr)
                .unwrap();

        let sig_commitment = output.0;
        let sok = output.1;
        let key = output.2.unwrap(); // safe unwrap()

        // 1. Verify commitment
        assert!(ac_verify_commitment::<P>(
            &issuer_pk,
            &sig_commitment,
            &sok,
            credential_addr
        )
        .is_ok());
        let conf_reveal_proof = ac_confidential_open_commitment::<_, P>(
            &mut prng,
            &user_sk,
            &credential,
            &key,
            reveal_bitmap,
            &enc_key,
            proof_message,
        )
        .unwrap();
        assert!(ac_confidential_open_verify::<P>(
            &credential.issuer_pub_key,
            &enc_key,
            reveal_bitmap,
            &sig_commitment,
            &conf_reveal_proof.ctexts,
            &conf_reveal_proof.pok,
            proof_message,
        )
        .is_ok());

        // Error cases /////////////////////////////////////////////////////////////////////////////////

        // Tampered bitmap
        let mut tampered_bitmap = vec![];
        tampered_bitmap.extend_from_slice(reveal_bitmap);

        let b = reveal_bitmap.get(0).unwrap();

        tampered_bitmap[0] = !(*b);

        let vrfy = ac_confidential_open_verify::<P>(
            &issuer_pk,
            &enc_key,
            &tampered_bitmap[..],
            &sig_commitment,
            &conf_reveal_proof.ctexts,
            &conf_reveal_proof.pok,
            proof_message,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            vrfy.unwrap_err(),
            "proof should fail, reveal map doesn't match"
        );

        // Empty bitmap
        let empty_bitmap = vec![];
        let vrfy = ac_confidential_open_verify::<P>(
            &issuer_pk,
            &enc_key,
            &empty_bitmap[..],
            &sig_commitment,
            &conf_reveal_proof.ctexts,
            &conf_reveal_proof.pok,
            proof_message,
        );
        msg_eq!(
            ZeiError::ParameterError,
            vrfy.unwrap_err(),
            "proof should fail, bitmap length does not match number of attributes"
        );

        // Wrong ac issuer public key
        let (another_issuer_pk, _) = ac_keygen_issuer::<_, P>(&mut prng, num_attr);
        let vrfy = ac_confidential_open_verify::<P>(
            &another_issuer_pk,
            &enc_key,
            &reveal_bitmap,
            &sig_commitment,
            &conf_reveal_proof.ctexts,
            &conf_reveal_proof.pok,
            proof_message,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            vrfy.unwrap_err(),
            "proof should fail, bad ac issuer public key"
        );

        // Wrong encryption public key
        let (_, another_enc_key) =
            elgamal_key_gen::<_, P::G1>(&mut prng, &P::G1::get_base());
        let vrfy = ac_confidential_open_verify::<P>(
            &issuer_pk,
            &another_enc_key,
            &reveal_bitmap,
            &sig_commitment,
            &conf_reveal_proof.ctexts,
            &conf_reveal_proof.pok,
            proof_message,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            vrfy.unwrap_err(),
            "proof should fail, bad encryption key"
        );

        // Wrong message
        let wrong_message = b"Some other message";
        let vrfy = ac_confidential_open_verify::<P>(
            &issuer_pk,
            &enc_key,
            &reveal_bitmap,
            &sig_commitment,
            &conf_reveal_proof.ctexts,
            &conf_reveal_proof.pok,
            wrong_message,
        );
        msg_eq!(
            ZeiError::IdentityRevealVerifyError,
            vrfy.unwrap_err(),
            "proof should fail, bad sok message"
        );
    }
}

#[cfg(test)]
mod test_bls12_381 {
    use crate::conf_cred_reveal::test_helper::test_confidential_ac_reveal;
    use algebra::bls12_381::Bls12381;

    #[test]
    fn confidential_reveal_one_attr_hidden() {
        test_confidential_ac_reveal::<Bls12381>(&[false]);
    }

    #[test]
    fn confidential_reveal_one_attr_revealed() {
        test_confidential_ac_reveal::<Bls12381>(&[true]);
    }

    #[test]
    fn confidential_reveal_two_attr_hidden_first() {
        test_confidential_ac_reveal::<Bls12381>(&[false, false]);
        test_confidential_ac_reveal::<Bls12381>(&[false, true]);
    }

    #[test]
    fn confidential_reveal_two_attr_revealed_first() {
        test_confidential_ac_reveal::<Bls12381>(&[true, false]);
        test_confidential_ac_reveal::<Bls12381>(&[true, true]);
    }

    #[test]
    fn confidential_reveal_ten_attr_all_hidden() {
        test_confidential_ac_reveal::<Bls12381>(&[false; 10]);
    }

    #[test]
    fn confidential_reveal_ten_attr_all_revealed() {
        test_confidential_ac_reveal::<Bls12381>(&[true; 10]);
    }

    #[test]
    fn confidential_reveal_ten_attr_half_revealed() {
        test_confidential_ac_reveal::<Bls12381>(&[
            true, false, true, false, true, false, true, false, true, false,
        ]);
        test_confidential_ac_reveal::<Bls12381>(&[
            false, true, false, true, false, true, false, true, false, true,
        ]);
    }
}

#[cfg(test)]
mod test_serialization {

    use algebra::bls12_381::Bls12381;
    use algebra::groups::Group;
    use algebra::pairing::Pairing;

    use super::test_helper::byte_slice_to_scalar;
    use crate::anon_creds::{ac_commit, ac_sign};
    use crate::anon_creds::{ac_keygen_issuer, ac_user_key_gen, Credential};
    use crate::basics::elgamal::elgamal_key_gen;
    use crate::conf_cred_reveal::ac_confidential_open_commitment;
    use crate::conf_cred_reveal::ConfidentialAC;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use rmp_serde::Deserializer;
    use serde::{Deserialize, Serialize};

    fn gen_confidential_ac<P>() -> ConfidentialAC<P::G1, P::G2, P::ScalarField>
    where
        P: Pairing,
    {
        let reveal_bitmap = [true, false, true, true];
        let num_attr = reveal_bitmap.len();

        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (issuer_pk, issuer_sk) = ac_keygen_issuer::<_, P>(&mut prng, num_attr);
        let (user_pk, user_sk) = ac_user_key_gen::<_, P>(&mut prng, &issuer_pk);
        let (_, enc_key) = elgamal_key_gen::<_, P::G1>(&mut prng, &P::G1::get_base());

        let mut attrs = Vec::new();
        for i in 0..num_attr {
            attrs.push(byte_slice_to_scalar(format!("attr{}!", i).as_bytes()));
        }

        let ac_sig =
            ac_sign::<_, P>(&mut prng, &issuer_sk, &user_pk, &attrs[..]).unwrap();
        let credential = Credential {
            signature: ac_sig,
            attributes: attrs,
            issuer_pub_key: issuer_pk,
        };

        let output =
            ac_commit::<_, P>(&mut prng, &user_sk, &credential, b"an address").unwrap();
        let key = output.2.unwrap(); // Safe unwrap()
        let conf_reveal_proof = ac_confidential_open_commitment::<_, P>(
            &mut prng,
            &user_sk,
            &credential,
            &key,
            &reveal_bitmap[..],
            &enc_key,
            b"Some message",
        )
        .unwrap();
        conf_reveal_proof
    }

    fn to_json<P: Pairing>() {
        let confidential_ac = gen_confidential_ac::<P>();

        let json_str = serde_json::to_string(&confidential_ac).unwrap();
        let confidential_ac_de: ConfidentialAC<P::G1, P::G2, P::ScalarField> =
            serde_json::from_str(&json_str).unwrap();
        assert_eq!(confidential_ac, confidential_ac_de);
    }

    fn to_msg_pack<P: Pairing>() {
        let confidential_ac = gen_confidential_ac::<P>();
        //keys serialization
        let mut vec = vec![];
        confidential_ac
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let confidential_ac_de: ConfidentialAC<P::G1, P::G2, P::ScalarField> =
            Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(confidential_ac, confidential_ac_de);
    }

    #[test]
    fn to_json_bls() {
        to_json::<Bls12381>();
    }

    #[test]
    fn to_msg_pack_bls() {
        to_msg_pack::<Bls12381>();
    }
}
