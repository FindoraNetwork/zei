use crate::basics::hash::rescue::{RescueCtr, RescueInstance};
use algebra::bls12_381::{BLSScalar, BLS_SCALAR_LEN};
use algebra::groups::{Group, GroupArithmetic, Scalar};
use algebra::jubjub::{JubjubPoint, JubjubScalar};
use algebra::ristretto::RistrettoPoint;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use std::hash::{Hash, Hasher};
use utils::errors::ZeiError;
use utils::serialization::ZeiFromToBytes;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalEncKey<G>(pub G); //PK = sk*G

impl<G: Clone> ElGamalEncKey<G> {
    pub fn get_point(&self) -> G {
        self.0.clone()
    }
    pub fn get_point_ref(&self) -> &G {
        &self.0
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalDecKey<S>(pub(crate) S); //sk

pub fn elgamal_key_gen<R: CryptoRng + RngCore, G: Group>(
    prng: &mut R,
    base: &G,
) -> (ElGamalDecKey<G::S>, ElGamalEncKey<G>) {
    let secret_key = ElGamalDecKey(G::S::random(prng));
    let public_key = ElGamalEncKey(base.mul(&secret_key.0));
    (secret_key, public_key)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext<G> {
    pub e1: G, //r*G
    pub e2: G, //m*G + r*PK
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalHybridCiphertext<G, S> {
    pub e1: G,              // r*G
    pub symm_ctxts: Vec<S>, // ctr-mode ciphertext
}

impl Hash for ElGamalEncKey<RistrettoPoint> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_compressed_bytes().as_slice().hash(state);
    }
}

impl ZeiFromToBytes for ElGamalCiphertext<RistrettoPoint> {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.e1.to_compressed_bytes().as_slice());
        v.extend_from_slice(self.e2.to_compressed_bytes().as_slice());
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        let e1 = RistrettoPoint::from_compressed_bytes(
            &bytes[0..RistrettoPoint::COMPRESSED_LEN],
        )
        .c(d!(ZeiError::DeserializationError))?;
        let e2 = RistrettoPoint::from_compressed_bytes(
            &bytes[RistrettoPoint::COMPRESSED_LEN..],
        )
        .c(d!(ZeiError::DeserializationError))?;
        Ok(ElGamalCiphertext { e1, e2 })
    }
}

impl ZeiFromToBytes for ElGamalHybridCiphertext<JubjubPoint, BLSScalar> {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.e1.zei_to_bytes().as_slice());
        for s in self.symm_ctxts.iter() {
            v.extend_from_slice(s.zei_to_bytes().as_slice());
        }
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        let e1 = JubjubPoint::zei_from_bytes(&bytes[0..JubjubPoint::COMPRESSED_LEN])
            .c(d!(ZeiError::DeserializationError))?;
        let mut pos = JubjubPoint::COMPRESSED_LEN;
        let mut symm_ctxts = vec![];
        while pos < bytes.len() {
            symm_ctxts.push(
                BLSScalar::zei_from_bytes(&bytes[pos..pos + BLS_SCALAR_LEN])
                    .c(d!(ZeiError::DeserializationError))?,
            );
            pos += BLS_SCALAR_LEN;
        }
        Ok(ElGamalHybridCiphertext { e1, symm_ctxts })
    }
}

/// I encrypt a plaintext vector `data` into an ElGamal ciphertext
/// * `base`: a public curve base point
/// * `pub_key`: ElGamal public key
/// * `r`: encryption randomness
/// * `data`: plaintext
/// * Returns a ciphertext (r*G, E_ctr(k; data)), where E_ctr is a Rescue-based counter-mode encryption
/// and k is a symmetric key derived from r * pub_key
// TODO: Generalize to arbitrary group and scalar types
pub fn elgamal_hybrid_encrypt(
    base: &JubjubPoint,
    pub_key: &ElGamalEncKey<JubjubPoint>,
    r: &JubjubScalar,
    data: &[BLSScalar],
) -> ElGamalHybridCiphertext<JubjubPoint, BLSScalar> {
    let e1 = base.mul(r);
    let e2 = pub_key.0.mul(r);
    let symm_ctxts = apply_keystream_from_seed(&e2, data, true);
    ElGamalHybridCiphertext { e1, symm_ctxts }
}

/// I decrypt a ciphertext of the Elgamal hybrid encryption back to the plaintext vector.
// TODO: Generalize to arbitrary group and scalar types
pub fn elgamal_hybrid_decrypt(
    sec_key: &ElGamalDecKey<JubjubScalar>,
    ctext: &ElGamalHybridCiphertext<JubjubPoint, BLSScalar>,
) -> Vec<BLSScalar> {
    let e2 = ctext.e1.mul(&sec_key.0);
    apply_keystream_from_seed(&e2, &ctext.symm_ctxts, false)
}

// Derive a symmetric key from `seed` and encrypt/decrypt the `data`.
fn apply_keystream_from_seed(
    seed: &JubjubPoint,
    data: &[BLSScalar],
    is_encrypt: bool,
) -> Vec<BLSScalar> {
    let rescue = RescueInstance::new();
    let zero = BLSScalar::from_u32(0);
    let input = [seed.get_x(), seed.get_y(), zero, zero];
    let key = rescue.rescue_hash(&input);
    let mut cipher = RescueCtr::new(&key, zero);
    let mut result = data.to_vec();
    if is_encrypt {
        cipher.add_keystream(&mut result);
    } else {
        cipher.sub_keystream(&mut result);
    }
    result
}

/// I return an ElGamal ciphertext pair as (r*G, m*g + r*PK), where G is a curve base point
pub fn elgamal_encrypt<G: Group>(
    base: &G,
    m: &G::S,
    r: &G::S,
    pub_key: &ElGamalEncKey<G>,
) -> ElGamalCiphertext<G> {
    let e1 = base.mul(r);
    let e2 = base.mul(m).add(&(pub_key.0).mul(r));

    ElGamalCiphertext::<G> { e1, e2 }
}

/// I verify that ctext encrypts m (ctext.e2 - ctext.e1 * sk = m* G)
pub fn elgamal_verify<G: Group>(
    base: &G,
    m: &G::S,
    ctext: &ElGamalCiphertext<G>,
    sec_key: &ElGamalDecKey<G::S>,
) -> Result<()> {
    if base.mul(m).add(&ctext.e1.mul(&sec_key.0)) == ctext.e2 {
        Ok(())
    } else {
        Err(eg!(ZeiError::ElGamalVerificationError))
    }
}

/// ElGamal decryption: Return group element
pub fn elgamal_decrypt_elem<G: Group>(
    ctext: &ElGamalCiphertext<G>,
    sec_key: &ElGamalDecKey<G::S>,
) -> G {
    ctext.e2.sub(&ctext.e1.mul(&sec_key.0))
}

/// I decrypt en ElGamal ciphertext on the exponent via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt<G: Group>(
    base: &G,
    ctext: &ElGamalCiphertext<G>,
    sec_key: &ElGamalDecKey<G::S>,
) -> Result<u64> {
    elgamal_decrypt_hinted::<G>(base, ctext, sec_key, 0, (u32::max_value() as u64) + 1)
        .c(d!())
}

/// I decrypt en ElGamal ciphertext on the exponent via brute force
/// Return ZeiError::ElGamalDecryptionError if value is not in the range [0..2^32-1]
pub fn elgamal_decrypt_as_scalar<G: Group>(
    base: &G,
    ctext: &ElGamalCiphertext<G>,
    sec_key: &ElGamalDecKey<G::S>,
) -> Result<G::S> {
    Ok(G::S::from_u64(
        elgamal_decrypt(base, ctext, sec_key).c(d!())?,
    ))
}

/// I decrypt en ElGamal ciphertext on the exponent via brute force in the range [lower_bound..upper_bound]
/// Return ZeiError::ElGamalDecryptionError if value is not in the range.
pub fn elgamal_decrypt_hinted<G: Group>(
    base: &G,
    ctext: &ElGamalCiphertext<G>,
    sec_key: &ElGamalDecKey<G::S>,
    lower_bound: u64,
    upper_bound: u64,
) -> Result<u64> {
    let encoded = elgamal_decrypt_elem(ctext, sec_key);
    brute_force::<G>(base, &encoded, lower_bound, upper_bound).c(d!())
}

fn brute_force<G: Group>(
    base: &G,
    encoded: &G,
    lower_bound: u64,
    upper_bound: u64,
) -> Result<u64> {
    let mut b = base.mul(&G::S::from_u64(lower_bound));
    for i in lower_bound..upper_bound {
        if b == *encoded {
            return Ok(i);
        }
        b = b.add(base);
    }
    Err(eg!(ZeiError::ElGamalDecryptionError))
}

#[cfg(test)]
mod elgamal_test {
    use crate::basics::elgamal::{
        ElGamalCiphertext, ElGamalDecKey, ElGamalEncKey, ElGamalHybridCiphertext,
    };
    use algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
    use algebra::groups::{Group, Scalar};
    use algebra::jubjub::{JubjubPoint, JubjubScalar};
    use algebra::ristretto::RistrettoPoint;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use rmp_serde::Deserializer;
    use ruc::*;
    use serde::de::Deserialize;
    use serde::ser::Serialize;
    use utils::errors::ZeiError;

    fn verification<G: Group>() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let base = G::get_base();

        let (secret_key, public_key) = super::elgamal_key_gen::<_, G>(&mut prng, &base);

        let m = G::S::from_u32(100u32);
        let r = G::S::random(&mut prng);
        let ctext = super::elgamal_encrypt::<G>(&base, &m, &r, &public_key);
        pnk!(super::elgamal_verify::<G>(&base, &m, &ctext, &secret_key));

        let wrong_m = G::S::from_u32(99u32);
        let err = super::elgamal_verify(&base, &wrong_m, &ctext, &secret_key)
            .err()
            .unwrap();
        msg_eq!(ZeiError::ElGamalVerificationError, err);
    }

    fn decryption<G: Group>() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let base = G::get_base();

        let (secret_key, public_key) = super::elgamal_key_gen::<_, G>(&mut prng, &base);

        let mu32 = 100u32;
        let m = G::S::from_u32(mu32);
        let r = G::S::random(&mut prng);
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        pnk!(super::elgamal_verify(&base, &m, &ctext, &secret_key));

        assert_eq!(
            m,
            super::elgamal_decrypt_as_scalar(&base, &ctext, &secret_key).unwrap()
        );
        assert_eq!(
            mu32,
            super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 200).unwrap()
                as u32
        );

        let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 0, 50)
            .err()
            .unwrap();
        msg_eq!(ZeiError::ElGamalDecryptionError, err);

        let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300)
            .err()
            .unwrap();
        msg_eq!(ZeiError::ElGamalDecryptionError, err);

        let m = G::S::from_u64(u64::max_value());
        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        pnk!(super::elgamal_verify(&base, &m, &ctext, &secret_key));

        let err = super::elgamal_decrypt_hinted(&base, &ctext, &secret_key, 200, 300)
            .err()
            .unwrap();
        msg_eq!(ZeiError::ElGamalDecryptionError, err);
    }

    fn serialize_to_json<G: Group>() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let base = G::get_base();

        let (secret_key, public_key) = super::elgamal_key_gen::<_, G>(&mut prng, &base);

        //keys serialization
        let json_str = serde_json::to_string(&secret_key).unwrap();
        let sk_de: ElGamalDecKey<G::S> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(secret_key, sk_de);

        let json_str = serde_json::to_string(&public_key).unwrap();
        let pk_de: ElGamalEncKey<G> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(public_key, pk_de);

        //ciphertext serialization
        let m = G::S::from_u32(100u32);
        let r = G::S::random(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);
        let json_str = serde_json::to_string(&ctext).unwrap();
        let ctext_de: ElGamalCiphertext<G> = serde_json::from_str(&json_str).unwrap();

        assert_eq!(ctext, ctext_de);
    }

    fn serialize_to_message_pack<G: Group>() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let base = G::get_base();

        let (secret_key, public_key) = super::elgamal_key_gen::<_, G>(&mut prng, &base);

        //keys serialization
        let mut vec = vec![];
        secret_key
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let sk_de: ElGamalDecKey<G::S> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(secret_key, sk_de);

        //public key serialization
        let mut vec = vec![];
        public_key
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let pk_de: ElGamalEncKey<G> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(public_key, pk_de);

        //ciphertext serialization
        let m = G::S::from_u32(100u32);
        let r = G::S::random(&mut prng);

        let ctext = super::elgamal_encrypt(&base, &m, &r, &public_key);

        let mut vec = vec![];
        ctext
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();

        let mut de = Deserializer::new(&vec[..]);
        let ctext_de: ElGamalCiphertext<G> = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(ctext, ctext_de);
    }

    #[test]
    fn verify() {
        verification::<RistrettoPoint>();
        verification::<BLSG1>();
        verification::<BLSG2>();
        verification::<BLSGt>();
        verification::<JubjubPoint>();
    }

    #[test]
    fn decrypt() {
        decryption::<RistrettoPoint>();
        decryption::<BLSG1>();
        decryption::<BLSG2>();
        decryption::<BLSGt>();
        decryption::<JubjubPoint>();
    }

    #[test]
    fn to_json() {
        serialize_to_json::<RistrettoPoint>();
        serialize_to_json::<BLSG1>();
        serialize_to_json::<BLSG2>();
        // serialize_to_json::<BLSGt>(); TODO BLSGt is not serializable yet
        serialize_to_json::<JubjubPoint>();
    }

    #[test]
    fn to_message_pack() {
        serialize_to_message_pack::<RistrettoPoint>();
        serialize_to_message_pack::<BLSG1>();
        serialize_to_message_pack::<BLSG2>();
        // serialize_to_message_pack::<BLSGt>(); TODO BLSGt is not serializable yet
        serialize_to_message_pack::<JubjubPoint>();
    }

    #[test]
    fn test_elgamal_hybrid() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let base = JubjubPoint::get_base();
        // encrypt and decrypt
        let (sec_key, pub_key) =
            super::elgamal_key_gen::<_, JubjubPoint>(&mut prng, &base);
        let m = vec![
            BLSScalar::from_u32(100u32),
            BLSScalar::from_u32(200u32),
            BLSScalar::from_u32(300u32),
            BLSScalar::from_u32(400u32),
            BLSScalar::from_u64(u64::max_value()),
        ];
        let r = JubjubScalar::random(&mut prng);
        let ctext = super::elgamal_hybrid_encrypt(&base, &pub_key, &r, &m);
        let plaintext = super::elgamal_hybrid_decrypt(&sec_key, &ctext);
        assert_eq!(plaintext, m);
        // given refreshed randomness `r`, the symmetric ciphertexts will be different
        let r = JubjubScalar::random(&mut prng);
        let ctext2 = super::elgamal_hybrid_encrypt(&base, &pub_key, &r, &m);
        assert_ne!(ctext.symm_ctxts, ctext2.symm_ctxts);

        // serialize to json
        let json_str = serde_json::to_string(&ctext).unwrap();
        let ctext_de: ElGamalHybridCiphertext<JubjubPoint, BLSScalar> =
            serde_json::from_str(&json_str).unwrap();

        assert_eq!(ctext, ctext_de);

        // serialize to message pack
        let mut vec = vec![];
        ctext
            .serialize(&mut rmp_serde::Serializer::new(&mut vec))
            .unwrap();
        let mut de = Deserializer::new(&vec[..]);
        let ctext_de: ElGamalHybridCiphertext<JubjubPoint, BLSScalar> =
            Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(ctext, ctext_de);
    }
}
