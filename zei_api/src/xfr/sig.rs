use algebra::{
    groups::Scalar as _,
    ristretto::{CompressedEdwardsY, RistrettoScalar as Scalar},
};
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, Signature, Verifier};
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};
use utils::{errors::ZeiError, serialization::ZeiFromToBytes};
use wasm_bindgen::prelude::*;

pub const XFR_SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;

#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Default)]
pub struct XfrPublicKey(pub(crate) PublicKey);
#[derive(Debug)]
pub struct XfrSecretKey(pub(crate) SecretKey);
#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XfrKeyPair {
    pub pub_key: XfrPublicKey,
    pub(crate) sec_key: XfrSecretKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XfrSignature(pub Signature);

impl Eq for XfrPublicKey {}

impl PartialEq for XfrPublicKey {
    fn eq(&self, other: &XfrPublicKey) -> bool {
        self.as_bytes().eq(other.as_bytes())
    }
}

impl Ord for XfrPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(&other.as_bytes())
    }
}

impl PartialOrd for XfrPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for XfrPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state)
    }
}

impl XfrPublicKey {
    /// returns XfrPublicKey as a compressed edwards point
    pub fn as_compressed_edwards_point(&self) -> CompressedEdwardsY {
        CompressedEdwardsY::from_slice(self.0.as_bytes())
    }

    pub fn verify(&self, message: &[u8], signature: &XfrSignature) -> Result<()> {
        self.0
            .verify(message, &signature.0)
            .c(d!(ZeiError::SignatureError))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Clone for XfrSecretKey {
    fn clone(&self) -> Self {
        XfrSecretKey(SecretKey::from_bytes(self.0.as_ref()).unwrap())
    }
}

impl Eq for XfrSecretKey {}

impl PartialEq for XfrSecretKey {
    fn eq(&self, other: &XfrSecretKey) -> bool {
        self.as_scalar().eq(&other.as_scalar())
    }
}

impl Ord for XfrSecretKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_scalar()
            .0
            .to_bytes()
            .cmp(&other.as_scalar().0.to_bytes())
    }
}

impl PartialOrd for XfrSecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for XfrSecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_scalar().0.hash(state)
    }
}

impl XfrSecretKey {
    #[inline(always)]
    pub fn into_keypair(self) -> XfrKeyPair {
        XfrKeyPair {
            pub_key: XfrPublicKey(ed25519_dalek::PublicKey::from(&self.0)),
            sec_key: self,
        }
    }

    pub fn sign(&self, message: &[u8], public_key: &XfrPublicKey) -> XfrSignature {
        let expanded: ExpandedSecretKey = (&self.0).into();
        let sign = expanded.sign(message, &public_key.0);

        XfrSignature(sign)
    }

    /// Returns SecretKey as a Scalar
    pub(crate) fn as_scalar(&self) -> Scalar {
        let expanded: ExpandedSecretKey = (&self.0).into();
        // expanded.key is not public, thus extract it via serialization
        let mut key_bytes = vec![];
        key_bytes.extend_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
        Scalar::from_bytes(&key_bytes).expect("Internal error, should never fail")
    }
}

impl XfrKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let kp = ed25519_dalek::Keypair::generate(prng);
        XfrKeyPair {
            pub_key: XfrPublicKey(kp.public),
            sec_key: XfrSecretKey(kp.secret),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> XfrSignature {
        self.sec_key.sign(msg, &self.pub_key)
    }

    #[inline(always)]
    pub fn get_pk(&self) -> XfrPublicKey {
        self.pub_key
    }

    #[inline(always)]
    pub fn get_pk_ref(&self) -> &XfrPublicKey {
        &self.pub_key
    }

    #[inline(always)]
    pub fn get_sk(&self) -> XfrSecretKey {
        self.sec_key.clone()
    }

    #[inline(always)]
    pub fn get_sk_ref(&self) -> &XfrSecretKey {
        &self.sec_key
    }
}

impl ZeiFromToBytes for XfrKeyPair {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.sec_key.zei_to_bytes().as_slice());
        vec.extend_from_slice(self.pub_key.zei_to_bytes().as_slice());
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(XfrKeyPair {
            sec_key: XfrSecretKey::zei_from_bytes(&bytes[0..XFR_SECRET_KEY_LENGTH])
                .c(d!())?,
            pub_key: XfrPublicKey::zei_from_bytes(&bytes[XFR_SECRET_KEY_LENGTH..])
                .c(d!())?,
        })
    }
}

////Primitive for multisignatures /////
///A multisignature is defined as a signature on a message that must verify against a list of public keys instead of one
// naive implementation below
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrMultiSig {
    pub signatures: Vec<XfrSignature>,
}

impl XfrMultiSig {
    /// Sign a multisig under a list of keypairs
    pub fn sign(keypairs: &[&XfrKeyPair], message: &[u8]) -> Self {
        // sort the key pairs based on alphabetical order of their public keys
        let mut sorted = keypairs.to_owned();
        sorted.sort_unstable_by_key(|kp| kp.pub_key.zei_to_bytes());
        let signatures = sorted.iter().map(|kp| kp.sign(&message)).collect_vec();
        XfrMultiSig { signatures }
    }

    /// Verify a multisig
    pub fn verify(&self, pubkeys: &[&XfrPublicKey], message: &[u8]) -> Result<()> {
        if pubkeys.len() != self.signatures.len() {
            return Err(eg!(ZeiError::SignatureError));
        }
        // sort the key pairs based on alphabetical order of their public keys
        let mut sorted = pubkeys.to_owned();
        sorted.sort_unstable_by_key(|k| k.zei_to_bytes());
        for (pk, sig) in sorted.iter().zip(self.signatures.iter()) {
            pk.verify(&message, &sig).c(d!())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::xfr::sig::{XfrKeyPair, XfrMultiSig};
    use itertools::Itertools;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::err::*;
    use utils::errors::ZeiError::SignatureError;

    #[test]
    fn signatures() {
        let mut prng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);

        let keypair = XfrKeyPair::generate(&mut prng);
        let message = "";

        let sig = keypair.sign(message.as_bytes());
        pnk!(keypair.pub_key.verify("".as_bytes(), &sig));
        //same test with secret key
        let sig = keypair.sec_key.sign(message.as_bytes(), &keypair.pub_key);
        pnk!(keypair.pub_key.verify("".as_bytes(), &sig));

        //test again with fresh same key
        let mut prng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);
        let keypair = XfrKeyPair::generate(&mut prng);
        pnk!(keypair.pub_key.verify("".as_bytes(), &sig));

        let keypair = XfrKeyPair::generate(&mut prng);
        let message = [10u8; 500];
        let sig = keypair.sign(&message);
        msg_eq!(
            dbg!(SignatureError),
            dbg!(keypair.pub_key.verify("".as_bytes(), &sig).unwrap_err()),
            "Verifying sig on different message should have return Err(Signature Error)"
        );
        pnk!(keypair.pub_key.verify(&message, &sig));
        //test again with secret key
        let sig = keypair.sec_key.sign(&message, &keypair.pub_key);
        msg_eq!(
            SignatureError,
            keypair.pub_key.verify("".as_bytes(), &sig).unwrap_err(),
            "Verifying sig on different message should have return Err(Signature Error)"
        );
        pnk!(keypair.pub_key.verify(&message, &sig));

        // test with different keys
        let keypair = XfrKeyPair::generate(&mut prng);
        msg_eq!(
            SignatureError,
            keypair.pub_key.verify(&message, &sig).unwrap_err(),
            "Verifying sig on with a different key should have return Err(Signature Error)"
        );
    }

    fn generate_keypairs(prng: &mut ChaChaRng, n: usize) -> Vec<XfrKeyPair> {
        let mut v = vec![];
        for _ in 0..n {
            v.push(XfrKeyPair::generate(prng));
        }
        v
    }

    #[test]
    fn multisig() {
        let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
        let msg = b"random message here!".to_vec();
        // test with one key
        let keypairs = generate_keypairs(&mut prng, 1);
        let keypairs_refs = keypairs.iter().collect_vec();
        let pubkeys = keypairs.iter().map(|kp| &kp.pub_key).collect_vec();
        assert!(
            XfrMultiSig::sign(&keypairs_refs, &msg)
                .verify(&pubkeys, &msg)
                .is_ok(),
            "Multisignature should have verify correctly for a single key"
        );

        // test with multiple keys
        let keypairs = generate_keypairs(&mut prng, 10);
        let keypairs_refs = keypairs.iter().collect_vec();
        let pubkeys = keypairs.iter().map(|kp| &kp.pub_key).collect_vec();
        assert!(
            XfrMultiSig::sign(&keypairs_refs, &msg)
                .verify(&pubkeys, &msg)
                .is_ok(),
            "Multisignature should have verify correctly for 10 keys"
        );

        // test with unmatching order of keypairs
        let keypairs = generate_keypairs(&mut prng, 10);
        let keypairs_refs = keypairs.iter().collect_vec();
        let mut pubkeys = keypairs.iter().map(|kp| &kp.pub_key).collect_vec();
        pubkeys.swap(1, 3);
        pubkeys.swap(4, 9);
        assert!(
            XfrMultiSig::sign(&keypairs_refs, &msg)
                .verify(&pubkeys, &msg)
                .is_ok(),
            "Multisignature should have verify correctly even when keylist is unordered"
        );
    }
}
