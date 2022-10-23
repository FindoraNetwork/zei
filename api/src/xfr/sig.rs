use crate::anon_xfr::keys::{AXfrPubKey, AXfrSecretKey};
use ark_serialize::{Flags, SWFlags};
use digest::consts::U64;
use ed25519_dalek::{
    ExpandedSecretKey, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey,
    Signature as Ed25519Signature, Signer, Verifier,
};
use libsecp256k1::{
    curve::{Affine as LibSecp256k1G1, FieldStorage, Scalar as LibSecp256k1Scalar},
    recover, sign as secp256k1_sign, verify as secp256k1_verify, Message,
    PublicKey as Secp256k1PublicKey, RecoveryId, SecretKey as Secp256k1SecretKey,
    Signature as Secp256k1Signature,
};
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;
use zei_algebra::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    prelude::*,
    ristretto::RistrettoScalar,
    secp256k1::{SECP256K1Scalar, SECP256K1G1},
};
use zei_crypto::basic::hybrid_encryption::{
    hybrid_decrypt_with_ed25519_secret_key, hybrid_encrypt_ed25519, ZeiHybridCiphertext,
};

/// The length of the secret key for confidential transfer.
pub const XFR_SECRET_KEY_LENGTH: usize = 33; // KeyType + 32 bytes

/// The length of the public key for confidential transfer.
pub const XFR_PUBLIC_KEY_LENGTH: usize = 34; // KeyType + 33 bytes

/// The length of the public key for confidential transfer.
pub const XFR_SIGNATURE_LENGTH: usize = 66; // KeyType + 64 bytes + 1 recovery

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Supported signature schemes.
pub enum KeyType {
    /// Ed25519
    Ed25519,
    /// Secp256k1
    Secp256k1,
    /// Secp256k1 address
    Address,
}

impl KeyType {
    /// Convert to u8.
    pub fn to_byte(&self) -> u8 {
        match self {
            KeyType::Ed25519 => 0,
            KeyType::Secp256k1 => 1,
            KeyType::Address => 2,
        }
    }

    /// Convert from u8.
    pub fn from_byte(byte: u8) -> KeyType {
        match byte {
            0u8 => KeyType::Ed25519,
            1u8 => KeyType::Secp256k1,
            2u8 => KeyType::Address,
            _ => KeyType::Ed25519,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[wasm_bindgen]
/// The public key wrapper for confidential transfer, for WASM compatability.
pub struct XfrPublicKey(pub(crate) XfrPublicKeyInner);

#[derive(Clone, Copy, Debug)]
/// The public key for confidential transfer.
pub enum XfrPublicKeyInner {
    /// Ed25519 Public Key
    Ed25519(Ed25519PublicKey),
    /// Secp256k1 Public Key
    Secp256k1(Secp256k1PublicKey),
    /// Hash of the secp256k1 public key.
    Address([u8; 20]),
}

impl Default for XfrPublicKey {
    fn default() -> Self {
        XfrPublicKey(XfrPublicKeyInner::Ed25519(Ed25519PublicKey::default()))
    }
}

#[derive(Debug)]
/// The secret key for confidential transfer.
pub enum XfrSecretKey {
    /// Ed25519 Secret Key
    Ed25519(Ed25519SecretKey),
    /// Secp256k1 Secret Key
    Secp256k1(Secp256k1SecretKey),
    /// Secp256k1 Secret Key with address
    Address(Secp256k1SecretKey),
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// The signature for confidential transfer.
pub enum XfrSignature {
    /// Ed25519 Signature
    Ed25519(Ed25519Signature),
    /// Secp256k1 Signature
    Secp256k1(Secp256k1Signature, RecoveryId),
    /// Secp256k1 Signature with recovery.
    /// params is r, s, v
    Address(Secp256k1Signature, RecoveryId),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
/// The keypair for confidential transfer.
pub struct XfrKeyPair {
    /// The public key.
    pub pub_key: XfrPublicKey,
    /// The secret key.
    pub(crate) sec_key: XfrSecretKey,
}

impl Eq for XfrPublicKey {}

impl PartialEq for XfrPublicKey {
    fn eq(&self, other: &XfrPublicKey) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Ord for XfrPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for XfrPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for XfrPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl XfrPublicKey {
    /// Get the reference of the inner type
    pub fn inner(&self) -> &XfrPublicKeyInner {
        &self.0
    }

    /// random a scalar and the compressed point.
    pub fn random_scalar_with_compressed_point<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
    ) -> (KeyType, Vec<u8>, Vec<u8>) {
        match self.0 {
            XfrPublicKeyInner::Ed25519(_) => {
                let (s, p) = RistrettoScalar::random_scalar_with_compressed_point(prng);
                (KeyType::Ed25519, s.to_bytes(), p.to_bytes().to_vec())
            }
            XfrPublicKeyInner::Secp256k1(_) | XfrPublicKeyInner::Address(_) => {
                let (s, p) = SECP256K1Scalar::random_scalar_with_compressed_point(prng);
                (KeyType::Secp256k1, s.to_bytes(), p.to_compressed_bytes())
            }
        }
    }

    /// Convert into the point format.
    pub fn as_compressed_point(&self) -> Vec<u8> {
        match self.0 {
            XfrPublicKeyInner::Ed25519(pk) => pk.as_bytes().to_vec(),
            XfrPublicKeyInner::Secp256k1(pk) => convert_point_libsecp256k1_to_algebra(&pk),
            XfrPublicKeyInner::Address(_) => panic!("Address not supported"),
        }
    }

    /// Hybrid encryption
    pub fn hybrid_encrypt<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        match self.0 {
            XfrPublicKeyInner::Ed25519(pk) => {
                Ok(hybrid_encrypt_ed25519(prng, &pk, msg).zei_to_bytes())
            }
            XfrPublicKeyInner::Secp256k1(pk) => {
                let bytes = convert_point_libsecp256k1_to_algebra(&pk);
                let gp = AXfrPubKey(SECP256K1G1::from_compressed_bytes(&bytes)?);
                let (p, mut ctext) = gp.encrypt(prng, msg)?;
                let mut bytes = vec![];
                bytes.append(&mut p.0.to_compressed_bytes());
                bytes.append(&mut ctext);
                Ok(bytes)
            }
            XfrPublicKeyInner::Address(_) => panic!("Address not supported"),
        }
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &XfrSignature) -> Result<()> {
        match (self.0, signature) {
            (XfrPublicKeyInner::Ed25519(pk), XfrSignature::Ed25519(sign)) => {
                pk.verify(message, sign).c(d!(ZeiError::SignatureError))
            }
            (XfrPublicKeyInner::Secp256k1(pk), XfrSignature::Secp256k1(sign, _)) => {
                let mut hasher = Keccak256::new();
                hasher.update(message);
                let res = hasher.finalize();
                let msg = Message::parse_slice(&res[..]).c(d!(ZeiError::SignatureError))?;
                if secp256k1_verify(&msg, sign, &pk) {
                    Ok(())
                } else {
                    Err(eg!(ZeiError::SignatureError))
                }
            }
            (XfrPublicKeyInner::Address(hash), XfrSignature::Address(sign, rec)) => {
                let mut hasher = Keccak256::new();
                hasher.update(message);
                let res = hasher.finalize();
                let msg = Message::parse_slice(&res[..]).c(d!(ZeiError::SignatureError))?;
                let pk = recover(&msg, sign, rec).c(d!(ZeiError::SignatureError))?;
                let other = convert_libsecp256k1_public_key_to_address(&pk);
                if hash == other {
                    Ok(())
                } else {
                    Err(eg!(ZeiError::SignatureError))
                }
            }
            _ => Err(eg!(ZeiError::SignatureError)),
        }
    }

    /// Convert into bytes.
    pub fn to_bytes(&self) -> [u8; XFR_PUBLIC_KEY_LENGTH] {
        let mut bytes = [0u8; XFR_PUBLIC_KEY_LENGTH];
        match self.0 {
            XfrPublicKeyInner::Ed25519(pk) => {
                bytes[0] = KeyType::Ed25519.to_byte();
                bytes[1..XFR_PUBLIC_KEY_LENGTH - 1].copy_from_slice(pk.as_bytes());
            }
            XfrPublicKeyInner::Secp256k1(pk) => {
                bytes[0] = KeyType::Secp256k1.to_byte();
                bytes[1..XFR_PUBLIC_KEY_LENGTH].copy_from_slice(&pk.serialize_compressed());
            }
            XfrPublicKeyInner::Address(hash) => {
                bytes[0] = KeyType::Address.to_byte();
                bytes[1..21].copy_from_slice(&hash);
            }
        }
        bytes
    }

    /// Convert from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Compatible with old data.
        if bytes.len() == XFR_PUBLIC_KEY_LENGTH - 2 {
            return Ok(XfrPublicKey(XfrPublicKeyInner::Ed25519(
                Ed25519PublicKey::from_bytes(bytes).c(d!(ZeiError::DeserializationError))?,
            )));
        }

        if bytes.len() != XFR_PUBLIC_KEY_LENGTH {
            return Err(eg!(ZeiError::DeserializationError));
        }

        let ktype = KeyType::from_byte(bytes[0]);
        match ktype {
            KeyType::Ed25519 => {
                let pk = Ed25519PublicKey::from_bytes(&bytes[1..XFR_PUBLIC_KEY_LENGTH - 1])
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrPublicKey(XfrPublicKeyInner::Ed25519(pk)))
            }
            KeyType::Secp256k1 => {
                let mut pk_bytes = [0u8; XFR_PUBLIC_KEY_LENGTH - 1];
                pk_bytes.copy_from_slice(&bytes[1..]);
                let pk = Secp256k1PublicKey::parse_compressed(&pk_bytes)
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrPublicKey(XfrPublicKeyInner::Secp256k1(pk)))
            }
            KeyType::Address => {
                let mut hash_bytes = [0u8; 20];
                hash_bytes.copy_from_slice(&bytes[1..21]);
                Ok(XfrPublicKey(XfrPublicKeyInner::Address(hash_bytes)))
            }
        }
    }

    /// Create a (fake) public key through hashing-to-curve from arbitrary bytes
    pub fn hash_from_bytes<D>(bytes: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let pk = Ed25519PublicKey::hash_from_bytes::<D>(bytes);
        Self(XfrPublicKeyInner::Ed25519(pk))
    }
}

impl Clone for XfrSecretKey {
    fn clone(&self) -> Self {
        Self::from_bytes(&self.to_bytes()).unwrap()
    }
}

impl Eq for XfrSecretKey {}

impl PartialEq for XfrSecretKey {
    fn eq(&self, other: &XfrSecretKey) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Ord for XfrSecretKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for XfrSecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for XfrSecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl XfrSecretKey {
    #[inline(always)]
    /// Convert into a keypair.
    pub fn into_keypair(self) -> XfrKeyPair {
        let pk = match self {
            XfrSecretKey::Ed25519(ref sk) => XfrPublicKey(XfrPublicKeyInner::Ed25519(sk.into())),
            XfrSecretKey::Secp256k1(ref sk) => XfrPublicKey(XfrPublicKeyInner::Secp256k1(
                Secp256k1PublicKey::from_secret_key(sk),
            )),
            XfrSecretKey::Address(ref sk) => {
                let pk = Secp256k1PublicKey::from_secret_key(sk);
                XfrPublicKey(XfrPublicKeyInner::Address(
                    convert_libsecp256k1_public_key_to_address(&pk),
                ))
            }
        };
        XfrKeyPair {
            pub_key: pk,
            sec_key: self,
        }
    }

    /// Hybrid decryption
    pub fn hybrid_decrypt(&self, lock: &[u8]) -> Result<Vec<u8>> {
        match self {
            XfrSecretKey::Ed25519(sk) => {
                let ctext = ZeiHybridCiphertext::zei_from_bytes(lock)?;
                Ok(hybrid_decrypt_with_ed25519_secret_key(&ctext, sk))
            }
            XfrSecretKey::Secp256k1(sk) => {
                let s: LibSecp256k1Scalar = (*sk).into();
                let bytes = convert_scalar_libsecp256k1_to_algebra(&s.0);
                let sk = AXfrSecretKey(SECP256K1Scalar::from_bytes(&bytes)?);
                let share = AXfrPubKey(SECP256K1G1::from_compressed_bytes(&lock[0..33])?);

                sk.decrypt(&share, &lock[33..])
            }
            XfrSecretKey::Address(_) => panic!("Address not supported"),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Result<XfrSignature> {
        match self {
            XfrSecretKey::Ed25519(sk) => {
                let sign = ed25519_dalek::Keypair::from(
                    Ed25519SecretKey::from_bytes(&sk.to_bytes()).unwrap(),
                )
                .sign(message);
                Ok(XfrSignature::Ed25519(sign))
            }
            XfrSecretKey::Secp256k1(sk) => {
                // If the Ethereum sign is used outside,
                // it needs to be dealt with first, only hash in zei.
                let mut hasher = Keccak256::new();
                hasher.update(message);
                let res = hasher.finalize();
                let msg = Message::parse_slice(&res[..]).c(d!(ZeiError::SignatureError))?;
                let (sign, rec) = secp256k1_sign(&msg, sk);
                Ok(XfrSignature::Secp256k1(sign, rec))
            }
            XfrSecretKey::Address(sk) => {
                // If the Ethereum sign is used outside,
                // it needs to be dealt with first, only hash in zei.
                let mut hasher = Keccak256::new();
                hasher.update(message);
                let res = hasher.finalize();
                let msg = Message::parse_slice(&res[..]).c(d!(ZeiError::SignatureError))?;
                let (sign, rec) = secp256k1_sign(&msg, sk);
                Ok(XfrSignature::Address(sign, rec))
            }
        }
    }

    /// Convert into scalar bytes.
    pub fn as_scalar_bytes(&self) -> (KeyType, Vec<u8>) {
        match self {
            XfrSecretKey::Ed25519(sk) => {
                let expanded: ExpandedSecretKey = (sk).into();
                let mut key_bytes = vec![];
                key_bytes.extend_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
                (KeyType::Ed25519, key_bytes)
            }
            XfrSecretKey::Secp256k1(sk) => {
                let s: LibSecp256k1Scalar = (*sk).into();
                (
                    KeyType::Secp256k1,
                    convert_scalar_libsecp256k1_to_algebra(&s.0),
                )
            }
            XfrSecretKey::Address(sk) => {
                let s: LibSecp256k1Scalar = (*sk).into();
                (
                    KeyType::Address,
                    convert_scalar_libsecp256k1_to_algebra(&s.0),
                )
            }
        }
    }

    /// Convert into bytes.
    pub fn to_bytes(&self) -> [u8; XFR_SECRET_KEY_LENGTH] {
        let mut bytes = [0u8; XFR_SECRET_KEY_LENGTH];
        match self {
            XfrSecretKey::Ed25519(sk) => {
                bytes[0] = KeyType::Ed25519.to_byte();
                bytes[1..].copy_from_slice(sk.as_bytes());
            }
            XfrSecretKey::Secp256k1(sk) => {
                bytes[0] = KeyType::Secp256k1.to_byte();
                bytes[1..].copy_from_slice(&sk.serialize());
            }
            XfrSecretKey::Address(sk) => {
                bytes[0] = KeyType::Address.to_byte();
                bytes[1..].copy_from_slice(&sk.serialize());
            }
        }
        bytes
    }

    /// Convert from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Compatible with old data.
        if bytes.len() == XFR_SECRET_KEY_LENGTH - 1 {
            return Ok(XfrSecretKey::Ed25519(
                Ed25519SecretKey::from_bytes(bytes).c(d!(ZeiError::DeserializationError))?,
            ));
        }

        if bytes.len() != XFR_SECRET_KEY_LENGTH {
            return Err(eg!(ZeiError::DeserializationError));
        }

        let ktype = KeyType::from_byte(bytes[0]);
        match ktype {
            KeyType::Ed25519 => {
                let sk = Ed25519SecretKey::from_bytes(&bytes[1..])
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrSecretKey::Ed25519(sk))
            }
            KeyType::Secp256k1 => {
                let sk = Secp256k1SecretKey::parse_slice(&bytes[1..])
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrSecretKey::Secp256k1(sk))
            }
            KeyType::Address => {
                let sk = Secp256k1SecretKey::parse_slice(&bytes[1..])
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrSecretKey::Address(sk))
            }
        }
    }

    /// Convert from raw bytes used secp256k1 and use it with address.
    pub fn from_secp256k1_with_address(bytes: &[u8]) -> Result<Self> {
        let sk = Secp256k1SecretKey::parse_slice(bytes).c(d!(ZeiError::DeserializationError))?;
        Ok(XfrSecretKey::Address(sk))
    }
}

impl XfrKeyPair {
    /// Default generate a key pair.
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self::generate_secp256k1(prng)
    }

    /// Generate a Ed25519 key pair.
    pub fn generate_ed25519<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let kp = ed25519_dalek::Keypair::generate(prng);
        XfrKeyPair {
            pub_key: XfrPublicKey(XfrPublicKeyInner::Ed25519(kp.public)),
            sec_key: XfrSecretKey::Ed25519(kp.secret_key()),
        }
    }

    /// Generate a Secp256k1 key pair.
    pub fn generate_secp256k1<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let sk = Secp256k1SecretKey::random(prng);
        let pk = Secp256k1PublicKey::from_secret_key(&sk);
        XfrKeyPair {
            pub_key: XfrPublicKey(XfrPublicKeyInner::Secp256k1(pk)),
            sec_key: XfrSecretKey::Secp256k1(sk),
        }
    }

    /// Generate a key pair from secret key bytes.
    pub fn generate_secp256k1_from_bytes(bytes: &[u8]) -> Result<Self> {
        let sk = Secp256k1SecretKey::parse_slice(bytes).c(d!())?;
        let pk = Secp256k1PublicKey::from_secret_key(&sk);
        Ok(XfrKeyPair {
            pub_key: XfrPublicKey(XfrPublicKeyInner::Secp256k1(pk)),
            sec_key: XfrSecretKey::Secp256k1(sk),
        })
    }

    /// Generate a Secp256k1 key pair with address.
    pub fn generate_address<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let sk = Secp256k1SecretKey::random(prng);
        let pk = Secp256k1PublicKey::from_secret_key(&sk);
        XfrKeyPair {
            pub_key: XfrPublicKey(XfrPublicKeyInner::Address(
                convert_libsecp256k1_public_key_to_address(&pk),
            )),
            sec_key: XfrSecretKey::Address(sk),
        }
    }

    /// Hybrid decryption
    pub fn hybrid_decrypt(&self, lock: &[u8]) -> Result<Vec<u8>> {
        self.sec_key.hybrid_decrypt(lock)
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Result<XfrSignature> {
        self.sec_key.sign(msg)
    }

    #[inline(always)]
    /// Return the public key.
    pub fn get_pk(&self) -> XfrPublicKey {
        self.pub_key
    }

    #[inline(always)]
    /// Return a reference of the public key.
    pub fn get_pk_ref(&self) -> &XfrPublicKey {
        &self.pub_key
    }

    #[inline(always)]
    /// Return the secret key.
    pub fn get_sk(&self) -> XfrSecretKey {
        self.sec_key.clone()
    }

    #[inline(always)]
    /// Return a reference of the secret key.
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
            sec_key: XfrSecretKey::zei_from_bytes(&bytes[0..XFR_SECRET_KEY_LENGTH]).c(d!())?,
            pub_key: XfrPublicKey::zei_from_bytes(&bytes[XFR_SECRET_KEY_LENGTH..]).c(d!())?,
        })
    }
}

impl XfrSignature {
    /// Convert into bytes.
    pub fn to_bytes(&self) -> [u8; XFR_SIGNATURE_LENGTH] {
        let mut bytes = [0u8; XFR_SIGNATURE_LENGTH];
        match self {
            XfrSignature::Ed25519(sign) => {
                bytes[0] = KeyType::Ed25519.to_byte();
                bytes[1..XFR_SIGNATURE_LENGTH - 1].copy_from_slice(&sign.to_bytes());
            }
            XfrSignature::Secp256k1(sign, rec) => {
                bytes[0] = KeyType::Secp256k1.to_byte();
                bytes[1..XFR_SIGNATURE_LENGTH - 1].copy_from_slice(&sign.serialize());
                bytes[XFR_SIGNATURE_LENGTH - 1] = rec.serialize();
            }
            XfrSignature::Address(sign, rec) => {
                bytes[0] = KeyType::Address.to_byte();
                bytes[1..XFR_SIGNATURE_LENGTH - 1].copy_from_slice(&sign.serialize());
                bytes[XFR_SIGNATURE_LENGTH - 1] = rec.serialize();
            }
        }
        bytes
    }

    /// Convert from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Compatible with old data.
        if bytes.len() == XFR_SIGNATURE_LENGTH - 2 {
            let sign = Ed25519Signature::from_bytes(bytes).c(d!(ZeiError::DeserializationError))?;
            return Ok(XfrSignature::Ed25519(sign));
        }

        if bytes.len() != XFR_SIGNATURE_LENGTH {
            return Err(eg!(ZeiError::DeserializationError));
        }

        let ktype = KeyType::from_byte(bytes[0]);
        match ktype {
            KeyType::Ed25519 => {
                let sign = Ed25519Signature::from_bytes(&bytes[1..XFR_SIGNATURE_LENGTH - 1])
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrSignature::Ed25519(sign))
            }
            KeyType::Secp256k1 => {
                let mut s_bytes = [0u8; XFR_SIGNATURE_LENGTH - 2];
                s_bytes.copy_from_slice(&bytes[1..XFR_SIGNATURE_LENGTH - 1]);
                let sign = Secp256k1Signature::parse_standard(&s_bytes)
                    .c(d!(ZeiError::DeserializationError))?;
                let rec = RecoveryId::parse(bytes[XFR_SIGNATURE_LENGTH - 1])
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrSignature::Secp256k1(sign, rec))
            }
            KeyType::Address => {
                let mut s_bytes = [0u8; XFR_SIGNATURE_LENGTH - 2];
                s_bytes.copy_from_slice(&bytes[1..XFR_SIGNATURE_LENGTH - 1]);
                let sign = Secp256k1Signature::parse_standard(&s_bytes)
                    .c(d!(ZeiError::DeserializationError))?;
                let rec = RecoveryId::parse(bytes[XFR_SIGNATURE_LENGTH - 1])
                    .c(d!(ZeiError::DeserializationError))?;
                Ok(XfrSignature::Address(sign, rec))
            }
        }
    }
}

/// Multisignatures (aka multisig), which is now a list of signatures under each signer.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrMultiSig {
    /// The list of signatures.
    pub signatures: Vec<XfrSignature>,
}

impl XfrMultiSig {
    /// Sign a multisig under a list of key pairs.
    pub fn sign(keypairs: &[&XfrKeyPair], message: &[u8]) -> Result<Self> {
        // sort the key pairs based on alphabetical order of their public keys
        let mut sorted = keypairs.to_owned();
        sorted.sort_unstable_by_key(|kp| kp.pub_key.zei_to_bytes());
        let mut signatures = vec![];
        for kp in sorted {
            signatures.push(kp.sign(message)?);
        }
        Ok(XfrMultiSig { signatures })
    }

    /// Verify a multisig.
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

/// Function helper for get recovery id from u64.
pub fn recovery_id_from_u64(v: u64) -> u8 {
    match v {
        27 => 0,
        28 => 1,
        v if v >= 35 => ((v - 1) % 2) as u8,
        _ => v as u8,
    }
}

/// Function helper for convert secp256k1 public key to address.
pub fn convert_libsecp256k1_public_key_to_address(pk: &Secp256k1PublicKey) -> [u8; 20] {
    let public_key = pk.serialize();
    debug_assert_eq!(public_key[0], 0x04);
    let mut hasher = Keccak256::new();
    hasher.update(&public_key[1..]);
    let result = hasher.finalize();
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&result[12..]);
    bytes
}

fn convert_point_libsecp256k1_to_algebra(pk: &Secp256k1PublicKey) -> Vec<u8> {
    let p: LibSecp256k1G1 = (*pk).into();
    let (mut x, mut y) = (p.x, p.y);
    x.normalize();
    y.normalize();
    let f: FieldStorage = (x).into();
    let mut bytes = convert_scalar_libsecp256k1_to_algebra(&f.0);
    let mut y_neg = y.neg(1);
    y_neg.normalize();
    let flag = if y >= y_neg {
        SWFlags::PositiveY.u8_bitmask()
    } else {
        SWFlags::NegativeY.u8_bitmask()
    };
    bytes.push(flag);
    bytes
}

fn convert_scalar_libsecp256k1_to_algebra(b: &[u32; 8]) -> Vec<u8> {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&b[0].to_le_bytes());
    bytes[4..8].copy_from_slice(&b[1].to_le_bytes());
    bytes[8..12].copy_from_slice(&b[2].to_le_bytes());
    bytes[12..16].copy_from_slice(&b[3].to_le_bytes());
    bytes[16..20].copy_from_slice(&b[4].to_le_bytes());
    bytes[20..24].copy_from_slice(&b[5].to_le_bytes());
    bytes[24..28].copy_from_slice(&b[6].to_le_bytes());
    bytes[28..32].copy_from_slice(&b[7].to_le_bytes());
    bytes.to_vec()
}

#[cfg(test)]
mod test {
    use crate::xfr::sig::{XfrKeyPair, XfrMultiSig, XfrPublicKeyInner, XfrSecretKey};
    use ark_std::{env, test_rng};
    use ruc::err::*;
    use zei_algebra::prelude::*;

    #[test]
    fn signatures() {
        env::set_var("DETERMINISTIC_TEST_RNG", "1");
        let mut prng = test_rng();

        let keypair = XfrKeyPair::generate_secp256k1(&mut prng);
        let message = "";

        let sig = keypair.sign(message.as_bytes()).unwrap();
        pnk!(keypair.pub_key.verify("".as_bytes(), &sig));
        //same test with secret key
        let sig = keypair.sec_key.sign(message.as_bytes()).unwrap();
        pnk!(keypair.pub_key.verify("".as_bytes(), &sig));

        //test again with fresh same key
        let mut prng = test_rng();
        let keypair = XfrKeyPair::generate_secp256k1(&mut prng);
        pnk!(keypair.pub_key.verify("".as_bytes(), &sig));

        env::set_var("DETERMINISTIC_TEST_RNG", "0");
        let mut prng = test_rng();
        let keypair = XfrKeyPair::generate_ed25519(&mut prng);
        let message = [10u8; 500];
        let sig = keypair.sign(&message).unwrap();
        msg_eq!(
            dbg!(ZeiError::SignatureError),
            dbg!(keypair.pub_key.verify("".as_bytes(), &sig).unwrap_err()),
            "Verifying sig on different message should have return Err(Signature Error)"
        );
        pnk!(keypair.pub_key.verify(&message, &sig));
        //test again with secret key
        let sig = keypair.sec_key.sign(&message).unwrap();
        msg_eq!(
            ZeiError::SignatureError,
            keypair.pub_key.verify("".as_bytes(), &sig).unwrap_err(),
            "Verifying sig on different message should have return Err(Signature Error)"
        );
        pnk!(keypair.pub_key.verify(&message, &sig));

        // test with different keys
        let keypair = XfrKeyPair::generate_ed25519(&mut prng);
        msg_eq!(
            ZeiError::SignatureError,
            keypair.pub_key.verify(&message, &sig).unwrap_err(),
            "Verifying sig on with a different key should have return Err(Signature Error)"
        );
    }

    fn generate_keypairs<R: CryptoRng + RngCore>(prng: &mut R, n: usize) -> Vec<XfrKeyPair> {
        let mut v = vec![];
        for _ in 0..n {
            v.push(XfrKeyPair::generate_secp256k1(prng));
        }
        v
    }

    #[test]
    fn secp256k1_address() {
        let sk = "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";
        let address = "8626f6940e2eb28930efb4cef49b2d1f2c9c1199";
        let xs = XfrSecretKey::from_secp256k1_with_address(&hex::decode(sk).unwrap()).unwrap();
        let kp = xs.into_keypair();
        match kp.pub_key.0 {
            XfrPublicKeyInner::Address(hash) => {
                assert_eq!(hash.to_vec(), hex::decode(address).unwrap())
            }
            _ => panic!("not secp256k1 address"),
        }
        let sign = kp.sign(b"message").unwrap();
        kp.pub_key.verify(b"message", &sign).unwrap();
    }

    #[test]
    fn multisig() {
        let mut prng = test_rng();
        let msg = b"random message here!".to_vec();
        // test with one key
        let keypairs = generate_keypairs(&mut prng, 1);
        let keypairs_refs = keypairs.iter().collect_vec();
        let pubkeys = keypairs.iter().map(|kp| &kp.pub_key).collect_vec();
        assert!(
            XfrMultiSig::sign(&keypairs_refs, &msg)
                .unwrap()
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
                .unwrap()
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
                .unwrap()
                .verify(&pubkeys, &msg)
                .is_ok(),
            "Multisignature should have verify correctly even when keylist is unordered"
        );
    }
}
