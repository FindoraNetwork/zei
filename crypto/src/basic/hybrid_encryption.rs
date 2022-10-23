use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Aes256,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey};
use serde::Serializer;
use sha2::Digest;
use wasm_bindgen::prelude::*;
use zei_algebra::errors::ZeiError;
use zei_algebra::prelude::*;
use zei_algebra::ristretto::RistrettoScalar;

type Aes256Ctr = ctr::Ctr64BE<Aes256>;

#[wasm_bindgen]
#[derive(Debug, Clone)]
/// The public key for the hybrid encryption scheme.
pub struct XPublicKey {
    pub(crate) key: x25519_dalek::PublicKey,
}

impl ZeiFromToBytes for XPublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let mut array = [0u8; 32];
            array.copy_from_slice(bytes);
            Ok(XPublicKey {
                key: x25519_dalek::PublicKey::from(array),
            })
        }
    }
}

serialize_deserialize!(XPublicKey);

impl XPublicKey {
    /// Derive the public key from the secret key.
    pub fn from(sk: &XSecretKey) -> XPublicKey {
        XPublicKey {
            key: x25519_dalek::PublicKey::from(&sk.key),
        }
    }
}

impl PartialEq for XPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.as_bytes() == other.key.as_bytes()
    }
}

impl Eq for XPublicKey {}

#[wasm_bindgen]
#[derive(Clone)]
/// The secret key for the hybrid encryption scheme.
pub struct XSecretKey {
    pub(crate) key: x25519_dalek::StaticSecret,
}

impl ZeiFromToBytes for XSecretKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let mut array = [0u8; 32];
            array.copy_from_slice(bytes);
            Ok(XSecretKey {
                key: x25519_dalek::StaticSecret::from(array),
            })
        }
    }
}

serialize_deserialize!(XSecretKey);

impl XSecretKey {
    /// Create a new secret key for x25519.
    pub fn new<R: CryptoRng + RngCore>(prng: &mut R) -> XSecretKey {
        XSecretKey {
            key: x25519_dalek::StaticSecret::new(prng),
        }
    }
}

impl PartialEq for XSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.to_bytes() == other.key.to_bytes()
    }
}

impl Eq for XSecretKey {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// The ciphertext from the symmetric encryption.
pub struct Ctext(pub Vec<u8>);
impl ZeiFromToBytes for Ctext {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Ctext(bytes.to_vec()))
    }
}
serialize_deserialize!(Ctext);

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
/// A ciphertext of hybrid encryption.
pub struct ZeiHybridCiphertext {
    pub(crate) ciphertext: Ctext,
    pub(crate) ephemeral_public_key: XPublicKey,
}

impl ZeiFromToBytes for ZeiHybridCiphertext {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.ephemeral_public_key.zei_to_bytes());
        bytes.append(&mut self.ciphertext.zei_to_bytes());
        bytes
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let ephemeral_public_key = XPublicKey::zei_from_bytes(&bytes[0..32])?;
            let ciphertext = Ctext::zei_from_bytes(&bytes[32..])?;
            Ok(Self {
                ciphertext,
                ephemeral_public_key,
            })
        }
    }
}

/// Encrypt a message over X25519
pub fn hybrid_encrypt_x25519<R: CryptoRng + RngCore>(
    prng: &mut R,
    pub_key: &XPublicKey,
    message: &[u8],
) -> ZeiHybridCiphertext {
    let (key, ephemeral_key) = symmetric_key_from_x25519_public_key(prng, &pub_key.key);
    let ciphertext = symmetric_encrypt(&key, message);
    ZeiHybridCiphertext {
        ciphertext,
        ephemeral_public_key: XPublicKey { key: ephemeral_key },
    }
}

/// Encrypt a message over Ed25519
pub fn hybrid_encrypt_ed25519<R: CryptoRng + RngCore>(
    prng: &mut R,
    pub_key: &PublicKey,
    message: &[u8],
) -> ZeiHybridCiphertext {
    let (key, ephemeral_key) = symmetric_key_from_ed25519_public_key(prng, pub_key);
    let ciphertext = symmetric_encrypt(&key, message);

    ZeiHybridCiphertext {
        ciphertext,
        ephemeral_public_key: XPublicKey { key: ephemeral_key },
    }
}

/// Decrypt a hybrid ciphertext over X25519
pub fn hybrid_decrypt_with_x25519_secret_key(
    ctext: &ZeiHybridCiphertext,
    sec_key: &XSecretKey,
) -> Vec<u8> {
    let key = symmetric_key_from_x25519_secret_key(&sec_key.key, &ctext.ephemeral_public_key.key);
    symmetric_decrypt(&key, &ctext.ciphertext)
}

/// Decrypt a hybrid ciphertext over Ed25519
pub fn hybrid_decrypt_with_ed25519_secret_key(
    ctext: &ZeiHybridCiphertext,
    sec_key: &SecretKey,
) -> Vec<u8> {
    let key = symmetric_key_from_ed25519_secret_key(sec_key, &ctext.ephemeral_public_key.key);
    symmetric_decrypt(&key, &ctext.ciphertext)
}

/// Convert the shared secret to a symmetric key
fn shared_secret_to_symmetric_key(shared_secret: &x25519_dalek::SharedSecret) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(shared_secret.as_bytes());
    let hash = hasher.finalize();
    let mut symmetric_key = [0u8; 32];
    symmetric_key.copy_from_slice(hash.as_slice());
    symmetric_key
}

/// Derive a symmetric key from an X25519 public key
fn symmetric_key_from_x25519_public_key<R: CryptoRng + RngCore>(
    prng: &mut R,
    public_key: &x25519_dalek::PublicKey,
) -> ([u8; 32], x25519_dalek::PublicKey) {
    // simulate a DH key exchange
    let ephemeral = x25519_dalek::EphemeralSecret::new(prng);
    let dh_pk = x25519_dalek::PublicKey::from(&ephemeral);

    let shared = ephemeral.diffie_hellman(public_key);

    let symmetric_key = shared_secret_to_symmetric_key(&shared);
    (symmetric_key, dh_pk)
}

/// Derive a symmetric key from an Ed25519 public key
fn symmetric_key_from_ed25519_public_key<R>(
    prng: &mut R,
    public_key: &PublicKey,
) -> ([u8; 32], x25519_dalek::PublicKey)
where
    R: CryptoRng + RngCore,
{
    let pk_curve_point = CompressedEdwardsY::from_slice(public_key.as_bytes());
    let pk_montgomery = pk_curve_point.decompress().unwrap().to_montgomery();
    let x_public_key = x25519_dalek::PublicKey::from(pk_montgomery.to_bytes());

    symmetric_key_from_x25519_public_key(prng, &x_public_key)
}

fn sec_key_as_scalar(sk: &SecretKey) -> RistrettoScalar {
    let expanded: ExpandedSecretKey = sk.into();
    //expanded.key is not public, I need to extract it via serialization
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&expanded.to_bytes()[0..32]); //1st 32 bytes are key
    RistrettoScalar::from_bytes(&key_bytes).unwrap() // safe unwrap
}

/// Derive a symmetric key from a secret key over X25519
fn symmetric_key_from_x25519_secret_key(
    sec_key: &x25519_dalek::StaticSecret,
    ephemeral_public_key: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    let shared_key = sec_key.diffie_hellman(ephemeral_public_key);
    shared_secret_to_symmetric_key(&shared_key)
}

/// Derive a symmetric key from a secret key over Ed25519
fn symmetric_key_from_ed25519_secret_key(
    sec_key: &SecretKey,
    ephemeral_public_key: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    let scalar_sec_key = sec_key_as_scalar(sec_key);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(scalar_sec_key.to_bytes().as_slice());
    let x_secret = x25519_dalek::StaticSecret::from(bytes);
    symmetric_key_from_x25519_secret_key(&x_secret, ephemeral_public_key)
}

fn symmetric_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Ctext {
    let kkey = GenericArray::from_slice(key);
    let ctr = GenericArray::from_slice(&[0u8; 16]); // counter can be zero because key is fresh
    let mut ctext_vec = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new(kkey, ctr);
    cipher.apply_keystream(ctext_vec.as_mut_slice());
    Ctext(ctext_vec)
}

fn symmetric_decrypt(key: &[u8; 32], ciphertext: &Ctext) -> Vec<u8> {
    let kkey = GenericArray::from_slice(key);
    let ctr = GenericArray::from_slice(&[0u8; 16]);
    let mut plaintext_vec = ciphertext.0.clone();
    let mut cipher = Aes256Ctr::new(kkey, ctr);
    cipher.apply_keystream(plaintext_vec.as_mut_slice());
    plaintext_vec
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::test_rng;
    use ed25519_dalek::Keypair;

    #[test]
    fn key_derivation() {
        let mut prng = test_rng();
        let keypair = Keypair::generate(&mut prng);
        let (from_pk_key, encoded_rand) =
            symmetric_key_from_ed25519_public_key(&mut prng, &keypair.public);
        let from_sk_key =
            symmetric_key_from_ed25519_secret_key(&keypair.secret_key(), &encoded_rand);
        assert_eq!(from_pk_key, from_sk_key);
    }

    #[test]
    fn symmetric_encryption_fresh_key() {
        let msg = b"this is a message";
        let key: [u8; 32] = [0u8; 32];
        let mut ciphertext = symmetric_encrypt(&key, msg);
        let decrypted = symmetric_decrypt(&key, &ciphertext);
        assert_eq!(msg, decrypted.as_slice());

        ciphertext.0[0] = 0xFF - ciphertext.0[0];
        let result = symmetric_decrypt(&key, &ciphertext);
        assert_ne!(msg, result.as_slice());
    }

    #[test]
    fn hybrid_cipher() {
        let mut prng = test_rng();
        let key_pair = Keypair::generate(&mut prng);
        let msg = b"this is another message";

        let cipherbox = hybrid_encrypt_ed25519(&mut prng, &key_pair.public, msg);
        let plaintext = hybrid_decrypt_with_ed25519_secret_key(&cipherbox, &key_pair.secret_key());
        assert_eq!(msg, plaintext.as_slice());
    }
}
