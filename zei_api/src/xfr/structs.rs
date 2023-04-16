extern crate serde_str;

use crate::api::anon_creds::{
    ACConfidentialRevealProof, ACIssuerPublicKey, AttributeCiphertext, AttributeDecKey,
    AttributeEncKey,
};
use crate::xfr::asset_mixer::AssetMixProof;
use crate::xfr::asset_record::AssetRecordType;
use crate::xfr::asset_tracer::{
    RecordDataCiphertext, RecordDataDecKey, RecordDataEncKey,
};
use crate::xfr::sig::{XfrKeyPair, XfrMultiSig, XfrPublicKey};
use algebra::bls12_381::BLSG1;
use algebra::groups::{Group, Scalar as ZeiScalar};
use algebra::ristretto::{
    CompressedEdwardsY, CompressedRistretto, RistrettoPoint, RistrettoScalar as Scalar,
};
use bulletproofs::RangeProof;
use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
use crypto::basics::elgamal::elgamal_key_gen;
use crypto::basics::hybrid_encryption::{self, XPublicKey, XSecretKey, ZeiHybridCipher};
use crypto::chaum_pedersen::ChaumPedersenProofX;
use crypto::pedersen_elgamal::PedersenElGamalEqProof;
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use sha2::Sha512;
use utils::errors::ZeiError;
use utils::serialization;

/// Asset Type identifier
pub const ASSET_TYPE_LENGTH: usize = 32;

#[derive(
    Deserialize,
    Serialize,
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Ord,
)]
pub struct AssetType(pub [u8; ASSET_TYPE_LENGTH]);

impl AssetType {
    /// Helper function to generate an asset type with identical value in each byte
    pub fn from_identical_byte(byte: u8) -> Self {
        Self([byte; ASSET_TYPE_LENGTH])
    }

    /// converts AssetType into a Scalar
    pub fn as_scalar<S: ZeiScalar>(&self) -> S {
        let repr = AssetTypeZeiRepr::from(self);
        repr.as_scalar()
    }
}

/// Asset type prepresentation length. must be less than MIN_SCALAR_LEN
/// All scalars in this code base are representable by 32 bytes, but
/// values are less than 2^256 -1
pub(crate) const ASSET_TYPE_ZEI_REPR_LENGTH: usize = 30;
/// Scalar representation length for JubjubScalar, RistrettoScalar and BlsScalar
pub(crate) const MIN_SCALAR_LENGTH: usize = 32;

/// Internal representation of asset types
/// Representable by any >= ASSET_TYPE_ZEI_REPR_LENGTH bytes scalar via little endian
/// Last MIN_SCALAR_LENGTH - ASSET_TYPE_ZEI_REPR_LENGTH are 0
pub(crate) struct AssetTypeZeiRepr([u8; MIN_SCALAR_LENGTH]);

/// Hash public AssetType into an internal representation that allows
/// to represent the asset_type in different scalars fields
impl<'a> From<&'a AssetType> for AssetTypeZeiRepr {
    fn from(asset_type: &'a AssetType) -> Self {
        let mut hash = sha2::Sha256::default();
        hash.update(&asset_type.0);
        let array = hash.finalize();
        let mut zei_repr = [0u8; MIN_SCALAR_LENGTH];
        zei_repr[0..ASSET_TYPE_ZEI_REPR_LENGTH]
            .copy_from_slice(&array[0..ASSET_TYPE_ZEI_REPR_LENGTH]);
        AssetTypeZeiRepr(zei_repr)
    }
}

impl AssetTypeZeiRepr {
    pub(crate) fn as_scalar<S: ZeiScalar>(&self) -> S {
        // interpret AssetTypeZeiRepr bytes as a little endian scalar that fits in S's representation
        // JubjubScalar, BlsScalar and RistrettoScalar have length MIN_SCALAR_LENGTH
        // but in case anther scalar length is larger then we can set to 0 high order bytes
        if MIN_SCALAR_LENGTH == S::bytes_len() {
            return S::from_le_bytes(&self.0).unwrap(); //safe unwrap
        }
        let mut v = vec![0u8; S::bytes_len()];
        v[0..ASSET_TYPE_ZEI_REPR_LENGTH].copy_from_slice(&self.0);
        S::from_le_bytes(&v).unwrap()
    }
}
/// A Transfer note: contains a transfer body and a (multi)signature
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrNote {
    pub body: XfrBody,
    pub multisig: XfrMultiSig,
}

impl XfrNote {
    pub fn outputs_iter(&self) -> std::slice::Iter<BlindAssetRecord> {
        self.body.outputs.iter()
    }
}

/// A Transfer's body: contains a inputs, outputs, proofs and messages to participants (asset tracer and output owners)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrBody {
    pub inputs: Vec<BlindAssetRecord>,
    pub outputs: Vec<BlindAssetRecord>,
    pub proofs: XfrProofs,
    pub asset_tracing_memos: Vec<Vec<TracerMemo>>, // each input or output can have a set of tracing memos
    pub owners_memos: Vec<Option<OwnerMemo>>, // If confidential amount or asset type, lock the amount and/or asset type to the public key in asset_record
}

/// A transfer input or output record as seen in the ledger
/// Amount and asset type can be confidential or non confidential
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlindAssetRecord {
    pub amount: XfrAmount,        // Amount being transferred
    pub asset_type: XfrAssetType, // Asset type being transferred
    pub public_key: XfrPublicKey, // ownership address
}

impl BlindAssetRecord {
    pub fn get_record_type(&self) -> AssetRecordType {
        AssetRecordType::from_flags(
            matches!(self.amount, XfrAmount::Confidential(_)),
            matches!(self.asset_type, XfrAssetType::Confidential(_)),
        )
    }

    // TODO: (alex) remove this if the concept of public v.s. hidden asset are no longer in use
    /// returns true if it is a "public record" where both amount and asset type are non-confidential
    pub fn is_public(&self) -> bool {
        matches!(
            self.get_record_type(),
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        )
    }
}

/// Amount in blind asset record: if confidential, provide commitments for lower and hight 32 bits
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum XfrAmount {
    // amount is a 64 bit positive integer expressed in base 2^32 in confidential transactions
    Confidential((CompressedRistretto, CompressedRistretto)),
    #[serde(with = "serde_str")]
    NonConfidential(u64),
}

impl XfrAmount {
    /// Returns true only if amount is confidential
    /// # Example:
    /// ```
    /// use zei::xfr::structs::XfrAmount;
    /// use algebra::ristretto::CompressedRistretto;
    /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
    /// assert!(xfr_amount.is_confidential());
    /// let xfr_amount = XfrAmount::NonConfidential(100u64);
    /// assert!(!xfr_amount.is_confidential());
    /// ```
    pub fn is_confidential(&self) -> bool {
        matches!(self, XfrAmount::Confidential(_))
    }
    /// Return Some(amount) if amount is non-confidential. Otherwise, return None
    /// # Example:
    /// ```
    /// use zei::xfr::structs::XfrAmount;
    /// use algebra::ristretto::CompressedRistretto;
    /// let xfr_amount = XfrAmount::NonConfidential(100u64);
    /// assert_eq!(xfr_amount.get_amount().unwrap(), 100u64);
    /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
    /// assert!(xfr_amount.get_amount().is_none());
    /// ```
    pub fn get_amount(&self) -> Option<u64> {
        match self {
            XfrAmount::NonConfidential(x) => Some(*x),
            _ => None,
        }
    }

    /// Return Some((c1,c2)), where (c1,c2) is a commitment to the amount
    /// if amount is confidential. Otherwise, return None
    /// # Example:
    /// ```
    /// use zei::xfr::structs::XfrAmount;
    /// use algebra::ristretto::CompressedRistretto;
    /// let xfr_amount = XfrAmount::NonConfidential(100u64);
    /// assert!(xfr_amount.get_commitments().is_none());
    /// let xfr_amount = XfrAmount::Confidential((CompressedRistretto::default(), CompressedRistretto::default()));
    /// assert_eq!(xfr_amount.get_commitments().unwrap(), (CompressedRistretto::default(), CompressedRistretto::default()));
    /// ```
    pub fn get_commitments(&self) -> Option<(CompressedRistretto, CompressedRistretto)> {
        match self {
            XfrAmount::Confidential(x) => Some(*x),
            _ => None,
        }
    }

    /// construct a confidential XfrAmount with amount and amount blinds
    pub fn from_blinds(
        pc_gens: &RistrettoPedersenGens,
        amount: u64,
        blind_lo: &Scalar,
        blind_hi: &Scalar,
    ) -> Self {
        let (amount_lo, amount_hi) = utils::u64_to_u32_pair(amount);
        let comm_lo = pc_gens
            .commit(Scalar::from_u32(amount_lo), *blind_lo)
            .compress();
        let comm_hi = pc_gens
            .commit(Scalar::from_u32(amount_hi), *blind_hi)
            .compress();
        XfrAmount::Confidential((comm_lo, comm_hi))
    }
}

/// Asset type in BlindAsset record: if confidential, provide commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum XfrAssetType {
    Confidential(CompressedRistretto),
    NonConfidential(AssetType),
}

impl XfrAssetType {
    /// Returns true only if amount is confidential
    /// # Example:
    /// ```
    /// use zei::xfr::structs::{AssetType, XfrAssetType};
    /// use algebra::ristretto::CompressedRistretto;
    /// let xfr_asset_type = XfrAssetType::Confidential(CompressedRistretto::default());
    /// assert!(xfr_asset_type.is_confidential());
    /// let xfr_asset_type = XfrAssetType::NonConfidential(AssetType::from_identical_byte(0u8));
    /// assert!(!xfr_asset_type.is_confidential());
    /// ```
    pub fn is_confidential(&self) -> bool {
        matches!(self, XfrAssetType::Confidential(_))
    }

    /// Return Some(asset_type) if asset_type is non-confidential. Otherwise, return None
    /// # Example:
    /// ```
    /// use zei::xfr::structs::{AssetType, XfrAssetType};
    /// use algebra::ristretto::CompressedRistretto;
    /// let xfr_asset_type = XfrAssetType::NonConfidential(AssetType::from_identical_byte(0u8));
    /// assert_eq!(xfr_asset_type.get_asset_type().unwrap(), AssetType::from_identical_byte(0u8));
    /// let xfr_asset_type = XfrAssetType::Confidential(CompressedRistretto::default());
    /// assert!(xfr_asset_type.get_asset_type().is_none());
    /// ```
    pub fn get_asset_type(&self) -> Option<AssetType> {
        match self {
            XfrAssetType::NonConfidential(x) => Some(*x),
            _ => None,
        }
    }

    /// Return Some(c), where c is a commitment to the asset_type
    /// if asset_type is confidential. Otherwise, return None
    /// # Example:
    /// ```
    /// use zei::xfr::structs::{AssetType, XfrAssetType};
    /// use algebra::ristretto::CompressedRistretto;
    /// let xfr_asset_type = XfrAssetType::NonConfidential(AssetType::from_identical_byte(0u8));
    /// assert!(xfr_asset_type.get_commitment().is_none());
    /// let xfr_amount = XfrAssetType::Confidential(CompressedRistretto::default());
    /// assert_eq!(xfr_amount.get_commitment().unwrap(), CompressedRistretto::default());
    /// ```
    pub fn get_commitment(&self) -> Option<CompressedRistretto> {
        match self {
            XfrAssetType::Confidential(x) => Some(*x),
            _ => None,
        }
    }

    /// constructs a confidential XfrAssetType with an asset type and asset type blind
    pub fn from_blind(
        pc_gens: &RistrettoPedersenGens,
        asset_type: &AssetType,
        blind: &Scalar,
    ) -> Self {
        let comm_type = pc_gens.commit(asset_type.as_scalar(), *blind).compress();
        XfrAssetType::Confidential(comm_type)
    }
}

/// Public Asset Tracer Encryption keys
/// Identity attributes are encrypted with keys.attrs_enc_key
/// Amount and Asset Type encrypted with keys.record_data_enc_key
/// All three info above are encrypted with keys.lock_info_enc_key
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerEncKeys {
    pub record_data_enc_key: RecordDataEncKey,
    pub attrs_enc_key: AttributeEncKey,
    pub lock_info_enc_key: XPublicKey,
}

/// Secret Asset Tracer Decryption keys
/// Identity attributed are encrypted with keys.attrs_enc_key
/// Amount and Asset Type encrypted with keys.record_data_enc_key
/// All three info above are encrypted with keys.lock_info_enc_key
#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerDecKeys {
    pub record_data_dec_key: RecordDataDecKey,
    pub attrs_dec_key: AttributeDecKey,
    pub lock_info_dec_key: XSecretKey,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracerKeyPair {
    pub enc_key: AssetTracerEncKeys,
    pub dec_key: AssetTracerDecKeys,
}

impl AssetTracerKeyPair {
    /// Generates a new keypair for asset tracing
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let (record_data_dec_key, record_data_enc_key) =
            elgamal_key_gen(prng, &RistrettoPoint::get_base());
        let (attrs_dec_key, attrs_enc_key) = elgamal_key_gen(prng, &BLSG1::get_base());
        let lock_info_dec_key = XSecretKey::new(prng);
        let lock_info_enc_key = XPublicKey::from(&lock_info_dec_key);
        AssetTracerKeyPair {
            enc_key: AssetTracerEncKeys {
                record_data_enc_key,
                attrs_enc_key,
                lock_info_enc_key,
            },
            dec_key: AssetTracerDecKeys {
                record_data_dec_key,
                attrs_dec_key,
                lock_info_dec_key,
            },
        }
    }
}
/// An asset and identity tracing policies for an asset record
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TracingPolicies(pub Vec<TracingPolicy>);

impl TracingPolicies {
    pub fn new() -> Self {
        TracingPolicies(vec![])
    }
    pub fn from_policy(policy: TracingPolicy) -> Self {
        TracingPolicies(vec![policy])
    }
    pub fn add(&mut self, policy: TracingPolicy) {
        self.0.push(policy);
    }
    pub fn get_policy(&self, index: usize) -> Option<&TracingPolicy> {
        self.0.get(index)
    }
    pub fn get_policies(&self) -> &[TracingPolicy] {
        self.0.as_slice()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An asset and identity tracing policy for an asset record
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TracingPolicy {
    pub enc_keys: AssetTracerEncKeys,
    pub asset_tracing: bool, // track amount and asset type
    pub identity_tracing: Option<IdentityRevealPolicy>, // get identity attribute of asset holder
}

/// An identity reveal policy. It indicates the credential issuer public key
/// and a reveal_map indicating which attributes needs to be revealed (by the position they
/// occur in the credential)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityRevealPolicy {
    pub cred_issuer_pub_key: ACIssuerPublicKey,
    pub reveal_map: Vec<bool>, // i-th is true, if i-th attribute is to be revealed
}

/// Information directed to an asset tracer
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TracerMemo {
    pub enc_key: AssetTracerEncKeys, // FIXME: (alex) to be removed with authenticated encyrption
    /// amount is a 64 bit positive integer expressed in base 2^32 in confidential transaction
    /// None if amount is non-confidential
    pub lock_amount: Option<(RecordDataCiphertext, RecordDataCiphertext)>,
    /// None if asset type is non-confidential
    pub lock_asset_type: Option<RecordDataCiphertext>,
    pub lock_attributes: Vec<AttributeCiphertext>,
    /// A hybrid encryption of amount, asset type and attributes encrypted above for faster access
    pub lock_info: ZeiHybridCipher,
}

/// Information directed to secret key holder of a BlindAssetRecord
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerMemo {
    pub blind_share: CompressedEdwardsY,
    pub lock: ZeiHybridCipher,
}

impl OwnerMemo {
    /// constructs an `OwnerMemo` for an asset record with only confidential amount
    /// returns (OwnerMemo, (amount_blind_low, amount_blind_high))
    /// PRNG should be seeded with good entropy instead of being deterministically seeded
    pub fn from_amount<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        pub_key: &XfrPublicKey,
    ) -> Result<(Self, (Scalar, Scalar))> {
        let (r, blind_share) = Scalar::random_scalar_with_compressed_edwards(prng);
        let shared_point = OwnerMemo::derive_shared_edwards_point(
            &r,
            &pub_key.as_compressed_edwards_point(),
        )
        .c(d!())?;
        let amount_blinds = OwnerMemo::calc_amount_blinds(&shared_point);

        let lock = hybrid_encryption::hybrid_encrypt_with_sign_key(
            prng,
            &pub_key.0,
            &amount.to_be_bytes(),
        );
        Ok((OwnerMemo { blind_share, lock }, amount_blinds))
    }

    /// constructs an `OwnerMemo` for an asset record with only confidential asset type
    /// returns (OwnerMemo, asset_type_blind)
    /// PRNG should be seeded with good entropy instead of being deterministically seeded
    pub fn from_asset_type<R: CryptoRng + RngCore>(
        prng: &mut R,
        asset_type: &AssetType,
        pub_key: &XfrPublicKey,
    ) -> Result<(Self, Scalar)> {
        let (r, blind_share) = Scalar::random_scalar_with_compressed_edwards(prng);
        let shared_point = OwnerMemo::derive_shared_edwards_point(
            &r,
            &pub_key.as_compressed_edwards_point(),
        )
        .c(d!())?;
        let asset_type_blind = OwnerMemo::calc_asset_type_blind(&shared_point);

        let lock = hybrid_encryption::hybrid_encrypt_with_sign_key(
            prng,
            &pub_key.0,
            &asset_type.0,
        );
        Ok((OwnerMemo { blind_share, lock }, asset_type_blind))
    }

    /// constructs an `OwnerMemo` for an asset record with both confidential amount and confidential asset type
    /// returns (OwnerMemo, (amount_blind_low, amount_blind_high), asset_type_blind)
    /// PRNG should be seeded with good entropy instead of being deterministically seeded
    pub fn from_amount_and_asset_type<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        asset_type: &AssetType,
        pub_key: &XfrPublicKey,
    ) -> Result<(Self, (Scalar, Scalar), Scalar)> {
        let (r, blind_share) = Scalar::random_scalar_with_compressed_edwards(prng);
        let shared_point = OwnerMemo::derive_shared_edwards_point(
            &r,
            &pub_key.as_compressed_edwards_point(),
        )
        .c(d!())?;
        let amount_blinds = OwnerMemo::calc_amount_blinds(&shared_point);
        let asset_type_blind = OwnerMemo::calc_asset_type_blind(&shared_point);

        let mut amount_asset_type_plaintext = vec![];
        amount_asset_type_plaintext.extend_from_slice(&amount.to_be_bytes()[..]);
        amount_asset_type_plaintext.extend_from_slice(&asset_type.0[..]);
        let lock = hybrid_encryption::hybrid_encrypt_with_sign_key(
            prng,
            &pub_key.0,
            &amount_asset_type_plaintext,
        );
        Ok((
            OwnerMemo { blind_share, lock },
            amount_blinds,
            asset_type_blind,
        ))
    }

    /// decrypt the `OwnerMemo.lock` which encrypts only the confidential amount
    /// returns error if the decrypted bytes length doesn't match
    pub fn decrypt_amount(&self, keypair: &XfrKeyPair) -> Result<u64> {
        let decrypted_bytes = self.decrypt(&keypair);
        // amount is u64, thus u64.to_be_bytes should be 8 bytes
        if decrypted_bytes.len() != 8 {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }
        let mut amt_be_bytes: [u8; 8] = Default::default();
        amt_be_bytes.copy_from_slice(&decrypted_bytes[..]);
        Ok(u64::from_be_bytes(amt_be_bytes))
    }

    /// decrypt the `OwnerMemo.lock` which encrypts only the confidential asset type
    /// returns error if the decrypted bytes length doesn't match
    pub fn decrypt_asset_type(&self, keypair: &XfrKeyPair) -> Result<AssetType> {
        let decrypted_bytes = self.decrypt(&keypair);
        if decrypted_bytes.len() != ASSET_TYPE_LENGTH {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }
        let mut asset_type_bytes: [u8; ASSET_TYPE_LENGTH] = Default::default();
        asset_type_bytes.copy_from_slice(&decrypted_bytes[..]);
        Ok(AssetType(asset_type_bytes))
    }

    /// decrypt the `OwnerMemo.lock` which encrypts "amount || asset type", both amount and asset type
    /// are confidential. Returns error if the decrypted bytes length doesn't match.
    pub fn decrypt_amount_and_asset_type(
        &self,
        keypair: &XfrKeyPair,
    ) -> Result<(u64, AssetType)> {
        let decrypted_bytes = self.decrypt(&keypair);
        if decrypted_bytes.len() != ASSET_TYPE_LENGTH + 8 {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }
        let mut amt_be_bytes: [u8; 8] = Default::default();
        amt_be_bytes.copy_from_slice(&decrypted_bytes[..8]);
        let mut asset_type_bytes: [u8; ASSET_TYPE_LENGTH] = Default::default();
        asset_type_bytes.copy_from_slice(&decrypted_bytes[8..]);

        Ok((
            u64::from_be_bytes(amt_be_bytes),
            AssetType(asset_type_bytes),
        ))
    }

    /// Returns the amount blind (blind_low, blind_high)
    pub fn derive_amount_blinds(
        &self,
        keypair: &XfrKeyPair,
    ) -> Result<(Scalar, Scalar)> {
        let shared_point = OwnerMemo::derive_shared_edwards_point(
            &keypair.sec_key.as_scalar(),
            &self.blind_share,
        )
        .c(d!())?;
        Ok(OwnerMemo::calc_amount_blinds(&shared_point))
    }

    /// Returns the asset type blind
    pub fn derive_asset_type_blind(&self, keypair: &XfrKeyPair) -> Result<Scalar> {
        let shared_point = OwnerMemo::derive_shared_edwards_point(
            &keypair.sec_key.as_scalar(),
            &self.blind_share,
        )
        .c(d!())?;
        Ok(OwnerMemo::calc_asset_type_blind(&shared_point))
    }
}

// internal function
impl OwnerMemo {
    // Decrypts the lock, returns bytes
    fn decrypt(&self, keypair: &XfrKeyPair) -> Vec<u8> {
        hybrid_encryption::hybrid_decrypt_with_ed25519_secret_key(
            &self.lock,
            &keypair.sec_key.0,
        )
    }

    // Given a shared point, calculate the amount blinds
    // returns (amount_blind_low, amount_blind_high)
    // noted shared_point = PK ^ r = blind_share ^ sk = (g^sk) ^ r
    fn calc_amount_blinds(shared_point: &CompressedEdwardsY) -> (Scalar, Scalar) {
        (
            OwnerMemo::hash_to_scalar(&shared_point, b"amount_low"),
            OwnerMemo::hash_to_scalar(&shared_point, b"amount_high"),
        )
    }

    // Given a shared point, calculate the asset type blind
    // noted shared_point = PK ^ r = blind_share ^ sk = (g^sk) ^ r
    fn calc_asset_type_blind(shared_point: &CompressedEdwardsY) -> Scalar {
        OwnerMemo::hash_to_scalar(&shared_point, b"asset_type")
    }

    // returns point ^ s, where point is a compressed edwards point, s is a scalar
    // during `OwnerMemo` creation, point = PublicKey = g^sk, s = r, where r is the randomization scalar
    // during `OwnerMemo` decryption, point = blind_share = g^r, s = sk, where sk is the secret key
    // in both cases, returns g^(sk*r) in `CompressedEdwardsY` form
    fn derive_shared_edwards_point(
        s: &Scalar,
        point: &CompressedEdwardsY,
    ) -> Result<CompressedEdwardsY> {
        let shared_edwards_point =
            s.0 * point.decompress().c(d!(ZeiError::DecompressElementError))?;
        Ok(CompressedEdwardsY(shared_edwards_point.compress()))
    }

    // returns H(point || aux) as a Scalar
    fn hash_to_scalar(point: &CompressedEdwardsY, aux: &'static [u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(point.0.as_bytes());
        hasher.update(aux);
        Scalar::from_hash(hasher)
    }
}

// ASSET RECORD STRUCTURES

/// A BlindAssetRecord with revealed commitment openings.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct OpenAssetRecord {
    pub blind_asset_record: BlindAssetRecord, //TODO have a reference here, and lifetime parameter. We will avoid copying info unnecessarily.
    #[serde(with = "serde_str")]
    pub amount: u64,
    pub amount_blinds: (Scalar, Scalar), // use Scalar::zero() if unneeded
    pub asset_type: AssetType,
    pub type_blind: Scalar, // use Scalar::zero() if unneeded
}

impl OpenAssetRecord {
    pub fn get_record_type(&self) -> AssetRecordType {
        self.blind_asset_record.get_record_type()
    }
    pub fn get_asset_type(&self) -> &AssetType {
        &self.asset_type
    }
    pub fn get_amount(&self) -> &u64 {
        &self.amount
    }
    pub fn get_pub_key(&self) -> &XfrPublicKey {
        &self.blind_asset_record.public_key
    }
}

/// An input or output record and associated information (policies and memos) used to build XfrNotes/XfrBodys.
/// It contains all the information used to the generate valid XfrNote/XfrBody.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetRecord {
    pub open_asset_record: OpenAssetRecord,
    pub tracing_policies: TracingPolicies,
    pub identity_proofs: Vec<Option<ACConfidentialRevealProof>>,
    pub asset_tracers_memos: Vec<TracerMemo>,
    pub owner_memo: Option<OwnerMemo>,
}

/// An asset record template: amount, asset type, owner public key, type and tracing
#[derive(Deserialize, Serialize)]
pub struct AssetRecordTemplate {
    #[serde(with = "serde_str")]
    pub amount: u64,
    pub asset_type: AssetType,
    pub public_key: XfrPublicKey, // ownership address
    pub asset_record_type: AssetRecordType,
    pub asset_tracing_policies: TracingPolicies,
}

// PROOFS STRUCTURES
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AssetTypeAndAmountProof {
    AssetMix(AssetMixProof),   // multi-type fully confidential Xfr
    ConfAmount(XfrRangeProof), // single-type and public, confidential amount
    ConfAsset(Box<ChaumPedersenProofX>), // single-type confidential, public amount
    ConfAll(Box<(XfrRangeProof, ChaumPedersenProofX)>), // fully confidential single type
    NoProof,                   // non-confidential transaction
}

/// I contain the proofs of a transfer note
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrProofs {
    pub asset_type_and_amount_proof: AssetTypeAndAmountProof,
    pub asset_tracing_proof: AssetTracingProofs,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct XfrRangeProof {
    #[serde(with = "serialization::zei_obj_serde")]
    pub range_proof: RangeProof,
    pub xfr_diff_commitment_low: CompressedRistretto, //lower 32 bits transfer amount difference commitment
    pub xfr_diff_commitment_high: CompressedRistretto, //higher 32 bits transfer amount difference commitment
}

/// Proof of records' data and identity tracing
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetTracingProofs {
    pub asset_type_and_amount_proofs: Vec<PedersenElGamalEqProof>, // One proof for each tracing key
    pub inputs_identity_proofs: Vec<Vec<Option<ACConfidentialRevealProof>>>, // None if asset policy does not require identity tracing for input. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
    pub outputs_identity_proofs: Vec<Vec<Option<ACConfidentialRevealProof>>>, // None if asset policy does not require identity tracing for output. Otherwise, value proves that ElGamal ciphertexts encrypts encrypts attributes that satisfy an credential verification
}

impl PartialEq for XfrRangeProof {
    fn eq(&self, other: &XfrRangeProof) -> bool {
        self.range_proof.to_bytes() == other.range_proof.to_bytes()
            && self.xfr_diff_commitment_low == other.xfr_diff_commitment_low
            && self.xfr_diff_commitment_high == other.xfr_diff_commitment_high
    }
}

impl Eq for XfrRangeProof {}
