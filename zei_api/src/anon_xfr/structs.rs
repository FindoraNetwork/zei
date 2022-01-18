use crate::anon_xfr::decrypt_memo;
use crate::anon_xfr::keys::{AXfrKeyPair, AXfrPubKey, AXfrSignature};
use crate::xfr::structs::{AssetType, OwnerMemo};
use algebra::bls12_381::{BLSScalar, Bls12381};
use algebra::groups::{Scalar, Zero};
use algebra::jubjub::JubjubScalar;
use crypto::basics::commitments::rescue;
use crypto::basics::hybrid_encryption::{
    hybrid_encrypt_with_x25519_key, XPublicKey, XSecretKey,
};
use poly_iops::commitments::kzg_poly_com::KZGCommitmentScheme;
use poly_iops::plonk::protocol::prover::PlonkPf;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use serde::Serialize;
use utils::errors::ZeiError;
use wasm_bindgen::prelude::*;
use utils::serialization::ZeiFromToBytes;
use base64;

pub type Nullifier = BLSScalar;
pub type Commitment = BLSScalar;
pub type BlindFactor = BLSScalar;

/// A Merkle tree node which consists of the following:
/// * `siblings1` - the 1st sibling of the tree node
/// * `siblings2` - the 2nd sibling of the tree node
/// * `is_left_child` - indicates whether the tree node is the left child of its parent
/// * `is_right_child` - indicates whether the tree node is the right child of its parent
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MTNode {
    pub siblings1: BLSScalar,
    pub siblings2: BLSScalar,
    pub is_left_child: u8,
    pub is_right_child: u8,
}

pub type SnarkProof = PlonkPf<KZGCommitmentScheme<Bls12381>>;

// AXfrNote is a wrapper over AXfrBody with signatures and verification.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrNote {
    pub body: AXfrBody,
    pub signatures: Vec<AXfrSignature>,
}

impl AXfrNote {
    pub fn generate_note_from_body(
        body: AXfrBody,
        keypairs: Vec<AXfrKeyPair>,
    ) -> Result<AXfrNote> {
        let mut signatures: Vec<AXfrSignature> = Vec::new();
        let msg: Vec<u8> = bincode::serialize(&body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        let mut index = 0;
        for keypair in keypairs {
            println!("generate_note_from_body Public Key: {}", base64::encode(&body.inputs[index].1.zei_to_bytes()));
            let signature = keypair.sign(msg.as_slice());
            body.inputs[index].1.verify(msg.as_slice(), &signature.clone()).unwrap();
            signatures.push(signature);
            index+=1;
        }

        Ok(AXfrNote { body, signatures })
    }

    pub fn verify(&self) -> Result<()> {
        let msg: Vec<u8> = bincode::serialize(&self.body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        self.body
            .inputs
            .iter()
            .zip(self.signatures.iter())
            .map(|(inp, sig)| {

                println!("generate_note_from_body Public Key: {}", base64::encode(&inp.1.zei_to_bytes()));
                inp.1.verify(msg.as_slice(), sig)
            })
            .collect::<Result<Vec<()>>>()
            .c(d!("AXfrNote signature verification failed"))?;

        Ok(())
    }
}

/// Anonymous transfers structure
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrBody {
    pub inputs: Vec<(Nullifier, AXfrPubKey)>,
    pub outputs: Vec<AnonBlindAssetRecord>,
    pub proof: AXfrProof,
    pub owner_memos: Vec<OwnerMemo>,
}

/// Asset record to be published
#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonBlindAssetRecord {
    pub amount_type_commitment: Commitment,
    pub public_key: AXfrPubKey,
}

impl AnonBlindAssetRecord {
    pub fn from_oabar(oabar: &OpenAnonBlindAssetRecord) -> AnonBlindAssetRecord {
        let rand_pub_key = oabar.pub_key_ref().randomize(&oabar.key_rand_factor);
        AnonBlindAssetRecord {
            amount_type_commitment: oabar.compute_commitment(),
            public_key: rand_pub_key,
        }
    }
}

/// Proof for an AXfrBody correctness
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrProof {
    pub snark_proof: SnarkProof,
    pub merkle_root: BLSScalar,
    pub merkle_root_version: usize,
}

/// MT PATH, merkle root value, leaf identifier
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MTLeafInfo {
    pub path: MTPath,
    pub root: BLSScalar,
    pub root_version: usize,
    pub uid: u64,
}

impl Default for MTLeafInfo {
    fn default() -> Self {
        MTLeafInfo {
            path: MTPath { nodes: vec![] },
            root: BLSScalar::zero(),
            root_version: 0,
            uid: 0,
        }
    }
}

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct OpenAnonBlindAssetRecord {
    pub(crate) amount: u64,
    pub(crate) asset_type: AssetType,
    pub(crate) blind: BLSScalar,
    pub(crate) pub_key: AXfrPubKey,
    pub(crate) key_rand_factor: JubjubScalar,
    pub(crate) owner_memo: Option<OwnerMemo>,
    pub(crate) mt_leaf_info: Option<MTLeafInfo>,
}

impl OpenAnonBlindAssetRecord {
    pub fn update_mt_leaf_info(&mut self, mt_leat_info: MTLeafInfo) {
        self.mt_leaf_info = Some(mt_leat_info);
    }
}

impl OpenAnonBlindAssetRecord {
    /// Get record amount
    pub fn get_amount(&self) -> u64 {
        self.amount
    }

    /// Get record asset type
    pub fn get_asset_type(&self) -> AssetType {
        self.asset_type
    }

    /// Get record public_key
    pub fn pub_key_ref(&self) -> &AXfrPubKey {
        &self.pub_key
    }

    /// Get record key randomization factor
    pub fn get_key_rand_factor(&self) -> JubjubScalar {
        self.key_rand_factor
    }

    /// Get record's owner memo
    pub fn get_owner_memo(&self) -> Option<OwnerMemo> {
        self.owner_memo.clone()
    }

    /// computes record's amount||asset type commitment
    pub fn compute_commitment(&self) -> Commitment {
        rescue::HashCommitment::new()
            .commit(
                &self.blind,
                &[
                    BLSScalar::from_u64(self.amount),
                    self.asset_type.as_scalar(),
                ],
            )
            .unwrap()
        // safe unwrap
    }
}

#[derive(Default)]
pub struct OpenAnonBlindAssetRecordBuilder {
    pub(crate) oabar: OpenAnonBlindAssetRecord,
}

// Builder pattern
impl OpenAnonBlindAssetRecordBuilder {
    /// Created new OpenAnonBlindAssetRecord builder
    pub fn new() -> Self {
        OpenAnonBlindAssetRecordBuilder {
            ..Default::default()
        }
    }

    /// Specify amount
    pub fn amount(mut self, amount: u64) -> Self {
        self.oabar.amount = amount;
        self
    }

    /// Specify asset_type
    pub fn asset_type(mut self, asset_type: AssetType) -> Self {
        self.oabar.asset_type = asset_type;
        self
    }

    /// Specify public_key
    pub fn pub_key(mut self, pub_key: AXfrPubKey) -> Self {
        self.oabar.pub_key = pub_key;
        self
    }

    /// Update mt_leaf_info
    pub fn mt_leaf_info(mut self, mt_leaf_info: MTLeafInfo) -> Self {
        self.oabar.update_mt_leaf_info(mt_leaf_info);
        self
    }

    /// Finalize builder:
    /// If built via constructor + builder methods, it samples commitment blinding and key randomization factor and
    /// creates associated owner memo.
    /// If built via `Self::from_abar(...)`, return Err(ZeiError::InconsistentStructureError)
    pub fn finalize<R: CryptoRng + RngCore>(
        mut self,
        prng: &mut R,
        enc_key: &XPublicKey,
    ) -> Result<Self> {
        if self.oabar.owner_memo.is_some() {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }

        self.oabar.blind = BLSScalar::random(prng);
        self.oabar.key_rand_factor = JubjubScalar::random(prng);
        let mut msg = vec![];
        msg.extend_from_slice(&self.oabar.amount.to_le_bytes());
        msg.extend_from_slice(&self.oabar.asset_type.0);
        msg.extend_from_slice(&self.oabar.blind.to_bytes());
        msg.extend_from_slice(&self.oabar.key_rand_factor.to_bytes());
        let cipher = hybrid_encrypt_with_x25519_key(prng, enc_key, &msg);
        let memo = OwnerMemo {
            blind_share: Default::default(),
            lock: cipher,
        };
        self.oabar.owner_memo = Some(memo);
        Ok(self)
    }

    /// Run a sanity check and if ok, return Ok(OpenBlindAssetRecord)
    pub fn build(self) -> Result<OpenAnonBlindAssetRecord> {
        self.sanity_check().c(d!())?;
        Ok(self.oabar)
    }
}

impl OpenAnonBlindAssetRecordBuilder {
    /// Builds an OpenAssetRecord from an BlindAssetRecord, opening keys, owner memo and decryption keys
    /// Return error if decrypted `owner_memo` is inconsistent with `record`
    pub fn from_abar(
        record: &AnonBlindAssetRecord,
        owner_memo: OwnerMemo,
        key_pair: &AXfrKeyPair,
        dec_key: &XSecretKey,
    ) -> Result<Self> {
        let (amount, asset_type, blind, key_rand) =
            decrypt_memo(&owner_memo, dec_key, key_pair, record).c(d!())?;
        let mut builder = OpenAnonBlindAssetRecordBuilder::new()
            .pub_key(key_pair.pub_key())
            .amount(amount)
            .asset_type(asset_type);

        builder.oabar.blind = blind;
        builder.oabar.key_rand_factor = key_rand;
        builder.oabar.owner_memo = Some(owner_memo);
        Ok(builder)
    }

    fn sanity_check(&self) -> Result<()> {
        // 1. check public key is non-default
        if self.oabar.pub_key == AXfrPubKey::default() {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }

        // 2. OwnerMemo is not None
        if self.oabar.owner_memo.is_none() {
            return Err(eg!(ZeiError::InconsistentStructureError));
        }
        Ok(())
    }
}

/// An authentication path of a ternary Merkle tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MTPath {
    pub nodes: Vec<MTNode>,
}

impl MTPath {
    pub fn new(nodes: Vec<MTNode>) -> Self {
        Self { nodes }
    }
}
