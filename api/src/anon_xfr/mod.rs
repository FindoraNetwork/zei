use crate::anon_xfr::keys::AXfrPubKey;
use crate::anon_xfr::structs::Commitment;
use crate::{
    anon_xfr::{
        keys::AXfrKeyPair,
        structs::{
            AccElemVars, AnonAssetRecord, AxfrOwnerMemo, MTPath, MerkleNodeVars, MerklePathVars,
            OpenAnonAssetRecord,
        },
    },
    xfr::structs::{AssetType, ASSET_TYPE_LENGTH},
};
use zei_algebra::{
    bls12_381::{BLSScalar, BLS12_381_SCALAR_LEN},
    collections::HashMap,
    prelude::*,
};
use zei_crypto::basic::rescue::RescueInstance;
use zei_plonk::{
    plonk::{
        constraint_system::{rescue::StateVar, TurboCS, VarIndex},
        indexer::PlonkPf,
    },
    poly_commit::kzg_poly_com::KZGCommitmentSchemeBLS,
};

/// Module for general-purpose anonymous payment.
pub mod abar_to_abar;
/// Module for converting anonymous assets to transparent assets.
pub mod abar_to_ar;
/// Module for converting anonymous assets to confidential assets.
pub mod abar_to_bar;
/// Module for designs related to address folding.
pub mod address_folding;
/// Module for converting transparent assets to anonymous assets.
pub mod ar_to_abar;
/// Module for converting confidential assets to anonymous assets.
pub mod bar_to_abar;
/// Module for the spending key and the public key.
pub mod keys;
/// Module for shared structures.
pub mod structs;

/// The asset type for FRA.
const ASSET_TYPE_FRA: AssetType = AssetType([0; ASSET_TYPE_LENGTH]);
/// FRA as the token used to pay the fee.
pub const FEE_TYPE: AssetType = ASSET_TYPE_FRA;
/// A constant 2^{32}.
pub const TWO_POW_32: u64 = 1 << 32;

pub(crate) type TurboPlonkCS = TurboCS<BLSScalar>;

/// The Plonk proof type.
pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;

/// Check that inputs have Merkle tree witness and matching key pair.
fn check_inputs(inputs: &[OpenAnonAssetRecord], keypair: &AXfrKeyPair) -> Result<()> {
    for input in inputs.iter() {
        if input.mt_leaf_info.is_none() || keypair.get_public_key() != input.pub_key {
            return Err(eg!(ZeiError::ParameterError));
        }
    }
    Ok(())
}

/// Check that for each asset type total input amount == total output amount
/// and for FRA, total input amount == total output amount + fees.
fn check_asset_amount(
    inputs: &[OpenAnonAssetRecord],
    outputs: &[OpenAnonAssetRecord],
    fee: u32,
) -> Result<()> {
    let fee_asset_type = FEE_TYPE;
    let mut balances = HashMap::new();

    for record in inputs.iter() {
        if let Some(x) = balances.get_mut(&record.asset_type) {
            *x += record.amount as i128;
        } else {
            balances.insert(record.asset_type, record.amount as i128);
        }
    }

    for record in outputs.iter() {
        if let Some(x) = balances.get_mut(&record.asset_type) {
            *x -= record.amount as i128;
        } else {
            balances.insert(record.asset_type, -(record.amount as i128));
        }
    }

    for (&asset_type, &sum) in balances.iter() {
        if asset_type != fee_asset_type {
            if sum != 0i128 {
                return Err(eg!(ZeiError::XfrCreationAssetAmountError));
            }
        } else {
            if sum != fee.into() {
                return Err(eg!(ZeiError::XfrCreationAssetAmountError));
            }
        }
    }

    Ok(())
}

/// Check that the Merkle roots in input asset records are the same
/// `inputs` is guaranteed to have at least one asset record.
fn check_roots(inputs: &[OpenAnonAssetRecord]) -> Result<()> {
    let root = inputs[0]
        .mt_leaf_info
        .as_ref()
        .c(d!(ZeiError::ParameterError))?
        .root;
    for input in inputs.iter().skip(1) {
        if input
            .mt_leaf_info
            .as_ref()
            .c(d!(ZeiError::ParameterError))?
            .root
            != root
        {
            return Err(eg!(ZeiError::AXfrVerificationError));
        }
    }
    Ok(())
}

/// Parse the owner memo from bytes.
/// * `bytes` - the memo bytes.
/// * `key_pair` - the memo bytes.
/// * `abar` - Associated anonymous blind asset record to check memo info against.
/// Return Error if memo info does not match the commitment.
/// Return Ok(amount, asset_type, blinding) otherwise.
pub fn parse_memo(
    bytes: &[u8],
    key_pair: &AXfrKeyPair,
    abar: &AnonAssetRecord,
) -> Result<(u64, AssetType, BLSScalar)> {
    if bytes.len() != 8 + ASSET_TYPE_LENGTH + BLS12_381_SCALAR_LEN {
        return Err(eg!(ZeiError::ParameterError));
    }
    let amount = u8_le_slice_to_u64(&bytes[0..8]);
    let mut i = 8;
    let mut asset_type_array = [0u8; ASSET_TYPE_LENGTH];
    asset_type_array.copy_from_slice(&bytes[i..i + ASSET_TYPE_LENGTH]);
    let asset_type = AssetType(asset_type_array);
    i += ASSET_TYPE_LENGTH;
    let blind = BLSScalar::from_bytes(&bytes[i..i + BLS12_381_SCALAR_LEN])
        .c(d!(ZeiError::ParameterError))?;

    let public_key_scalars = key_pair.get_public_key().get_public_key_scalars()?;

    let hash = RescueInstance::new();
    let expected_commitment = {
        let cur = hash.rescue(&[
            blind,
            BLSScalar::from(amount),
            asset_type.as_scalar(),
            public_key_scalars[0],
        ])[0];
        hash.rescue(&[
            cur,
            public_key_scalars[1],
            public_key_scalars[2],
            BLSScalar::zero(),
        ])[0]
    };
    if expected_commitment != abar.commitment {
        return Err(eg!(ZeiError::CommitmentVerificationError));
    }

    Ok((amount, asset_type, blind))
}

/// Decrypts the owner memo.
/// * `memo` - Owner memo to decrypt
/// * `dec_key` - Decryption key
/// * `abar` - Associated anonymous blind asset record to check memo info against.
/// Return Error if memo info does not match the commitment or public key.
/// Return Ok(amount, asset_type, blinding) otherwise.
pub fn decrypt_memo(
    memo: &AxfrOwnerMemo,
    key_pair: &AXfrKeyPair,
    abar: &AnonAssetRecord,
) -> Result<(u64, AssetType, BLSScalar)> {
    let plaintext = memo.decrypt(&key_pair.get_secret_key())?;
    parse_memo(&plaintext, key_pair, abar)
}

/// Compute the nullifier.
pub fn nullify(
    key_pair: &AXfrKeyPair,
    amount: u64,
    asset_type: &AssetType,
    uid: u64,
) -> Result<BLSScalar> {
    let pub_key = key_pair.get_public_key();

    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::from(1u32));
    let uid_shifted = BLSScalar::from(uid).mul(&pow_2_64);
    let uid_amount = uid_shifted.add(&BLSScalar::from(amount));

    let public_key_scalars = pub_key.get_public_key_scalars()?;
    let secret_key_scalars = key_pair.get_secret_key().get_secret_key_scalars()?;

    let hash = RescueInstance::new();
    let cur = hash.rescue(&[
        uid_amount,
        asset_type.as_scalar(),
        public_key_scalars[0],
        public_key_scalars[1],
    ])[0];
    Ok(hash.rescue(&[
        cur,
        public_key_scalars[2],
        secret_key_scalars[0],
        secret_key_scalars[1],
    ])[0])
}

/// Length of the amount allowed in anonymous assets.
pub(crate) const AMOUNT_LEN: usize = 64;

/// Depth of the Merkle Tree circuit.
pub const TREE_DEPTH: usize = 20;

/// Add the commitment constraints to the constraint system:
/// comm = hash(hash(blinding, amount, asset_type, 0), pubkey_x, 0, 0).
pub fn commit_in_cs(
    cs: &mut TurboPlonkCS,
    blinding_var: VarIndex,
    amount_var: VarIndex,
    asset_var: VarIndex,
    public_key_scalars: &[VarIndex; 3],
) -> VarIndex {
    let input_var = StateVar::new([blinding_var, amount_var, asset_var, public_key_scalars[0]]);
    let cur = cs.rescue_hash(&input_var)[0];
    let input_var = StateVar::new([
        cur,
        public_key_scalars[1],
        public_key_scalars[2],
        cs.zero_var(),
    ]);
    cs.rescue_hash(&input_var)[0]
}

/// Compute the record's amount||asset type||pub key commitment
pub fn commit(
    public_key: &AXfrPubKey,
    blind: &BLSScalar,
    amount: u64,
    asset_type: &AssetType,
) -> Result<Commitment> {
    let public_key_scalars = public_key.get_public_key_scalars()?;

    let hash = RescueInstance::new();
    let cur = hash.rescue(&[
        blind.clone(),
        BLSScalar::from(amount),
        asset_type.as_scalar(),
        public_key_scalars[0],
    ])[0];
    Ok(hash.rescue(&[
        cur,
        public_key_scalars[1],
        public_key_scalars[2],
        BLSScalar::zero(),
    ])[0])
}

/// Add the nullifier constraints to the constraint system.
pub(crate) fn nullify_in_cs(
    cs: &mut TurboPlonkCS,
    secret_key_scalars: &[VarIndex; 2],
    uid_amount: VarIndex,
    asset_type: VarIndex,
    public_key_scalars: &[VarIndex; 3],
) -> VarIndex {
    let input_var = StateVar::new([
        uid_amount,
        asset_type,
        public_key_scalars[0],
        public_key_scalars[1],
    ]);
    let cur = cs.rescue_hash(&input_var)[0];
    let input_var = StateVar::new([
        cur,
        public_key_scalars[2],
        secret_key_scalars[0],
        secret_key_scalars[1],
    ]);
    cs.rescue_hash(&input_var)[0]
}

/// Add the Merkle tree path constraints to the constraint system.
pub fn add_merkle_path_variables(cs: &mut TurboPlonkCS, path: MTPath) -> MerklePathVars {
    let path_vars: Vec<MerkleNodeVars> = path
        .nodes
        .into_iter()
        .map(|node| MerkleNodeVars {
            siblings1: cs.new_variable(node.siblings1),
            siblings2: cs.new_variable(node.siblings2),
            is_left_child: cs.new_variable(BLSScalar::from(node.is_left_child as u32)),
            is_right_child: cs.new_variable(BLSScalar::from(node.is_right_child as u32)),
        })
        .collect();
    // Boolean-constrain `is_left_child` and `is_right_child`
    for node_var in path_vars.iter() {
        cs.insert_boolean_gate(node_var.is_left_child);
        cs.insert_boolean_gate(node_var.is_right_child);
        // 0 <= is_left_child[i] + is_right_child[i] <= 1 for every i,
        // because a node can't simultaneously be the left and right child of its parent
        let left_add_right = cs.add(node_var.is_left_child, node_var.is_right_child);
        cs.insert_boolean_gate(left_add_right);
    }

    MerklePathVars { nodes: path_vars }
}

/// Add the sorting constraints that arrange the positions of the sibling nodes.
/// If `node` is the left child of parent, output (`node`, `sib1`, `sib2`);
/// if `node` is the right child of parent, output (`sib1`, `sib2`, `node`);
/// otherwise, output (`sib1`, `node`, `sib2`).
fn sort(
    cs: &mut TurboPlonkCS,
    node: VarIndex,
    sib1: VarIndex,
    sib2: VarIndex,
    is_left_child: VarIndex,
    is_right_child: VarIndex,
) -> StateVar {
    let left = cs.select(sib1, node, is_left_child);
    let right = cs.select(sib2, node, is_right_child);
    let sum_left_right = cs.add(left, right);
    let one = BLSScalar::one();
    let mid = cs.linear_combine(
        &[node, sib1, sib2, sum_left_right],
        one,
        one,
        one,
        one.neg(),
    );
    StateVar::new([left, mid, right, cs.zero_var()])
}

/// Compute the Merkle tree root given the path information.
pub fn compute_merkle_root_variables(
    cs: &mut TurboPlonkCS,
    elem: AccElemVars,
    path_vars: &MerklePathVars,
) -> VarIndex {
    let (uid, commitment) = (elem.uid, elem.commitment);
    let zero_var = cs.zero_var();

    let mut node_var = cs.rescue_hash(&StateVar::new([uid, commitment, zero_var, zero_var]))[0];
    for path_node in path_vars.nodes.iter() {
        let input_var = sort(
            cs,
            node_var,
            path_node.siblings1,
            path_node.siblings2,
            path_node.is_left_child,
            path_node.is_right_child,
        );
        node_var = cs.rescue_hash(&input_var)[0];
    }
    node_var
}

/// The number of the Bulletproofs generators needed for anonymous transfer.
pub const ANON_XFR_BP_GENS_LEN: usize = 2048;
