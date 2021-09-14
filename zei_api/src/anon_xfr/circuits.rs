use crate::anon_xfr::keys::AXfrPubKey;
use crate::anon_xfr::structs::{BlindFactor, Commitment, MTNode, MTPath, Nullifier};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{Group, GroupArithmetic, One, Scalar, ScalarArithmetic, Zero};
use algebra::jubjub::{JubjubPoint, JubjubScalar};
use crypto::basics::commitments::pedersen::PedersenGens;
use crypto::basics::commitments::rescue::HashCommitment as CommScheme;
use crypto::basics::hash::rescue::RescueInstance;
use crypto::basics::prf::PRF;
use poly_iops::plonk::turbo_plonk_cs::ecc::PointVar;
use poly_iops::plonk::turbo_plonk_cs::rescue::StateVar;
use poly_iops::plonk::turbo_plonk_cs::{TurboPlonkConstraintSystem, VarIndex};

pub type TurboPlonkCS = TurboPlonkConstraintSystem<BLSScalar>;

// TODO: Move these constants to another file.
const SK_LEN: usize = 252; // secret key size (in bits)
const JUBJUB_SCALAR_BIT_LEN: usize = 252; // jubjub scalar size (in bits)
const AMOUNT_LEN: usize = 64; // amount value size (in bits)
pub const TREE_DEPTH: usize = 20; // Depth of the Merkle Tree

#[derive(Debug, Clone)]
pub(crate) struct PayerSecret {
    pub sec_key: JubjubScalar,
    pub diversifier: JubjubScalar, // key randomizer for the signature verification key
    pub amount: u64,
    pub asset_type: BLSScalar,
    pub uid: u64,
    pub path: MTPath,
    pub blind: BlindFactor,
}

#[derive(Debug, Clone)]
pub(crate) struct PayeeSecret {
    pub amount: u64,
    pub blind: BlindFactor,
    pub asset_type: BLSScalar,
}

/// Secret witness of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrWitness {
    pub payers_secrets: Vec<PayerSecret>,
    pub payees_secrets: Vec<PayeeSecret>,
}

impl AMultiXfrWitness {
    // create a default `AMultiXfrWitness`.
    pub(crate) fn fake(n_payers: usize, n_payees: usize, tree_depth: usize) -> Self {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();
        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            diversifier: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };
        let payee_secret = PayeeSecret {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
        };

        AMultiXfrWitness {
            payers_secrets: vec![payer_secret; n_payers],
            payees_secrets: vec![payee_secret; n_payees],
        }
    }
}

/// Public inputs of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrPubInputs {
    pub payers_inputs: Vec<(Nullifier, AXfrPubKey)>,
    pub payees_commitments: Vec<Commitment>,
    pub merkle_root: BLSScalar,
}

impl AMultiXfrPubInputs {
    pub fn to_vec(&self) -> Vec<BLSScalar> {
        let mut result = vec![];
        // nullifiers and signature verification keys
        for (nullifier, pk_sign) in &self.payers_inputs {
            result.push(*nullifier);
            result.push(pk_sign.as_jubjub_point().get_x());
            result.push(pk_sign.as_jubjub_point().get_y());
        }
        // merkle_root
        result.push(self.merkle_root);
        // output commitments
        for comm in &self.payees_commitments {
            result.push(*comm);
        }
        result
    }

    // Compute the public inputs from the secret inputs
    #[allow(dead_code)]
    pub(crate) fn from_witness(witness: &AMultiXfrWitness) -> Self {
        // nullifiers and signature public keys
        let prf = PRF::new();
        let base = JubjubPoint::get_base();
        let payers_inputs: Vec<(Nullifier, AXfrPubKey)> = witness
            .payers_secrets
            .iter()
            .map(|sec| {
                let pk_point = base.mul(&sec.sec_key);
                let pk_sign =
                    AXfrPubKey::from_jubjub_point(pk_point.mul(&sec.diversifier));

                let pow_2_64 =
                    BLSScalar::from_u64(u64::max_value()).add(&BLSScalar::one());
                let uid_amount = pow_2_64
                    .mul(&BLSScalar::from_u64(sec.uid))
                    .add(&BLSScalar::from_u64(sec.amount));
                let nullifier = prf.eval(
                    &BLSScalar::from(&sec.sec_key),
                    &[
                        uid_amount,
                        sec.asset_type,
                        pk_point.get_x(),
                        pk_point.get_y(),
                    ],
                );
                (nullifier, pk_sign)
            })
            .collect();

        // output commitments
        let comm = CommScheme::new();
        let payees_commitments: Vec<Commitment> = witness
            .payees_secrets
            .iter()
            .map(|sec| {
                comm.commit(
                    &sec.blind,
                    &[BLSScalar::from_u64(sec.amount), sec.asset_type],
                )
                .unwrap()
            })
            .collect();

        // merkle root
        let hash = RescueInstance::new();
        let payer = &witness.payers_secrets[0];
        let pk_point = base.mul(&payer.sec_key);
        let zero = BLSScalar::zero();
        let pk_hash =
            hash.rescue_hash(&[pk_point.get_x(), pk_point.get_y(), zero, zero])[0];
        let commitment = comm
            .commit(
                &payer.blind,
                &[BLSScalar::from_u64(payer.amount), payer.asset_type],
            )
            .unwrap();
        let mut node = hash.rescue_hash(&[
            BLSScalar::from_u64(payer.uid),
            commitment,
            pk_hash,
            zero,
        ])[0];
        for path_node in payer.path.nodes.iter().rev() {
            let input = match (path_node.is_left_child, path_node.is_right_child) {
                (1, 0) => vec![node, path_node.siblings1, path_node.siblings2, zero],
                (0, 0) => vec![path_node.siblings1, node, path_node.siblings2, zero],
                _ => vec![path_node.siblings1, path_node.siblings2, node, zero],
            };
            node = hash.rescue_hash(&input)[0];
        }

        Self {
            payers_inputs,
            payees_commitments,
            merkle_root: node,
        }
    }
}

/// Returns the constraint system (and associated number of constraints) for a multi-inputs/outputs transaction.
/// A prover can provide honest `secret_inputs` and obtain the cs witness by calling `cs.get_and_clear_witness()`.
/// One provide an empty secret_inputs to get the constraint system `cs` for verification only.
pub(crate) fn build_multi_xfr_cs(
    secret_inputs: AMultiXfrWitness,
) -> (TurboPlonkCS, usize) {
    assert_ne!(secret_inputs.payers_secrets.len(), 0);
    assert_ne!(secret_inputs.payees_secrets.len(), 0);

    let mut cs = TurboPlonkConstraintSystem::new();
    let payers_secrets = add_payers_secrets(&mut cs, &secret_inputs.payers_secrets);
    let payees_secrets = add_payees_secrets(&mut cs, &secret_inputs.payees_secrets);

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from_u64(u64::max_value()).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;
    for payer in &payers_secrets {
        // prove knowledge of payer's secret key: pk = base^{sk}
        let (pk_var, pk_point) = cs.scalar_mul(base.clone(), payer.sec_key, SK_LEN);
        let pk_x = pk_var.get_x();
        let pk_y = pk_var.get_y();

        // prove knowledge of diversifier: pk_sign = pk^{diversifier}
        let (pk_sign_var, _) =
            cs.var_base_scalar_mul(pk_var, pk_point, payer.diversifier, SK_LEN);

        // commitments
        let com_abar_in_var =
            commit(&mut cs, payer.blind, payer.amount, payer.asset_type);

        // prove pre-image of the nullifier
        // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
        let uid_amount = cs.linear_combine(
            &[payer.uid, payer.amount, zero_var, zero_var],
            pow_2_64,
            one,
            zero,
            zero,
        );
        let nullifier_input_vars = NullifierInputVars {
            uid_amount,
            asset_type: payer.asset_type,
            pub_key_x: pk_x,
            pub_key_y: pk_y,
        };
        let nullifier_var = nullify(&mut cs, payer.sec_key, nullifier_input_vars);

        // Merkle path authentication
        let acc_elem = AccElemVars {
            uid: payer.uid,
            commitment: com_abar_in_var,
            pub_key_x: pk_x,
            pub_key_y: pk_y,
        };
        let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payer.path);

        if let Some(root) = root_var {
            cs.equal(root, tmp_root_var);
        } else {
            root_var = Some(tmp_root_var);
        }

        // prepare public inputs variables
        cs.prepare_io_variable(nullifier_var);
        cs.prepare_io_point_variable(pk_sign_var);
    }
    // prepare the publc input for merkle_root
    cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

    for payee in &payees_secrets {
        // commitment
        let com_abar_out_var =
            commit(&mut cs, payee.blind, payee.amount, payee.asset_type);

        // Range check `amount`
        // Note we don't need to range-check payers' `amount`, because those amounts are bound
        // to payers' accumulated abars, whose underlying amounts have already been range-checked
        // in the transactions that created the payers' abars.
        cs.range_check(payee.amount, AMOUNT_LEN);

        // prepare the public input for the output commitment
        cs.prepare_io_variable(com_abar_out_var);
    }

    // add asset-mixing constraints
    let inputs: Vec<(VarIndex, VarIndex)> = payers_secrets
        .into_iter()
        .map(|payer| (payer.asset_type, payer.amount))
        .collect();
    let outputs: Vec<(VarIndex, VarIndex)> = payees_secrets
        .into_iter()
        .map(|payee| (payee.asset_type, payee.amount))
        .collect();
    asset_mixing(&mut cs, &inputs, &outputs);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

/// Returns the constraint system (and associated number of constraints) for equality of values
/// in a Pedersen commitment and a Rescue commitment.
pub(crate) fn build_eq_committed_vals_cs(
    amount: BLSScalar,
    asset_type: BLSScalar,
    blind_pc: BLSScalar,
    blind_hash: BLSScalar,
    pc_gens: &PedersenGens<JubjubPoint>,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboPlonkConstraintSystem::new();
    // add secret inputs
    let amount_var = cs.new_variable(amount);
    let at_var = cs.new_variable(asset_type);
    let blind_pc_var = cs.new_variable(blind_pc);
    let blind_hash_var = cs.new_variable(blind_hash);

    // pedersen commitment
    let (point1_var, point1) =
        cs.scalar_mul(pc_gens.get_base(0).unwrap().clone(), amount_var, AMOUNT_LEN); // safe unwrap
    let (point2_var, point2) = cs.scalar_mul(
        pc_gens.get_base(1).unwrap().clone(),
        at_var,
        JUBJUB_SCALAR_BIT_LEN,
    ); // safe unwrap
    let (point3_var, point3) = cs.scalar_mul(
        pc_gens.get_blinding_base().clone(),
        blind_pc_var,
        JUBJUB_SCALAR_BIT_LEN,
    );
    let tmp_ext = cs.ecc_add(&point1_var, &point2_var, &point1, &point2);
    let ped_comm_ext =
        cs.ecc_add(&point3_var, tmp_ext.get_var(), &point3, tmp_ext.get_point());

    // rescue commitment
    let zero_var = cs.zero_var();
    let rescue_comm_var = cs.rescue_hash(&StateVar::new([
        blind_hash_var,
        amount_var,
        at_var,
        zero_var,
    ]))[0];

    // prepare public inputs
    cs.prepare_io_variable(rescue_comm_var);
    cs.prepare_io_point_variable(ped_comm_ext.into_point_var());

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

fn add_payers_secrets(
    cs: &mut TurboPlonkCS,
    secrets: &[PayerSecret],
) -> Vec<PayerSecretVars> {
    secrets
        .iter()
        .map(|secret| {
            let bls_sk = BLSScalar::from(&secret.sec_key);
            let bls_diversifier = BLSScalar::from(&secret.diversifier);
            let sec_key = cs.new_variable(bls_sk);
            let diversifier = cs.new_variable(bls_diversifier);
            let uid = cs.new_variable(BLSScalar::from_u64(secret.uid));
            let amount = cs.new_variable(BLSScalar::from_u64(secret.amount));
            let blind = cs.new_variable(secret.blind);
            let path = add_merkle_path_variables(cs, secret.path.clone());
            let asset_type = cs.new_variable(secret.asset_type);
            PayerSecretVars {
                sec_key,
                diversifier,
                uid,
                amount,
                asset_type,
                path,
                blind,
            }
        })
        .collect()
}

fn add_payees_secrets(
    cs: &mut TurboPlonkCS,
    secrets: &[PayeeSecret],
) -> Vec<PayeeSecretVars> {
    secrets
        .iter()
        .map(|secret| {
            let amount = cs.new_variable(BLSScalar::from_u64(secret.amount));
            let blind = cs.new_variable(secret.blind);
            let asset_type = cs.new_variable(secret.asset_type);
            PayeeSecretVars {
                amount,
                blind,
                asset_type,
            }
        })
        .collect()
}

struct PayerSecretVars {
    pub sec_key: VarIndex,
    pub diversifier: VarIndex,
    pub uid: VarIndex,
    pub amount: VarIndex,
    pub asset_type: VarIndex,
    pub path: MerklePathVars,
    pub blind: VarIndex,
}

struct PayeeSecretVars {
    pub amount: VarIndex,
    pub blind: VarIndex,
    pub asset_type: VarIndex,
}

// cs variables for a Merkle node
pub(crate) struct MerkleNodeVars {
    pub siblings1: VarIndex,
    pub siblings2: VarIndex,
    pub is_left_child: VarIndex,
    pub is_right_child: VarIndex,
}

// cs variables for a merkle authentication path
pub(crate) struct MerklePathVars {
    pub nodes: Vec<MerkleNodeVars>,
}

// cs variables for an accumulated element
pub(crate) struct AccElemVars {
    pub uid: VarIndex,
    pub commitment: VarIndex,
    pub pub_key_x: VarIndex,
    pub pub_key_y: VarIndex,
}

// cs variables for the nullifier PRF inputs
struct NullifierInputVars {
    pub uid_amount: VarIndex,
    pub asset_type: VarIndex,
    pub pub_key_x: VarIndex,
    pub pub_key_y: VarIndex,
}

// cs variables for ElGamal ciphertexts
pub struct ElGamalHybridCtextVars {
    #[allow(dead_code)]
    pub e1: PointVar, // r*G
    #[allow(dead_code)]
    pub symm_ctxts: Vec<VarIndex>, // ctr-mode ciphertext
}

pub(crate) fn add_merkle_path_variables(
    cs: &mut TurboPlonkCS,
    path: MTPath,
) -> MerklePathVars {
    let path_vars: Vec<MerkleNodeVars> = path
        .nodes
        .into_iter()
        .map(|node| MerkleNodeVars {
            siblings1: cs.new_variable(node.siblings1),
            siblings2: cs.new_variable(node.siblings2),
            is_left_child: cs
                .new_variable(BLSScalar::from_u32(node.is_left_child as u32)),
            is_right_child: cs
                .new_variable(BLSScalar::from_u32(node.is_right_child as u32)),
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

// Add the sorting constraints that arrange the positions of the sibling nodes.
// If `node` is the left child of parent, output (`node`, `sib1`, `sib2`);
// if `node` is the right child of parent, output (`sib1`, `sib2`, `node`);
// otherwise, output (`sib1`, `node`, `sib2`)
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

pub(crate) fn compute_merkle_root(
    cs: &mut TurboPlonkCS,
    elem: AccElemVars,
    path_vars: &MerklePathVars,
) -> VarIndex {
    let (uid, commitment, pub_key_x, pub_key_y) =
        (elem.uid, elem.commitment, elem.pub_key_x, elem.pub_key_y);
    let zero_var = cs.zero_var();
    // TODO: compute `pk_hash_var` using a simpler encoding that has fewer constraints
    let pk_hash_var =
        cs.rescue_hash(&StateVar::new([pub_key_x, pub_key_y, zero_var, zero_var]))[0];
    let mut node_var =
        cs.rescue_hash(&StateVar::new([uid, commitment, pk_hash_var, zero_var]))[0];

    for path_node in path_vars.nodes.iter().rev() {
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

// Add the commitment constraints to the constraint system:
// comm = commit(blinding, amount, asset_type)
fn commit(
    cs: &mut TurboPlonkCS,
    blinding_var: VarIndex,
    amount_var: VarIndex,
    asset_var: VarIndex,
) -> VarIndex {
    let input_var = StateVar::new([blinding_var, amount_var, asset_var, cs.zero_var()]);
    cs.rescue_hash(&input_var)[0]
}

// Add the nullifier constraints to the constraint system.
// nullifer = PRF(sk, msg = [uid_amount, asset_type, pk_x, pk_y])
// The PRF follows the Full-State Keyed Sponge (FKS) paradigm explained in https://eprint.iacr.org/2015/541.pdf
// Let perm : Fp^w -> Fp^w be a public permutation.
// Given secret key `key`, set initial state `s_key` := (0 || ... || 0 || key), the PRF output is:
// PRF^p(key, (m1, ..., mw)) = perm(s_key \xor (m1 || ... || mw))[0]
fn nullify(
    cs: &mut TurboPlonkCS,
    sk_var: VarIndex,
    nullifier_input_vars: NullifierInputVars,
) -> VarIndex {
    let (uid_amount, asset_type, pub_key_x, pub_key_y) = (
        nullifier_input_vars.uid_amount,
        nullifier_input_vars.asset_type,
        nullifier_input_vars.pub_key_x,
        nullifier_input_vars.pub_key_y,
    );
    let input_var =
        StateVar::new([uid_amount, asset_type, pub_key_x, cs.add(pub_key_y, sk_var)]);
    cs.rescue_hash(&input_var)[0]
}

/// Enforce asset_mixing constraints:
/// Inputs = [(type_in_1, v_in_1), ..., (type_in_n, v_in_n)], values {v_in_i} are guaranteed to be positive.
/// Outputs = [(type_out_1, v_out_1), ..., (type_out_m, v_out_m)], values {v_out_j} are guaranteed to be positive.
/// Goal: Prove that for every asset type, the corresponding inputs sum equals the corresponding outputs sum.
/// The circuit:
/// 1. Compute [sum_in_1, ..., sum_in_n] from inputs, where sum_in_i = \sum_{j : type_in_j == type_in_i} v_in_j
/// 2. Similarly, compute [sum_out_1, ..., sum_out_m] from outputs.
/// 3. Enumerate pair (i \in [n], j \in [m]), check that: (type_in_i != type_out_j) \lor (sum_in_i == sum_out_j)
fn asset_mixing(
    cs: &mut TurboPlonkCS,
    inputs: &[(VarIndex, VarIndex)],
    outputs: &[(VarIndex, VarIndex)],
) {
    let inputs_type_sum_amounts: Vec<(VarIndex, VarIndex)> = inputs
        .iter()
        .map(|input| {
            let zero_var = cs.zero_var();
            let sum_var = inputs.iter().fold(zero_var, |sum, other_input| {
                let adder = match_select(
                    cs,
                    input.0,       // asset_type
                    other_input.0, // asset_type
                    other_input.1,
                ); // amount
                cs.add(sum, adder)
            });
            (input.0, sum_var)
        })
        .collect();

    let outputs_type_sum_amounts: Vec<(VarIndex, VarIndex)> = outputs
        .iter()
        .map(|output| {
            let zero_var = cs.zero_var();
            let sum_var = outputs.iter().fold(zero_var, |sum, other_output| {
                let adder = match_select(
                    cs,
                    output.0,       // asset_type
                    other_output.0, // asset_type
                    other_output.1,
                ); // amount
                cs.add(sum, adder)
            });
            (output.0, sum_var)
        })
        .collect();

    for (input_type, input_sum) in inputs_type_sum_amounts {
        for &(output_type, output_sum) in &outputs_type_sum_amounts {
            let type_matched = cs.is_equal(input_type, output_type);
            // enforce `type_matched` * (input_sum - output_sum) == 0, which guarantees that
            // (`input_type` != `output_type`) \lor (`input_sum` == `output_sum`)
            let zero_var = cs.zero_var();
            let diff = cs.sub(input_sum, output_sum);
            cs.insert_mul_gate(type_matched, diff, zero_var);
        }
    }

    // check that every input type appears in the set of output types
    for &(input_type, _) in inputs {
        // \prod_j (input_type - output_type_j) == 0
        let mut product = cs.one_var();
        for &(output_type, _) in outputs {
            let diff = cs.sub(input_type, output_type);
            product = cs.mul(product, diff);
        }
        cs.insert_constant_gate(product, BLSScalar::zero());
    }

    // check that every output type appears in the set of input types
    for &(output_type, _) in outputs {
        // \prod_i (input_type_i - output_type) == 0
        let mut product = cs.one_var();
        for &(input_type, _) in inputs {
            let diff = cs.sub(input_type, output_type);
            product = cs.mul(product, diff);
        }
        cs.insert_constant_gate(product, BLSScalar::zero());
    }
}

// If `type1` == `type2`, returns a variable that equals `val`, otherwise returns a zero variable
fn match_select(
    cs: &mut TurboPlonkCS,
    type1: VarIndex,
    type2: VarIndex,
    val: VarIndex,
) -> VarIndex {
    let is_equal_var = cs.is_equal(type1, type2);
    cs.mul(is_equal_var, val)
}

#[allow(dead_code)]
fn elgamal_hybrid_encrypt(
    cs: &mut TurboPlonkCS,
    base: JubjubPoint,
    pk_var: PointVar,
    pk_point: JubjubPoint,
    rand_var: VarIndex,
    data_vars: &[VarIndex],
) -> ElGamalHybridCtextVars {
    let (e1_var, _) = cs.scalar_mul(base, rand_var, JUBJUB_SCALAR_BIT_LEN);
    let (e2_var, _) = cs.var_base_scalar_mul(
        PointVar::new(pk_var.get_x(), pk_var.get_y()),
        pk_point,
        rand_var,
        JUBJUB_SCALAR_BIT_LEN,
    );
    let zero_var = cs.zero_var();
    let key_vars = cs.rescue_hash(&StateVar::new([
        e2_var.get_x(),
        e2_var.get_y(),
        zero_var,
        zero_var,
    ]));
    let symm_ctxts_vars = cs.rescue_ctr(key_vars, data_vars);

    // prepare public inputs: the public key and the ciphertext
    cs.prepare_io_point_variable(pk_var);
    cs.prepare_io_point_variable(PointVar::new(e1_var.get_x(), e1_var.get_y()));
    for &ctxt in &symm_ctxts_vars {
        cs.prepare_io_variable(ctxt);
    }
    ElGamalHybridCtextVars {
        e1: e1_var,
        symm_ctxts: symm_ctxts_vars,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{One, Scalar, Zero};
    use crypto::basics::commitments::pedersen::PedersenGens;
    use crypto::basics::commitments::rescue::HashCommitment;
    use crypto::basics::hash::rescue::RescueInstance;
    use crypto::basics::prf::PRF;
    use poly_iops::plonk::turbo_plonk_cs::ecc::Point;
    use poly_iops::plonk::turbo_plonk_cs::TurboPlonkConstraintSystem;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::*;

    pub(crate) fn new_multi_xfr_witness_for_test(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar)>,
        seed: [u8; 32],
    ) -> AMultiXfrWitness {
        let n_payers = inputs.len();
        assert!(n_payers <= 3);
        let mut prng = ChaChaRng::from_seed(seed);
        let zero = BLSScalar::zero();
        let mut payers_secrets: Vec<PayerSecret> = inputs
            .iter()
            .enumerate()
            .map(|(i, &(amount, asset_type))| {
                let (is_left_child, is_right_child) = match i % 3 {
                    0 => (1, 0),
                    1 => (0, 0),
                    _ => (0, 1),
                };
                let node = MTNode {
                    siblings1: zero,
                    siblings2: zero,
                    is_left_child,
                    is_right_child,
                };
                PayerSecret {
                    sec_key: JubjubScalar::random(&mut prng),
                    diversifier: JubjubScalar::random(&mut prng),
                    uid: i as u64,
                    amount,
                    asset_type,
                    path: MTPath::new(vec![node]),
                    blind: BLSScalar::random(&mut prng),
                }
            })
            .collect();
        // compute the merkle leafs and update the merkle paths if there are more than 1 payers
        if n_payers > 1 {
            let hash = RescueInstance::new();
            let comm = CommScheme::new();
            let base = JubjubPoint::get_base();
            let leafs: Vec<BLSScalar> = payers_secrets
                .iter()
                .map(|payer| {
                    let pk_point = base.mul(&payer.sec_key);
                    let pk_hash = hash.rescue_hash(&[
                        pk_point.get_x(),
                        pk_point.get_y(),
                        zero,
                        zero,
                    ])[0];
                    let commitment = comm
                        .commit(
                            &payer.blind,
                            &[BLSScalar::from_u64(payer.amount), payer.asset_type],
                        )
                        .unwrap();
                    hash.rescue_hash(&[
                        BLSScalar::from_u64(payer.uid),
                        commitment,
                        pk_hash,
                        zero,
                    ])[0]
                })
                .collect();
            payers_secrets[0].path.nodes[0].siblings1 = leafs[1];
            if n_payers == 2 {
                payers_secrets[0].path.nodes[0].siblings2 = zero;
                payers_secrets[1].path.nodes[0].siblings1 = leafs[0];
                payers_secrets[1].path.nodes[0].siblings2 = zero;
            } else {
                payers_secrets[0].path.nodes[0].siblings2 = leafs[2];
                payers_secrets[1].path.nodes[0].siblings1 = leafs[0];
                payers_secrets[1].path.nodes[0].siblings2 = leafs[2];
                payers_secrets[2].path.nodes[0].siblings1 = leafs[0];
                payers_secrets[2].path.nodes[0].siblings2 = leafs[1];
            }
        }

        let payees_secrets: Vec<PayeeSecret> = outputs
            .iter()
            .map(|&(amount, asset_type)| PayeeSecret {
                amount,
                blind: BLSScalar::random(&mut prng),
                asset_type,
            })
            .collect();

        AMultiXfrWitness {
            payers_secrets,
            payees_secrets,
        }
    }

    #[test]
    fn test_elgamal_hybrid_encrypt_cs() {
        let mut cs = TurboPlonkConstraintSystem::new();

        // prepare inputs
        let base = JubjubPoint::get_base();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (_, pub_key) =
            crypto::basics::elgamal::elgamal_key_gen::<_, JubjubPoint>(&mut prng, &base);
        let pk_point = pub_key.get_point();
        let pk_var = cs.new_point_variable(Point::from(&pk_point));
        let mut data_vars = vec![];
        let mut data = vec![];
        for i in 0..10 {
            data.push(BLSScalar::from_u32(i as u32));
            data_vars.push(cs.new_variable(data[i]));
        }
        let r = JubjubScalar::random(&mut prng);
        let rand_var = cs.new_variable(BLSScalar::from(&r));

        // encrypt
        let ctxts =
            crypto::basics::elgamal::elgamal_hybrid_encrypt(&base, &pub_key, &r, &data);
        let ctxts_vars = elgamal_hybrid_encrypt(
            &mut cs, base, pk_var, pk_point, rand_var, &data_vars,
        );

        // check that the ciphertext in the witness is correct
        let witness = cs.get_and_clear_witness();
        assert_eq!(ctxts.e1.get_x(), witness[ctxts_vars.e1.get_x()]);
        assert_eq!(ctxts.e1.get_y(), witness[ctxts_vars.e1.get_y()]);
        for (&ctxt, &ctxt_var) in
            ctxts.symm_ctxts.iter().zip(ctxts_vars.symm_ctxts.iter())
        {
            assert_eq!(ctxt, witness[ctxt_var]);
        }

        // check the constraint system
        let mut public_inputs =
            vec![pub_key.get_point().get_x(), pub_key.get_point().get_y()];
        public_inputs.extend(vec![ctxts.e1.get_x(), ctxts.e1.get_y()]);
        public_inputs.extend(ctxts.symm_ctxts.clone());
        assert!(cs.verify_witness(&witness, &public_inputs).is_ok());

        let bad_pk_point = pub_key.get_point().double();
        let mut public_inputs = vec![bad_pk_point.get_x(), bad_pk_point.get_y()];
        public_inputs.extend(vec![ctxts.e1.get_x(), ctxts.e1.get_y()]);
        public_inputs.extend(ctxts.symm_ctxts.clone());
        assert!(cs.verify_witness(&witness, &public_inputs).is_err());

        let bad_e1 = ctxts.e1.double();
        let mut public_inputs =
            vec![pub_key.get_point().get_x(), pub_key.get_point().get_y()];
        public_inputs.extend(vec![bad_e1.get_x(), bad_e1.get_y()]);
        public_inputs.extend(ctxts.symm_ctxts.clone());
        assert!(cs.verify_witness(&witness, &public_inputs).is_err());

        let mut bad_symm_ctxts = ctxts.symm_ctxts;
        bad_symm_ctxts[0] = BLSScalar::from_u32(1);
        let mut public_inputs =
            vec![pub_key.get_point().get_x(), pub_key.get_point().get_y()];
        public_inputs.extend(vec![ctxts.e1.get_x(), ctxts.e1.get_y()]);
        public_inputs.extend(bad_symm_ctxts);
        assert!(cs.verify_witness(&witness, &public_inputs).is_err());
    }

    #[test]
    fn test_asset_mixing() {
        // The error path
        let mut cs = TurboPlonkConstraintSystem::new();
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);
        // asset_types = (0, 2)
        let in_types = [cs.new_variable(zero), cs.new_variable(two)];
        // amoutns = (60, 100)
        let in_amounts = [
            cs.new_variable(BLSScalar::from_u32(60)),
            cs.new_variable(BLSScalar::from_u32(100)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 2)
        let out_types = [cs.new_variable(two), cs.new_variable(two)];
        // amoutns = (40, 10)
        let out_amounts = [
            cs.new_variable(BLSScalar::from_u32(40)),
            cs.new_variable(BLSScalar::from_u32(10)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // The happy path
        let mut cs = TurboPlonkConstraintSystem::new();
        // asset_types = (0, 2, 1, 2)
        let in_types = [
            cs.new_variable(zero),
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(two),
        ];
        // amounts = (60, 100, 10, 50)
        let in_amounts = [
            cs.new_variable(BLSScalar::from_u32(60)),
            cs.new_variable(BLSScalar::from_u32(100)),
            cs.new_variable(BLSScalar::from_u32(10)),
            cs.new_variable(BLSScalar::from_u32(50)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        // asset_types = (2, 1, 1, 2, 0, 0, 2)
        let out_types = [
            cs.new_variable(two),
            cs.new_variable(one),
            cs.new_variable(one),
            cs.new_variable(two),
            cs.new_variable(zero),
            cs.new_variable(zero),
            cs.new_variable(two),
        ];
        // amounts = (40, 9, 1, 80, 50, 10, 30)
        let out_amounts = [
            cs.new_variable(BLSScalar::from_u32(40)),
            cs.new_variable(BLSScalar::from_u32(9)),
            cs.new_variable(BLSScalar::from_u32(1)),
            cs.new_variable(BLSScalar::from_u32(80)),
            cs.new_variable(BLSScalar::from_u32(50)),
            cs.new_variable(BLSScalar::from_u32(10)),
            cs.new_variable(BLSScalar::from_u32(30)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();

        asset_mixing(&mut cs, &inputs, &outputs);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        // The circuit cannot be satisfied when the set of input asset types is different from the set of output asset types.
        let mut cs = TurboPlonkConstraintSystem::new();
        // asset_types = (1, 0, 1, 2)
        let in_types = [
            cs.new_variable(one),
            cs.new_variable(zero),
            cs.new_variable(one),
            cs.new_variable(two),
        ];
        // amounts = (10, 5, 5, 10)
        let in_amounts = [
            cs.new_variable(BLSScalar::from_u32(10)),
            cs.new_variable(BLSScalar::from_u32(5)),
            cs.new_variable(BLSScalar::from_u32(5)),
            cs.new_variable(BLSScalar::from_u32(10)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        // asset_types = (0, 1, 0)
        let out_types = [
            cs.new_variable(zero),
            cs.new_variable(one),
            cs.new_variable(zero),
        ];
        // amounts = (1, 15, 4)
        let out_amounts = [
            cs.new_variable(BLSScalar::from_u32(1)),
            cs.new_variable(BLSScalar::from_u32(15)),
            cs.new_variable(BLSScalar::from_u32(4)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        asset_mixing(&mut cs, &inputs, &outputs);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        let mut cs = TurboPlonkConstraintSystem::new();
        // asset_types = (1, 0, 1)
        let in_types = [
            cs.new_variable(one),
            cs.new_variable(zero),
            cs.new_variable(one),
        ];
        // amounts = (10, 5, 5)
        let in_amounts = [
            cs.new_variable(BLSScalar::from_u32(10)),
            cs.new_variable(BLSScalar::from_u32(5)),
            cs.new_variable(BLSScalar::from_u32(5)),
        ];
        let inputs: Vec<(VarIndex, VarIndex)> = in_types
            .iter()
            .zip(in_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        // asset_types = (0, 1, 2)
        let out_types = [
            cs.new_variable(zero),
            cs.new_variable(one),
            cs.new_variable(two),
        ];
        // amounts = (5, 15, 4)
        let out_amounts = [
            cs.new_variable(BLSScalar::from_u32(5)),
            cs.new_variable(BLSScalar::from_u32(15)),
            cs.new_variable(BLSScalar::from_u32(4)),
        ];
        let outputs: Vec<(VarIndex, VarIndex)> = out_types
            .iter()
            .zip(out_amounts.iter())
            .map(|(&asset_type, &amount)| (asset_type, amount))
            .collect();
        asset_mixing(&mut cs, &inputs, &outputs);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_eq_committed_vals_cs() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        // compute Rescue commitment
        let comm = HashCommitment::new();
        let amount = BLSScalar::from_u32(71);
        let asset_type = BLSScalar::from_u32(52);
        let blind_hash = BLSScalar::random(&mut prng);
        let hash_comm = comm.commit(&blind_hash, &[amount, asset_type]).unwrap();

        // compute Pedersen commitment
        let pc_gens_jubjub = PedersenGens::<JubjubPoint>::new(2);
        let amount_jj = JubjubScalar::from_u32(71);
        let at_jj = JubjubScalar::from_u32(52);
        let blind_pc = JubjubScalar::random(&mut prng);
        let ped_comm = pc_gens_jubjub
            .commit(&[amount_jj, at_jj], &blind_pc)
            .unwrap(); // safe unwrap

        // compute cs
        let (mut cs, _) = build_eq_committed_vals_cs(
            amount,
            asset_type,
            BLSScalar::from(&blind_pc),
            blind_hash,
            &pc_gens_jubjub,
        );
        let witness = cs.get_and_clear_witness();
        let mut pub_inputs = vec![hash_comm, ped_comm.get_x(), ped_comm.get_y()];

        // Check the constraints
        assert!(cs.verify_witness(&witness, &pub_inputs).is_ok());
        pub_inputs[0].add_assign(&BLSScalar::one());
        assert!(cs.verify_witness(&witness, &pub_inputs).is_err());
    }

    #[test]
    fn test_commit() {
        let mut cs = TurboPlonkConstraintSystem::new();
        let amount = BLSScalar::from_u32(7);
        let asset_type = BLSScalar::from_u32(5);
        let comm = HashCommitment::new();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let blind = BLSScalar::random(&mut prng);
        let commitment = comm.commit(&blind, &[amount, asset_type]).unwrap(); // safe unwrap

        let amount_var = cs.new_variable(amount);
        let asset_var = cs.new_variable(asset_type);
        let blind_var = cs.new_variable(blind);
        let comm_var = commit(&mut cs, blind_var, amount_var, asset_var);
        let mut witness = cs.get_and_clear_witness();

        // Check commitment consistency
        assert_eq!(witness[comm_var], commitment);

        // Check the constraints
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        witness[comm_var] = BLSScalar::zero();
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_nullify() {
        let one = BLSScalar::one();
        let zero = BLSScalar::zero();
        let mut cs = TurboPlonkConstraintSystem::new();
        let mut prng = ChaChaRng::from_seed([1u8; 32]);
        let sk = BLSScalar::random(&mut prng);
        let bytes = vec![1u8; 32];
        let uid_amount = BLSScalar::from_bytes(&bytes[..]).unwrap(); // safe unwrap
        let asset_type = one;
        let pk = Point::new(zero, one);
        let prf = PRF::new();
        let expected_output =
            prf.eval(&sk, &[uid_amount, asset_type, *pk.get_x(), *pk.get_y()]);

        let sk_var = cs.new_variable(sk);
        let uid_amount_var = cs.new_variable(uid_amount);
        let asset_var = cs.new_variable(asset_type);
        let pk_var = cs.new_point_variable(pk);
        let nullifier_input_var = NullifierInputVars {
            uid_amount: uid_amount_var,
            asset_type: asset_var,
            pub_key_x: pk_var.get_x(),
            pub_key_y: pk_var.get_y(),
        };
        let nullifier_var = nullify(&mut cs, sk_var, nullifier_input_var);
        let mut witness = cs.get_and_clear_witness();

        // Check PRF output consistency
        assert_eq!(witness[nullifier_var], expected_output);

        // Check the constraints
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        witness[nullifier_var] = zero;
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_sort() {
        let mut cs = TurboPlonkConstraintSystem::new();
        let num: Vec<BLSScalar> =
            (0..5).map(|x| BLSScalar::from_u32(x as u32)).collect();
        let node_var = cs.new_variable(num[2]);
        let sib1_var = cs.new_variable(num[3]);
        let sib2_var = cs.new_variable(num[4]);
        let is_left_var = cs.new_variable(num[0]);
        let is_right_var = cs.new_variable(num[1]);
        let out_state = sort(
            &mut cs,
            node_var,
            sib1_var,
            sib2_var,
            is_left_var,
            is_right_var,
        );
        let mut witness = cs.get_and_clear_witness();
        let output: Vec<BLSScalar> = out_state
            .as_slice()
            .iter()
            .map(|&idx| witness[idx])
            .collect();
        // node_var is at the right position
        let expected_output = vec![
            witness[sib1_var],
            witness[sib2_var],
            witness[node_var],
            witness[cs.zero_var()],
        ];
        // Check output correctness
        assert_eq!(output, expected_output);

        // Check constraints
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        witness[sib1_var] = BLSScalar::one();
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_merkle_root() {
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);
        let mut cs = TurboPlonkConstraintSystem::new();
        let uid_var = cs.new_variable(one);
        let comm_var = cs.new_variable(two);
        let pk_var = cs.new_point_variable(Point::new(zero, one));
        let elem = AccElemVars {
            uid: uid_var,
            commitment: comm_var,
            pub_key_x: pk_var.get_x(),
            pub_key_y: pk_var.get_y(),
        };

        let path_node1 = MTNode {
            siblings1: one,
            siblings2: three,
            is_left_child: 1u8,
            is_right_child: 0u8,
        };
        let path_node2 = MTNode {
            siblings1: two,
            siblings2: four,
            is_left_child: 0u8,
            is_right_child: 1u8,
        };
        // compute the root value
        let hash = RescueInstance::new();
        let pk_hash =
            hash.rescue_hash(&[/*pk_x=*/ zero, /*pk_y=*/ one, zero, zero])[0];
        let leaf =
            hash.rescue_hash(&[/*uid=*/ one, /*comm=*/ two, pk_hash, zero])[0];
        // leaf is the right child of node1
        let node1 =
            hash.rescue_hash(&[path_node2.siblings1, path_node2.siblings2, leaf, zero])
                [0];
        // node1 is the left child of the root
        let root =
            hash.rescue_hash(&[node1, path_node1.siblings1, path_node1.siblings2, zero])
                [0];

        // compute the constraints
        let path = MTPath::new(vec![path_node1, path_node2]);
        let path_vars = add_merkle_path_variables(&mut cs, path);
        let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

        // Check Merkle root correctness
        let mut witness = cs.get_and_clear_witness();
        assert_eq!(witness[root_var], root);

        // Check constraints
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        witness[root_var] = one;
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_add_merkle_path_variables() {
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        // happy path: `is_left_child`/`is_right_child`/`is_left_child + is_right_child` are boolean
        let mut cs = TurboPlonkConstraintSystem::new();
        let node = MTNode {
            siblings1: one,
            siblings2: zero,
            is_left_child: 1u8,
            is_right_child: 0u8,
        };
        let path = MTPath::new(vec![node]);
        let _ = add_merkle_path_variables(&mut cs, path);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());

        // cs cannot be satisfied when `is_left_child` (or `is_right_child`) is not boolean
        let mut cs = TurboPlonkConstraintSystem::new();
        // is_left is not boolean
        let node = MTNode {
            siblings1: one,
            siblings2: zero,
            is_left_child: 2u8,
            is_right_child: 0u8,
        };
        let path = MTPath::new(vec![node]);
        let _ = add_merkle_path_variables(&mut cs, path);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());

        // cs cannot be satisfied when `is_left_child` + `is_right_child` is not boolean
        let mut cs = TurboPlonkConstraintSystem::new();
        // `is_left` and `is_right` are both 1
        let node = MTNode {
            siblings1: one,
            siblings2: zero,
            is_left_child: 1u8,
            is_right_child: 1u8,
        };
        let path = MTPath::new(vec![node]);
        let _ = add_merkle_path_variables(&mut cs, path);
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_err());
    }

    #[test]
    fn test_build_multi_xfr_cs() {
        // single-asset xfr: good witness
        let zero = BLSScalar::zero();
        let inputs = vec![
            (/*amount=*/ 30, /*asset_type=*/ zero),
            (20, zero),
            (10, zero),
        ];
        let mut outputs = vec![(19, zero), (17, zero), (24, zero)];
        test_xfr_cs(inputs.to_vec(), outputs.to_vec(), true);

        // single-asset xfr: bad witness
        outputs[0].0 = 18;
        test_xfr_cs(inputs, outputs, false);

        // multi-assets xfr: good witness
        let one = BLSScalar::one();
        let inputs = vec![
            (/*amount=*/ 50, /*asset_type=*/ zero),
            (60, one),
            (20, zero),
        ];
        let mut outputs = vec![
            (19, one),
            (15, zero),
            (1, one),
            (35, zero),
            (20, zero),
            (40, one),
        ];
        test_xfr_cs(inputs.to_vec(), outputs.to_vec(), true);

        // multi-assets xfr: bad witness
        outputs[0].0 = 18;
        test_xfr_cs(inputs, outputs, false);
    }

    fn test_xfr_cs(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar)>,
        witness_is_valid: bool,
    ) {
        let secret_inputs = new_multi_xfr_witness_for_test(inputs, outputs, [0u8; 32]);
        let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);

        // check the constraints
        let (mut cs, _) = build_multi_xfr_cs(secret_inputs);
        let witness = cs.get_and_clear_witness();
        let online_inputs = pub_inputs.to_vec();
        let verify = cs.verify_witness(&witness, &online_inputs);
        if witness_is_valid {
            pnk!(verify);
        } else {
            assert!(verify.is_err());
        }
    }
}
