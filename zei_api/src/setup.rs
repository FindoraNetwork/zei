//The Public Setup needed for Proofs
use crate::anon_xfr::circuits::{
    build_eq_committed_vals_cs, build_multi_xfr_cs, AMultiXfrWitness, TurboPlonkCS,
    TREE_DEPTH,
};
use algebra::bls12_381::BLSScalar;
use algebra::groups::Zero;
use algebra::jubjub::JubjubPoint;
use bulletproofs::BulletproofGens;
use crypto::basics::commitments::pedersen::PedersenGens;
use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
use poly_iops::commitments::kzg_poly_com::{
    KZGCommitmentScheme, KZGCommitmentSchemeBLS,
};
use poly_iops::plonk::plonk_setup::{preprocess_prover, ProverParams, VerifierParams};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use ruc::*;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use utils::errors::ZeiError;
use utils::save_to_file;

//Shared by all members of the ledger
#[derive(Serialize, Deserialize)]
pub struct PublicParams {
    pub bp_gens: BulletproofGens,
    pub bp_circuit_gens: BulletproofGens,
    pub pc_gens: RistrettoPedersenGens,
    pub range_proof_bits: usize,
}

#[derive(Serialize, Deserialize)]
pub struct UserParams {
    pub bp_params: PublicParams,
    pub pcs: KZGCommitmentSchemeBLS,
    pub cs: TurboPlonkCS,
    pub prover_params: ProverParams<KZGCommitmentSchemeBLS>,
}

pub struct NodeParams {
    pub bp_params: PublicParams,
    pub pcs: KZGCommitmentSchemeBLS,
    pub cs: TurboPlonkCS,
    pub verifier_params: VerifierParams<KZGCommitmentSchemeBLS>,
}

pub const BULLET_PROOF_RANGE: usize = 32;

pub const DEFAULT_BP_NUM_GENS: usize = 256;

pub const MAX_PARTY_NUMBER: usize = 128;

const COMMON_SEED: [u8; 32] = [0u8; 32];

fn from_file<T: for<'de> Deserialize<'de>>(filename: &str) -> Result<T> {
    let contents = fs::read(filename).c(d!(ZeiError::ParameterError))?;
    bincode::deserialize(&contents).c(d!(ZeiError::DeserializationError))
}

#[allow(clippy::new_without_default)]
impl PublicParams {
    pub fn new(bp_num_gens: usize) -> PublicParams {
        //Create a new BulletproofGens generators
        let range_generators =
            BulletproofGens::new(BULLET_PROOF_RANGE, MAX_PARTY_NUMBER);
        let circuit_generators = BulletproofGens::new(bp_num_gens, 1);
        // Pedersen commitment parameters
        let pc_gens = RistrettoPedersenGens::default();

        PublicParams {
            bp_gens: range_generators,
            bp_circuit_gens: circuit_generators,
            pc_gens,
            range_proof_bits: BULLET_PROOF_RANGE,
        }
    }

    pub fn from_file(filename: &str) -> Result<PublicParams> {
        from_file::<PublicParams>(filename).c(d!())
    }

    /// Generate the parameters from a file if it exists.
    /// The filename is derived from some internal path and the values of `bp_num_gens`
    /// Otherwise it generates the parameters and store them on disk so that these parameters can be retrieved later.
    /// * `bp_num_gens` - number of generators for the circuit.
    /// * `path` - name of the file where the parameters are stored. If set to None, a hardcoded filename will be used.
    /// * `returns` the public parameters
    ///
    pub fn from_file_if_exists(
        bp_num_gens: usize,
        path: Option<String>,
    ) -> PublicParams {
        let default_filename = format!("public_params_{}.bin", bp_num_gens);
        let default_filename = compute_full_path_from_root(&default_filename);
        let full_filename = path.unwrap_or(default_filename);

        let public_params = Self::from_file(&full_filename).unwrap_or_else(|_| {
            let res = Self::new(bp_num_gens);
            let res_ser = bincode::serialize(&res).unwrap(); // safe unwrap PublicParam serialization tested
            save_to_file(&res_ser, PathBuf::from(full_filename));
            res
        });
        public_params
    }

    /// Has no effect if new_size.next_power_of_two() is less or equal than current capacity
    pub fn increase_circuit_gens(&mut self, new_size: usize) {
        self.bp_circuit_gens
            .increase_capacity(new_size.next_power_of_two());
    }
}

impl Default for PublicParams {
    fn default() -> Self {
        PublicParams::new(DEFAULT_BP_NUM_GENS)
    }
}

impl UserParams {
    pub fn new(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
        bp_num_gens: usize,
    ) -> UserParams {
        let (cs, n_constraints) = match tree_depth {
            Some(depth) => {
                build_multi_xfr_cs(AMultiXfrWitness::fake(n_payers, n_payees, depth))
            }
            None => build_multi_xfr_cs(AMultiXfrWitness::fake(
                n_payers, n_payees, TREE_DEPTH,
            )),
        };

        let pcs = KZGCommitmentScheme::new(
            n_constraints + 2,
            &mut ChaChaRng::from_seed([0u8; 32]),
        );


        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
        UserParams {
            bp_params: PublicParams::new(bp_num_gens),
            pcs,
            cs,
            prover_params,
        }
    }

    //This function is the same that new, but max_degree_poly_com allows to set the size of the CRS
    //the parameter max_degree_poly_com is padded to the minimum power of two grater than it.
    pub fn new_max_degree_poly_com(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
        bp_num_gens: usize,
        max_degree_poly_com: usize,
    ) -> UserParams {
        let (cs, /*n_constrains*/_ ) = match tree_depth {
            Some(depth) => {
                build_multi_xfr_cs(AMultiXfrWitness::fake(n_payers, n_payees, depth))
            }
            None => build_multi_xfr_cs(AMultiXfrWitness::fake(
                n_payers, n_payees, TREE_DEPTH,
            )),
        };

        max_degree_poly_com.next_power_of_two();

        let pcs = KZGCommitmentScheme::new(
            max_degree_poly_com + 2,
            &mut ChaChaRng::from_seed([0u8; 32]),
        );

        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
        UserParams {
            bp_params: PublicParams::new(bp_num_gens),
            pcs,
            cs,
            prover_params,
        }
    }

    pub fn eq_committed_vals_params() -> UserParams {
        let zero = BLSScalar::zero();
        let pc_gens_jubjub = PedersenGens::<JubjubPoint>::new(2);
        let (cs, n_constraints) =
            build_eq_committed_vals_cs(zero, zero, zero, zero, &pc_gens_jubjub);
        let pcs = KZGCommitmentScheme::new(
            n_constraints + 2,
            &mut ChaChaRng::from_seed([0u8; 32]),
        );
        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
        UserParams {
            bp_params: PublicParams::new(DEFAULT_BP_NUM_GENS),
            pcs,
            cs,
            prover_params,
        }
    }

    pub fn from_file(filename: &str) -> Result<UserParams> {
        from_file::<UserParams>(filename).c(d!())
    }

    /// Generate the parameters from a file if it exists.
    /// The filename is derived from some internal path and the values of `n_payers`,`n_payees`,`tree_depth`and `bp_num_gens`.
    /// Otherwise it generates the parameters and store them on disk so that these parameters can be retrieved later.
    /// * `n_payers` - number of payers
    /// * `n_payees` - number of payeers
    /// * `tree_depth` - depth of the merkle tree
    /// * `bp_num_gens` - number of BP generators for the circuit
    /// * `path` - path to retrieve the file. If set to None, a default value will be used
    /// * `returns` the parameters for the user
    pub fn from_file_if_exists(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
        bp_num_gens: usize,
        path: Option<String>,
    ) -> Result<UserParams> {
        let default_filename = compute_full_path_from_root(&format!(
            "user_params_{}_{}_{}_{}.bin",
            n_payers,
            n_payees,
            tree_depth.unwrap_or(0_usize),
            bp_num_gens
        ));
        let full_filename = path.unwrap_or(default_filename);

        let user_params = Self::from_file(&full_filename).or_else(|_| {
            let res = Self::new(n_payers, n_payees, tree_depth, bp_num_gens);
            let val = bincode::serialize(&res).unwrap();
            save_to_file(&val, PathBuf::from(full_filename));
            Ok(res)
        });
        user_params
    }
}

impl NodeParams {
    pub fn new(
        tree_depth: Option<usize>,
        n_payers: usize,
        n_payees: usize,
        bp_num_gens: usize,
    ) -> Result<NodeParams> {
        let user_params = UserParams::new(n_payers, n_payees, tree_depth, bp_num_gens);
        Ok(Self::from(user_params))
    }
}

impl From<UserParams> for NodeParams {
    fn from(params: UserParams) -> Self {
        NodeParams {
            bp_params: params.bp_params,
            pcs: params.pcs,
            cs: params.cs,
            verifier_params: params.prover_params.get_verifier_params(),
        }
    }
}

fn compute_full_path_from_root(filename: &str) -> String {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("data");
    d.push(filename);
    let path = d.to_str().unwrap();
    path.to_string()
}

#[cfg(test)]
mod test {
    use crate::setup::{UserParams, DEFAULT_BP_NUM_GENS};

    #[test]
    fn test_params_serialization() {
        let params =
            UserParams::from_file_if_exists(1, 1, Some(1), DEFAULT_BP_NUM_GENS, None)
                .unwrap();

        let v = bincode::serialize(&params).unwrap();
        let params_de: UserParams = bincode::deserialize(&v).unwrap();

        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);
    }
}
