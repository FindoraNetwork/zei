#[cfg(test)]
mod tests {
    use crate::anon_xfr::circuits::{
        add_merkle_path_variables, compute_merkle_root, AccElemVars,
    };
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::{
        AnonBlindAssetRecord, MTNode, MTPath, OpenAnonBlindAssetRecord,
    };
    use accumulators::merkle_tree::{PersistentMerkleTree, TreePath};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{Scalar, Zero};
    use crypto::basics::hash::rescue::RescueInstance;
    use parking_lot::RwLock;
    use poly_iops::plonk::constraint_system::{ecc::Point, TurboConstraintSystem};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::*;
    use std::sync::Arc;
    use std::thread;
    use storage::db::{RocksDB, TempRocksDB};
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;

    #[test]
    fn test_persistent_merkle_tree() {
        let hash = RescueInstance::new();

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        assert_eq!(mt.get_root().unwrap(), BLSScalar::zero(),);

        let abar =
            AnonBlindAssetRecord::from_oabar(&OpenAnonBlindAssetRecord::default());
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        assert_ne!(
            mt.get_root().unwrap(),
            hash.rescue_hash(&[
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero()
            ])[0]
        );

        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        assert!(mt.generate_proof(0).is_ok());
        assert!(mt.generate_proof(1).is_ok());
        assert!(mt.generate_proof(2).is_ok());

        assert!(mt.generate_proof(3).is_err());
        assert!(mt.generate_proof(4).is_err());
        assert!(mt.generate_proof(11234).is_err());
    }

    #[test]
    fn test_persistent_merkle_tree_proof_commitment() {
        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);
        let abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        let proof = mt.generate_proof(0).unwrap();

        let mut cs = TurboConstraintSystem::new();
        let uid_var = cs.new_variable(BLSScalar::from_u64(0));
        let comm_var = cs.new_variable(abar.amount_type_commitment);
        let pk_var = cs.new_point_variable(Point::new(
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
        ));
        let elem = AccElemVars {
            uid: uid_var,
            commitment: comm_var,
            pub_key_x: pk_var.get_x(),
            pub_key_y: pk_var.get_y(),
        };

        let path_vars = add_merkle_path_variables(
            &mut cs,
            MTPath {
                nodes: proof
                    .nodes
                    .iter()
                    .map(|e| MTNode {
                        siblings1: e.siblings1,
                        siblings2: e.siblings2,
                        is_left_child: (e.path == TreePath::Left) as u8,
                        is_right_child: (e.path == TreePath::Right) as u8,
                    })
                    .collect(),
            },
        );
        let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

        // Check Merkle root correctness
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        assert_eq!(witness[root_var], mt.get_root().unwrap());

        let _ = mt.commit();
    }

    #[test]
    fn test_persistent_merkle_tree_recovery() {
        let path = thread::current().name().unwrap().to_owned();
        let _ = build_and_save_dummy_tree(path.clone()).unwrap();

        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mt = PersistentMerkleTree::new(store).unwrap();

        assert_eq!(mt.version(), 4);
        assert_eq!(mt.entry_count(), 4);
    }

    #[test]
    fn test_init_tree() {
        let path = thread::current().name().unwrap().to_owned();

        let fdb = TempRocksDB::open(path).expect("failed to open db");

        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        build_tree(&mut state);
        build_tree(&mut state);
    }

    #[allow(dead_code)]
    fn build_tree(state: &mut State<TempRocksDB>) {
        let store = PrefixedStore::new("mystore", state);
        let _mt = PersistentMerkleTree::new(store).unwrap();
    }

    #[allow(dead_code)]
    fn build_and_save_dummy_tree(path: String) -> Result<()> {
        let fdb = RocksDB::open(path).expect("failed to open db");

        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let mut key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);
        let mut abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        mt.commit()?;

        key_pair = AXfrKeyPair::generate(&mut prng);
        abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        mt.commit()?;

        key_pair = AXfrKeyPair::generate(&mut prng);
        abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        mt.commit()?;

        key_pair = AXfrKeyPair::generate(&mut prng);
        abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        mt.commit()?;

        Ok(())
    }

    #[test]
    pub fn test_merkle_proofs() {
        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        let store = PrefixedStore::new("mystore", &mut state);
        let mut pmt = PersistentMerkleTree::new(store).unwrap();

        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let key_pair: AXfrKeyPair = AXfrKeyPair::generate(&mut prng);
        let abar0 = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        let abar1 = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };
        let abar2 = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };

        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar0))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar1))
            .unwrap();
        pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar2))
            .unwrap();
        pmt.commit().unwrap();
    }

    fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();

        let pk_hash = hash.rescue_hash(&[
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0];

        hash.rescue_hash(&[
            BLSScalar::from_u64(uid),
            abar.amount_type_commitment,
            pk_hash,
            BLSScalar::zero(),
        ])[0]
    }
}
