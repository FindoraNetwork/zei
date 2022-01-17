#[cfg(test)]
mod tests {
    use crate::anon_xfr::circuits::{
        add_merkle_path_variables, compute_merkle_root, AccElemVars,
    };
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::{
        AnonBlindAssetRecord, MTNode, MTPath, OpenAnonBlindAssetRecord,
    };
    use accumulators::merkle_tree::{
        generate_path_keys, get_path_from_uid, Path, PersistentMerkleTree, BASE_KEY,
    };
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{Scalar, Zero};
    use crypto::basics::hash::rescue::RescueInstance;
    use parking_lot::RwLock;
    use poly_iops::plonk::turbo_plonk_cs::ecc::Point;
    use poly_iops::plonk::turbo_plonk_cs::TurboPlonkConstraintSystem;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::*;
    use std::sync::Arc;
    use std::thread;
    use storage::db::{RocksDB, TempRocksDB};
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;

    #[test]
    pub fn test_generate_path_keys() {
        let keys = generate_path_keys(vec![Path::Right, Path::Left, Path::Middle]);
        assert_eq!(
            keys,
            vec![
                "dense_merkle_tree:root:",
                "dense_merkle_tree:root:r",
                "dense_merkle_tree:root:rl",
                "dense_merkle_tree:root:rlm"
            ]
        );
    }

    #[test]
    fn test_get_path() {
        let zero_path = get_path_from_uid(0);
        assert_eq!(zero_path[0], Path::Left);
        assert_eq!(zero_path[1], Path::Left);
        assert_eq!(zero_path[2], Path::Left);
        assert_eq!(zero_path[40], Path::Left);

        let one_path = get_path_from_uid(1);
        assert_eq!(
            one_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle
            ]
        );

        let two_path = get_path_from_uid(2);
        assert_eq!(
            two_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Right
            ]
        );

        let three_path = get_path_from_uid(3);
        assert_eq!(
            three_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle,
                Path::Left
            ]
        );

        let four_path = get_path_from_uid(4);
        assert_eq!(
            four_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle,
                Path::Middle
            ]
        );

        let five_path = get_path_from_uid(5);
        assert_eq!(
            five_path,
            vec![
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Left,
                Path::Middle,
                Path::Right
            ]
        );
    }

    #[test]
    fn test_persistent_merkle_tree() {
        let hash = RescueInstance::new();

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("mystore", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        assert_eq!(
            mt.get_current_root_hash().unwrap(),
            hash.rescue_hash(&[
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero()
            ])[0]
        );

        let abar =
            AnonBlindAssetRecord::from_oabar(&OpenAnonBlindAssetRecord::default());
        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());

        assert_ne!(
            mt.get_current_root_hash().unwrap(),
            hash.rescue_hash(&[
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero(),
                BLSScalar::zero()
            ])[0]
        );

        let mut key = BASE_KEY.to_owned();
        for _t in 1..42 {
            key.push('l');
            let res = mt.get(key.as_bytes());
            assert!(res.is_ok());
            assert!(res.unwrap().is_some());
            // println!("{}       {} {:#?}", t, key, res.unwrap().unwrap());
        }

        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        let key2 = "dense_merkle_tree:root:llllllllllllllllllllllllllllllllllllllllm";
        let mut res = mt.get(key2.as_bytes());
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        let key3 = "dense_merkle_tree:root:llllllllllllllllllllllllllllllllllllllllr";
        res = mt.get(key3.as_bytes());
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        assert!(mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .is_ok());
        res = mt.get(key3.as_bytes());
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        assert!(mt.generate_proof(0).is_ok());
        assert!(mt.generate_proof(1).is_ok());
        assert!(mt.generate_proof(2).is_ok());

        assert!(mt.generate_proof(3).is_err());
        assert!(mt.generate_proof(4).is_err());
        assert!(mt.generate_proof(11234).is_err());
    }

    #[test]
    fn test_persistant_merkle_tree_proof_commitment() {
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

        let mut cs = TurboPlonkConstraintSystem::new();
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
                        is_left_child: e.is_left_child,
                        is_right_child: e.is_right_child,
                    })
                    .collect(),
            },
        );
        let root_var = compute_merkle_root(&mut cs, elem, &path_vars);

        // Check Merkle root correctness
        let witness = cs.get_and_clear_witness();
        assert!(cs.verify_witness(&witness, &[]).is_ok());
        assert_eq!(witness[root_var], mt.get_current_root_hash().unwrap());

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
