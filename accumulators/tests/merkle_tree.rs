use mem_db::MemoryDB;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Instant;
use storage::state::{ChainState, State};
use storage::store::PrefixedStore;
use zei_accumulators::merkle_tree::{verify, PersistentMerkleTree, TREE_DEPTH};
use zei_algebra::{bls12_381::BLSScalar, prelude::*};

#[test]
fn test_merkle_tree() {
    let fdb = MemoryDB::new();
    let ver_window = 100;
    let cs = Arc::new(RwLock::new(ChainState::new(
        fdb,
        "test_db".to_string(),
        ver_window,
    )));
    let mut state = State::new(cs, false);
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();
    assert_eq!(0, mt.version());

    let start = Instant::now();
    for _ in 0..10 {
        let sid_0 = mt.add_commitment_hash(BLSScalar::one()).unwrap();
        let proof0 = mt.generate_proof(sid_0).unwrap();
        assert_eq!(proof0.uid, sid_0);
        assert!(verify(BLSScalar::one(), &proof0));
    }
    let end = start.elapsed();
    println!("Time: {:?} microseconds", end.as_micros());
    let v1 = mt.commit().unwrap();
    let root1 = mt.get_root().unwrap();
    assert_eq!(v1, mt.version());
    assert_eq!(1, v1);

    let sid_x = mt.add_commitment_hash(BLSScalar::one()).unwrap();
    let proofx = mt.generate_proof_with_depth(sid_x, 10).unwrap();
    let v2 = mt.commit().unwrap();
    assert_eq!(2, mt.version());
    let root2 = mt.get_root_with_depth(10).unwrap();

    assert!(verify(BLSScalar::one(), &proofx));
    let proof4 = mt.generate_proof_with_depth(sid_x, 14).unwrap();
    assert!(verify(BLSScalar::one(), &proof4));
    assert!(mt.generate_proof_with_depth(sid_x, 21).is_err());
    assert!(mt.generate_proof_with_depth(sid_x, 2).is_err());

    assert_eq!(
        mt.get_root_with_depth_and_version(TREE_DEPTH, v1).unwrap(),
        root1
    );
    assert_eq!(mt.get_root_with_depth_and_version(10, v2).unwrap(), root2);
}
