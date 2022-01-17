use algebra::bls12_381::BLSScalar;
use algebra::groups::Zero;
use crypto::basics::hash::rescue::RescueInstance;
use ruc::*;
use std::borrow::Borrow;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use storage::db::MerkleDB;
use storage::store::{ImmutablePrefixedStore, PrefixedStore, Stated, Store};
use utils::serialization::ZeiFromToBytes;

// const HASH_SIZE: i32 = 32;             // assuming we are storing SHA256 hash of abar
// const MAX_KEYS: u64 = u64::MAX;
const TREE_DEPTH: usize = 41; // ceil(log(u64::MAX, 3))
pub const BASE_KEY: &str = "dense_merkle_tree:root:";
const ENTRY_COUNT_KEY: &str = "dense_merkle_tree:entrycount:";

#[derive(Debug, PartialEq, Clone)]
pub enum Path {
    Left,
    Middle,
    Right,
}

///
/// PersistentMerkleTree is a 3-ary merkle tree
///
/// Usage:
///    ```
///
///     use std::collections::HashMap;
///     use std::thread;
///     use storage::db::TempRocksDB;
///     use std::sync::Arc;
///     use parking_lot::RwLock;
///     use storage::state::{ChainState, State};
///     use storage::store::PrefixedStore;
///     use accumulators::merkle_tree::PersistentMerkleTree;
///     use algebra::bls12_381::BLSScalar;
///     use algebra::groups::Zero;
///     use crypto::basics::hash::rescue::RescueInstance;
///
///         let hash = RescueInstance::new();
///
///         let path = thread::current().name().unwrap().to_owned();
///         let fdb = TempRocksDB::open(path).expect("failed to open db");
///         let cs = Arc::new(RwLock::new(ChainState::new(
///             fdb,
///             "test_db".to_string(),
///             0,
///         )));
///         let mut state = State::new(cs, false);
///         let mut store = PrefixedStore::new("my_store", &mut state);
///         let mut mt = PersistentMerkleTree::new(store).unwrap();
///
///         mt.get_current_root_hash();
///
///         mt.add_commitment_hash(BLSScalar::default());
///            mt.commit();
///         mt.generate_proof(0);
///
///
/// ```
///
///
///
///
///
///

pub struct PersistentMerkleTree<'a, D: MerkleDB> {
    entry_count: u64,
    version: u64,
    store: PrefixedStore<'a, D>,
}

impl<'a, D: MerkleDB> PersistentMerkleTree<'a, D> {
    // Generates a new PersistentMerkleTree based on a sessioned KV store
    pub fn new(mut store: PrefixedStore<'a, D>) -> Result<PersistentMerkleTree<'a, D>> {
        let mut entry_count = 0;
        let mut version = 0;
        match store.get(BASE_KEY.as_bytes()).unwrap() {
            None => {
                let hash = RescueInstance::new();
                let zero_hash: BLSScalar = hash.rescue_hash(&[
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                ])[0];
                store
                    .set(BASE_KEY.as_bytes(), zero_hash.zei_to_bytes())
                    .unwrap();
                store
                    .set(ENTRY_COUNT_KEY.as_bytes(), 0u64.to_be_bytes().to_vec())
                    .unwrap();
                store.state_mut().commit(0).c(d!())?;
            }
            Some(_) => {
                // TODO: In the case that a pre-existing tree is loaded, calculate the entry-count.
                let ecb = store.get(ENTRY_COUNT_KEY.as_bytes()).unwrap();
                match ecb {
                    Some(bytes) => {
                        let array: [u8; 8] = [
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                            bytes[6], bytes[7],
                        ];
                        entry_count = u64::from_be_bytes(array);
                        version = store.height().c(d!())?;
                    }
                    None => return Err(eg!("entry count key not found in Store")),
                };
            }
        };
        Ok(PersistentMerkleTree {
            entry_count,
            version,
            store,
        })
    }

    pub fn add_commitment_hash(&mut self, hash: BLSScalar) -> Result<u64> {
        let mut cache = Cache::new();
        // 1. generate keys of ancestors for update in tree
        let path = get_path_from_uid(self.entry_count);
        let keys = generate_path_keys(path);

        let (leaf, ancestors) = keys.as_slice().split_last().unwrap();

        // 2. Hash ABAR and save leaf node
        let uid = self.entry_count;
        cache.set(leaf, hash.zei_to_bytes());

        // 3. update hash of all ancestors of the new leaf
        for node_key in ancestors.iter().rev() {
            let parse_hash = |key: &str| -> Result<BLSScalar> {
                if let Some(b) = cache.get(key) {
                    return BLSScalar::zei_from_bytes(b.as_slice());
                }
                match self.get(key.as_bytes()).unwrap() {
                    Some(b) => BLSScalar::zei_from_bytes(b.as_slice()),
                    None => Ok(BLSScalar::zero()),
                }
            };
            let left_child_hash = parse_hash(format!("{}{}", node_key, "l").as_str())?;
            let middle_child_hash = parse_hash(format!("{}{}", node_key, "m").as_str())?;
            let right_child_hash = parse_hash(format!("{}{}", node_key, "r").as_str())?;

            let hasher = RescueInstance::new();
            let hash = hasher.rescue_hash(&[
                left_child_hash,
                middle_child_hash,
                right_child_hash,
                BLSScalar::zero(),
            ])[0];
            cache.set(node_key, BLSScalar::zei_to_bytes(&hash));
        }

        self.entry_count += 1;
        cache.set(ENTRY_COUNT_KEY, self.entry_count.to_be_bytes().to_vec());

        for (k, v) in cache.iter() {
            self.store.set(k.as_bytes(), v.to_vec())?;
        }
        Ok(uid)
    }

    pub fn generate_proof(&self, id: u64) -> Result<Proof> {
        let path = get_path_from_uid(id);
        let keys = generate_path_keys(path);

        let mut previous = keys.first().unwrap();

        let nodes: Vec<ProofNode> = keys
            .iter()
            .skip(1)
            .map(|key| {
                // if current node is not present in store then it is not a valid uid to generate
                if !self.store.exists(key.as_bytes()).unwrap() {
                    return Err(eg!("uid not found in tree, cannot generate proof"));
                }

                let direction = key.chars().last();
                let mut node = ProofNode {
                    siblings1: Default::default(),
                    siblings2: Default::default(),
                    is_left_child: 0,
                    is_right_child: 0,
                };
                let sib1_key;
                let sib2_key;

                match direction {
                    Some('l') => {
                        sib1_key = format!("{}{}", previous, "m");
                        sib2_key = format!("{}{}", previous, "r");
                        node.is_left_child = 1;
                    }
                    Some('m') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "r");
                    }
                    Some('r') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "m");
                        node.is_right_child = 1;
                    }
                    _ => return Err(eg!("incorrect key")),
                };
                if let Some(b) = self.store.get(sib1_key.as_bytes()).unwrap() {
                    node.siblings1 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }
                if let Some(b) = self.store.get(sib2_key.as_bytes()).unwrap() {
                    node.siblings2 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }

                previous = key;
                Ok(node)
            })
            .collect::<Result<Vec<ProofNode>>>()?;

        Ok(Proof {
            nodes: nodes,
            root: self.get_current_root_hash().unwrap(),
            root_version: 1,
            uid: id,
        })
    }

    pub fn get_current_root_hash(&self) -> Result<BLSScalar> {
        match self.store.get(BASE_KEY.as_bytes()).unwrap() {
            Some(hash) => BLSScalar::zei_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found")),
        }
    }

    // fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
    //     let hash = RescueInstance::new();
    //
    //     let pk_hash = hash.rescue_hash(&[
    //         abar.public_key.0.point_ref().get_x(),
    //         abar.public_key.0.point_ref().get_y(),
    //         BLSScalar::zero(),
    //         BLSScalar::zero(),
    //     ])[0];
    //
    //     hash.rescue_hash(&[
    //         BLSScalar::from_u64(uid),
    //         abar.amount_type_commitment,
    //         pk_hash,
    //         BLSScalar::zero(),
    //     ])[0]
    // }

    #[allow(dead_code)]
    pub fn commit(&mut self) -> Result<u64> {
        let (_, ver) = self.store.state_mut().commit(self.version + 1).c(d!())?;
        self.version = ver;
        Ok(self.version)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.store.get(key)
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

#[allow(dead_code)]
pub struct ImmutablePersistentMerkleTree<'a, D: MerkleDB> {
    entry_count: u64,
    version: u64,
    store: ImmutablePrefixedStore<'a, D>,
}

impl<'a, D: MerkleDB> ImmutablePersistentMerkleTree<'a, D> {
    // Generates a new PersistentMerkleTree based on a sessioned KV store
    pub fn new(
        store: ImmutablePrefixedStore<'a, D>,
    ) -> Result<ImmutablePersistentMerkleTree<'a, D>> {
        let mut entry_count = 0;
        let mut version = 0;
        match store.get(BASE_KEY.as_bytes()).unwrap() {
            Some(_) => {
                // TODO: In the case that a pre-existing tree is loaded, calculate the entry-count.
                let ecb = store.get(ENTRY_COUNT_KEY.as_bytes()).unwrap();
                match ecb {
                    Some(bytes) => {
                        let array: [u8; 8] = [
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                            bytes[6], bytes[7],
                        ];
                        entry_count = u64::from_be_bytes(array);
                        version = store.height().c(d!())?;
                    }
                    None => return Err(eg!("entry count key not found in Store")),
                };
            }
            _ => {}
        };
        Ok(ImmutablePersistentMerkleTree {
            entry_count,
            version,
            store,
        })
    }

    pub fn generate_proof(&self, id: u64) -> Result<Proof> {
        let path = get_path_from_uid(id);
        let keys = generate_path_keys(path);

        let mut previous = keys.first().unwrap();

        let nodes: Vec<ProofNode> = keys
            .iter()
            .skip(1)
            .map(|key| {
                // if current node is not present in store then it is not a valid uid to generate
                if !self.store.exists(key.as_bytes()).unwrap() {
                    return Err(eg!("uid not found in tree, cannot generate proof"));
                }

                let direction = key.chars().last();
                let mut node = ProofNode {
                    siblings1: Default::default(),
                    siblings2: Default::default(),
                    is_left_child: 0,
                    is_right_child: 0,
                };
                let sib1_key;
                let sib2_key;
                match direction {
                    Some('l') => {
                        sib1_key = format!("{}{}", previous, "m");
                        sib2_key = format!("{}{}", previous, "r");
                        node.is_left_child = 1;
                    }
                    Some('m') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "r");
                    }
                    Some('r') => {
                        sib1_key = format!("{}{}", previous, "l");
                        sib2_key = format!("{}{}", previous, "m");
                        node.is_right_child = 1;
                    }
                    _ => return Err(eg!("incorrect key")),
                };
                if let Some(b) = self.store.get(sib1_key.as_bytes()).unwrap() {
                    node.siblings1 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }
                if let Some(b) = self.store.get(sib2_key.as_bytes()).unwrap() {
                    node.siblings2 = BLSScalar::zei_from_bytes(b.as_slice())?;
                }

                previous = key;
                Ok(node)
            })
            .collect::<Result<Vec<ProofNode>>>()?;

        Ok(Proof {
            nodes,
            root: self.get_current_root_hash().unwrap(),
            root_version: 1,
            uid: id,
        })
    }

    pub fn get_current_root_hash(&self) -> Result<BLSScalar> {
        match self.store.get(BASE_KEY.as_bytes()).unwrap() {
            Some(hash) => BLSScalar::zei_from_bytes(hash.as_slice()),
            None => Err(eg!("root hash key not found")),
        }
    }

    #[allow(dead_code)]
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.store.get(key)
    }
}

#[derive(Clone)]
pub struct Proof {
    pub nodes: Vec<ProofNode>,
    pub root: BLSScalar,
    pub root_version: usize,
    pub uid: u64,
}
#[derive(Clone)]
pub struct ProofNode {
    pub siblings1: BLSScalar,
    pub siblings2: BLSScalar,
    pub is_left_child: u8,
    pub is_right_child: u8,
}

struct Cache {
    store: HashMap<String, Vec<u8>>,
}

impl Cache {
    fn new() -> Cache {
        Cache {
            store: HashMap::new(),
        }
    }
    fn set(&mut self, key: &str, val: Vec<u8>) {
        self.store.insert(key.to_string(), val);
    }
    fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.store.get(key)
    }
    fn iter(&self) -> Iter<'_, String, Vec<u8>> {
        self.store.iter()
    }
}

pub fn generate_path_keys(path_stream: Vec<Path>) -> Vec<String> {
    let mut key = BASE_KEY.to_owned();
    let mut keys: Vec<String> = path_stream
        .into_iter()
        .map(|path| {
            key.push_str(get_path_str(path).borrow());
            key.clone()
        })
        .collect();

    keys.insert(0, BASE_KEY.to_owned());
    keys
}

fn get_path_str(p: Path) -> String {
    match p {
        Path::Left => "l".to_string(),
        Path::Middle => "m".to_string(),
        Path::Right => "r".to_string(),
    }
}

pub fn get_path_from_uid(mut uid: u64) -> Vec<Path> {
    let mut path: Vec<Path> = Vec::new();
    let mut count = 0;
    while count < TREE_DEPTH {
        let rem = uid % 3;
        uid /= 3;

        match rem {
            0 => path.push(Path::Left),
            1 => path.push(Path::Middle),
            2 => path.push(Path::Right),
            _ => {}
        }
        count += 1;
    }
    path.reverse();
    path
}
