use parking_lot::lock_api::RwLock;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::thread;
use storage::db::TempRocksDB;
use storage::state::{ChainState, State};
use storage::store::PrefixedStore;
use zei::anon_xfr::{
    abar_to_bar::{gen_abar_to_bar_note, verify_abar_to_bar_note},
    anon_fee::{gen_anon_fee_body, verify_anon_fee_body, AnonFeeNote, ANON_FEE_MIN},
    bar_to_abar::{gen_bar_to_abar_note, verify_bar_to_abar_note},
    config::{FEE_CALCULATING_FUNC, FEE_TYPE},
    gen_anon_xfr_body, hash_abar,
    keys::AXfrKeyPair,
    structs::{
        AXfrNote, AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonBlindAssetRecordBuilder,
    },
    verify_anon_xfr_body, TREE_DEPTH,
};
use zei::setup::{ProverParams, VerifierParams};
use zei::xfr::{
    asset_record::{
        open_blind_asset_record, AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
    },
    sig::XfrSecretKey,
    structs::{BlindAssetRecord, OwnerMemo},
};
use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
use zei_algebra::bls12_381::BLSScalar;
use zei_algebra::prelude::*;
use zei_crypto::basic::hybrid_encryption::{XPublicKey, XSecretKey};

// PK: Zo3TnO_aW7eu35EetdphTzaTvUABkCORSNS5WuXLsE0=
const XFR_SK: &'static str = "\"f4is51osSzRRC16Nmsadgtooy86GKYmRtfaM6Sow-g8=\"";

const SK1: &'static str = r#"{
  "axfr_secret_key": "wX1y7BqaXTowHU9C-HaIiKZezc00COfCLXL7Dz3A0gDH7rvZicwd4CayrSGamWhdERIZhJuB5NJdJdUkygLdhw==",
  "axfr_public_key": "x-672YnMHeAmsq0hmploXRESGYSbgeTSXSXVJMoC3Yc=",
  "enc_key": "IoAYWDX1Ml9UA5U_8A3pWXJs88E5roY_36BfZf2rayU=",
  "dec_key": "YEu9vrvoDYHU511z3vISDE36QMyEzZRlLPjCWjd-cng="
}"#;

const SK2: &'static str = r#"{
  "axfr_secret_key": "h-KN1mJ3EoJzSVMjcgwTkvInB59EjZU1bwWX3WCCHQpH6CMBbsGOMYthFMAMYXpynUC3pm-ek25YcOrGwl1ssQ==",
  "axfr_public_key": "R-gjAW7BjjGLYRTADGF6cp1At6ZvnpNuWHDqxsJdbLE=",
  "enc_key": "22m-2L1lOII8Ud_SEy1DwjrOIJ2ylyJxnWZ9w2OGmHA=",
  "dec_key": "oPogNzcudnN6xCN7uynhsFbG2ix0zd8kiMgZI4SJZnI="
}"#;

#[derive(Deserialize, Serialize)]
struct AnonKeys {
    pub axfr_secret_key: String,
    pub axfr_public_key: String,
    pub enc_key: String,
    pub dec_key: String,
}

impl AnonKeys {
    fn key(s: &str) -> (AXfrKeyPair, XSecretKey) {
        let keys = serde_json::from_str::<AnonKeys>(s).unwrap();
        let anon_kp = base64::decode_config(&keys.axfr_secret_key, base64::URL_SAFE)
            .map(|bytes| AXfrKeyPair::zei_from_bytes(&bytes).unwrap())
            .unwrap();

        let dec_key = base64::decode_config(&keys.dec_key, base64::URL_SAFE)
            .map(|bytes| XSecretKey::zei_from_bytes(&bytes).unwrap())
            .unwrap();

        (anon_kp, dec_key)
    }

    fn gen(rng: &mut ChaChaRng) -> (AXfrKeyPair, XSecretKey, XPublicKey) {
        let anon_kp = AXfrKeyPair::generate(rng);
        let dec_key = XSecretKey::new(rng);
        let enc_key = XPublicKey::from(&dec_key);
        (anon_kp, dec_key, enc_key)
    }
}

// outputs &mut merkle tree (wrap it in an option merkle tree, not req)
fn build_new_merkle_tree(n: i32, mt: &mut PersistentMerkleTree<TempRocksDB>) -> Result<()> {
    // add 6/7 abar and populate and then retrieve values

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let key_pair = AXfrKeyPair::generate(&mut prng);

    let mut abar = AnonBlindAssetRecord {
        amount_type_commitment: BLSScalar::random(&mut prng),
        public_key: key_pair.pub_key(),
    };

    let _ = mt.add_commitment_hash(hash_abar(mt.entry_count(), &abar))?;
    mt.commit()?;

    for _i in 0..n - 1 {
        abar = AnonBlindAssetRecord {
            amount_type_commitment: BLSScalar::random(&mut prng),
            public_key: key_pair.pub_key(),
        };

        let _ = mt.add_commitment_hash(hash_abar(mt.entry_count(), &abar))?;
        mt.commit()?;
    }

    Ok(())
}

fn create_mt_leaf_info(proof: Proof) -> MTLeafInfo {
    MTLeafInfo {
        path: MTPath {
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
        root: proof.root,
        root_version: proof.root_version,
        uid: proof.uid,
    }
}

#[test]
fn anon_xfr_1_1() {
    // 1. load sender & abar.
    let (send_keypair, send_deckey) = AnonKeys::key(SK1);
    let abar_bytes = include_bytes!("./migrate_files/anon_xfr_1.bin");
    let (abar, memo): (AnonBlindAssetRecord, OwnerMemo) = bincode::deserialize(abar_bytes).unwrap();

    // 2. build state merkle tree.
    let path = thread::current().name().unwrap().to_owned();
    let mut state = State::new(
        Arc::new(RwLock::new(ChainState::new(
            TempRocksDB::open(path).expect("failed to open db"),
            "test_db".to_string(),
            0,
        ))),
        false,
    );
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();
    build_new_merkle_tree(5, &mut mt).unwrap();

    // 3. init merkle abar.
    let uid = mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .unwrap();
    let _ = mt.commit();
    let mt_proof = mt.generate_proof(uid).unwrap();
    assert_eq!(mt.get_root().unwrap(), mt_proof.root);

    // 4. prepare proof system.
    let mut prng = ChaChaRng::from_entropy();
    let (recv_keypair, recv_deckey, recv_enckey) = AnonKeys::gen(&mut prng);
    let user_params = ProverParams::new(1, 1, Some(TREE_DEPTH)).unwrap();

    let input_amount = 10_000_000u64;
    let fee_amount = FEE_CALCULATING_FUNC(1, 1) as u64;
    let output_amount = input_amount - fee_amount;
    let asset_type = FEE_TYPE;

    // 5. prove input
    let oabar_in =
        OpenAnonBlindAssetRecordBuilder::from_abar(&abar, memo, &send_keypair, &send_deckey)
            .unwrap()
            .mt_leaf_info(create_mt_leaf_info(mt_proof.clone()))
            .build()
            .unwrap();
    assert_eq!(input_amount, oabar_in.get_amount());
    assert_eq!(asset_type, oabar_in.get_asset_type());
    assert_eq!(&send_keypair.pub_key(), oabar_in.pub_key_ref());

    // 6. prove output
    let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
        .amount(output_amount)
        .asset_type(asset_type)
        .pub_key(recv_keypair.pub_key())
        .finalize(&mut prng, &recv_enckey)
        .unwrap()
        .build()
        .unwrap();

    // 7. prove proof
    let (body, key_pairs) = gen_anon_xfr_body(
        &mut prng,
        &user_params,
        &[oabar_in],
        &[oabar_out],
        &[send_keypair],
    )
    .unwrap();

    // 8. check output
    let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
        &body.outputs[0],
        body.owner_memos[0].clone(),
        &recv_keypair,
        &recv_deckey,
    )
    .unwrap()
    .build()
    .unwrap();
    let rand_pk = recv_keypair
        .pub_key()
        .randomize(&oabar.get_key_rand_factor());
    assert_eq!(output_amount, oabar.get_amount());
    assert_eq!(asset_type, oabar.get_asset_type());
    assert_eq!(rand_pk, body.outputs[0].public_key);

    // 9.1 verify proof - (VerifierParams from ProverParams)
    let verifier_params = VerifierParams::from(user_params);
    let t = verify_anon_xfr_body(&verifier_params, &body, &mt.get_root().unwrap());
    assert!(t.is_ok());

    // 9.2 verify proof - (VerifierParams from shrink)
    let vk1 = verifier_params.shrink().unwrap();
    assert!(verify_anon_xfr_body(&vk1, &body, &mt.get_root().unwrap()).is_ok());

    // 9.3 verify proof - (VerifierParams from precomputed file)
    let vk2 = VerifierParams::load(1, 1).unwrap();
    assert!(verify_anon_xfr_body(&vk2, &body, &mt.get_root().unwrap()).is_ok());

    // 9.4 verify proof - (with note signature)
    let note = AXfrNote::generate_note_from_body(&mut prng, body, key_pairs).unwrap();
    assert!(note.verify().is_ok())
}

#[test]
fn anon_xfr_2_2() {
    // 1. load sender & abar.
    let (send1_keypair, send1_deckey) = AnonKeys::key(SK1);
    let abar1_bytes = include_bytes!("./migrate_files/anon_xfr_1.bin");
    let (abar1, memo1): (AnonBlindAssetRecord, OwnerMemo) =
        bincode::deserialize(abar1_bytes).unwrap();

    let (send2_keypair, send2_deckey) = AnonKeys::key(SK2);
    let abar2_bytes = include_bytes!("./migrate_files/anon_xfr_2.bin");
    let (abar2, memo2): (AnonBlindAssetRecord, OwnerMemo) =
        bincode::deserialize(abar2_bytes).unwrap();

    let input1_amount = 10_000_000u64;
    let input2_amount = 15_000_000u64;
    let fee_amount = FEE_CALCULATING_FUNC(2, 2) as u64; // 1_100_000
    let output1_amount = 5_000_000;
    let output2_amount = input1_amount + input2_amount - output1_amount - fee_amount;
    let asset_type = FEE_TYPE;

    // 2. build state merkle tree.
    let path = thread::current().name().unwrap().to_owned();
    let mut state = State::new(
        Arc::new(RwLock::new(ChainState::new(
            TempRocksDB::open(path).expect("failed to open db"),
            "test_db".to_string(),
            0,
        ))),
        false,
    );
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();
    build_new_merkle_tree(5, &mut mt).unwrap();

    // 3. init merkle abar.
    let uid1 = mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar1))
        .unwrap();
    let uid2 = mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar2))
        .unwrap();
    let _ = mt.commit();
    let mt1_proof = mt.generate_proof(uid1).unwrap();
    assert_eq!(mt.get_root().unwrap(), mt1_proof.root);
    let mt2_proof = mt.generate_proof(uid2).unwrap();
    assert_eq!(mt.get_root().unwrap(), mt2_proof.root);

    // 4. prepare proof system.
    let mut prng = ChaChaRng::from_entropy();
    let (recv1_keypair, recv1_deckey, recv1_enckey) = AnonKeys::gen(&mut prng);
    let (recv2_keypair, recv2_deckey, recv2_enckey) = AnonKeys::gen(&mut prng);
    let user_params = ProverParams::new(2, 2, Some(TREE_DEPTH)).unwrap();

    // 5. prove input
    let oabar1_in =
        OpenAnonBlindAssetRecordBuilder::from_abar(&abar1, memo1, &send1_keypair, &send1_deckey)
            .unwrap()
            .mt_leaf_info(create_mt_leaf_info(mt1_proof.clone()))
            .build()
            .unwrap();
    assert_eq!(input1_amount, oabar1_in.get_amount());
    assert_eq!(asset_type, oabar1_in.get_asset_type());
    assert_eq!(&send1_keypair.pub_key(), oabar1_in.pub_key_ref());

    let oabar2_in =
        OpenAnonBlindAssetRecordBuilder::from_abar(&abar2, memo2, &send2_keypair, &send2_deckey)
            .unwrap()
            .mt_leaf_info(create_mt_leaf_info(mt2_proof.clone()))
            .build()
            .unwrap();
    assert_eq!(input2_amount, oabar2_in.get_amount());
    assert_eq!(asset_type, oabar2_in.get_asset_type());
    assert_eq!(&send2_keypair.pub_key(), oabar2_in.pub_key_ref());

    // 6. prove output
    let oabar1_out = OpenAnonBlindAssetRecordBuilder::new()
        .amount(output1_amount)
        .asset_type(asset_type)
        .pub_key(recv1_keypair.pub_key())
        .finalize(&mut prng, &recv1_enckey)
        .unwrap()
        .build()
        .unwrap();

    let oabar2_out = OpenAnonBlindAssetRecordBuilder::new()
        .amount(output2_amount)
        .asset_type(asset_type)
        .pub_key(recv2_keypair.pub_key())
        .finalize(&mut prng, &recv2_enckey)
        .unwrap()
        .build()
        .unwrap();

    // 7. prove proof
    let (body, key_pairs) = gen_anon_xfr_body(
        &mut prng,
        &user_params,
        &[oabar1_in, oabar2_in],
        &[oabar1_out, oabar2_out],
        &[send1_keypair, send2_keypair],
    )
    .unwrap();

    // 8. check output
    let oabar1 = OpenAnonBlindAssetRecordBuilder::from_abar(
        &body.outputs[0],
        body.owner_memos[0].clone(),
        &recv1_keypair,
        &recv1_deckey,
    )
    .unwrap()
    .build()
    .unwrap();
    let rand1_pk = recv1_keypair
        .pub_key()
        .randomize(&oabar1.get_key_rand_factor());
    assert_eq!(output1_amount, oabar1.get_amount());
    assert_eq!(asset_type, oabar1.get_asset_type());
    assert_eq!(rand1_pk, body.outputs[0].public_key);

    let oabar2 = OpenAnonBlindAssetRecordBuilder::from_abar(
        &body.outputs[1],
        body.owner_memos[1].clone(),
        &recv2_keypair,
        &recv2_deckey,
    )
    .unwrap()
    .build()
    .unwrap();
    let rand2_pk = recv2_keypair
        .pub_key()
        .randomize(&oabar2.get_key_rand_factor());
    assert_eq!(output2_amount, oabar2.get_amount());
    assert_eq!(asset_type, oabar2.get_asset_type());
    assert_eq!(rand2_pk, body.outputs[1].public_key);

    // 9.1 verify proof - (VerifierParams from precomputed file)
    let vk = VerifierParams::load(2, 2).unwrap();
    assert!(verify_anon_xfr_body(&vk, &body, &mt.get_root().unwrap()).is_ok());

    // 9.2 verify proof - (with note signature)
    let note = AXfrNote::generate_note_from_body(&mut prng, body, key_pairs).unwrap();
    assert!(note.verify().is_ok())
}

#[test]
fn anon_xfr_bar2abar() {
    let bar_keypair = serde_json::from_str::<XfrSecretKey>(XFR_SK)
        .unwrap()
        .into_keypair();
    let (abar_keypair, abar_deckey) = AnonKeys::key(SK1);
    let abar_enckey = XPublicKey::from(&abar_deckey);

    // 1 load xfr from migration.
    let bar_bytes = include_bytes!("./migrate_files/xfr_bar_conf_1.bin");
    let (bar, memo): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar_bytes).unwrap();
    let obar = open_blind_asset_record(&bar, &memo, &bar_keypair).unwrap();
    let amount = 100u64;
    let asset_type = FEE_TYPE;

    // 2. prepare proof parameters
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let params = ProverParams::eq_committed_vals_params().unwrap();

    // 3. prove
    let note = gen_bar_to_abar_note(
        &mut prng,
        &params,
        &obar,
        &bar_keypair,
        &abar_keypair.pub_key(),
        &abar_enckey,
    )
    .unwrap();

    // 4. check abar
    let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
        &note.body.output,
        note.body.memo.clone(),
        &abar_keypair,
        &abar_deckey,
    )
    .unwrap()
    .build()
    .unwrap();
    assert_eq!(oabar.get_amount(), amount);
    assert_eq!(oabar.get_asset_type(), asset_type);
    assert_eq!(
        abar_keypair
            .pub_key()
            .randomize(&oabar.get_key_rand_factor()),
        note.body.output.public_key
    );

    // 5. load verifier parameters & verify
    let node_params = VerifierParams::bar_to_abar_params().unwrap();
    assert!(verify_bar_to_abar_note(&node_params, &note, &bar_keypair.pub_key).is_ok());
}

#[test]
fn anon_xfr_abar2bar() {
    // 1. load sender & abar.
    let (abar_keypair, abar_deckey) = AnonKeys::key(SK1);
    let abar_bytes = include_bytes!("./migrate_files/anon_xfr_1.bin");
    let (abar, memo): (AnonBlindAssetRecord, OwnerMemo) = bincode::deserialize(abar_bytes).unwrap();
    let amount = 10_000_000u64;

    let bar_keypair = serde_json::from_str::<XfrSecretKey>(XFR_SK)
        .unwrap()
        .into_keypair();
    let bar_pubkey = bar_keypair.pub_key;

    // 2. build state merkle tree.
    let path = thread::current().name().unwrap().to_owned();
    let mut state = State::new(
        Arc::new(RwLock::new(ChainState::new(
            TempRocksDB::open(path).expect("failed to open db"),
            "test_db".to_string(),
            0,
        ))),
        false,
    );
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();
    build_new_merkle_tree(5, &mut mt).unwrap();

    // 3. init merkle abar.
    let uid = mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .unwrap();
    let _ = mt.commit();
    let mt_proof = mt.generate_proof(uid).unwrap();
    assert_eq!(mt.get_root().unwrap(), mt_proof.root);

    // 4. prepare proof system.
    let mut prng = ChaChaRng::from_entropy();
    let user_params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();

    // 5. prove input
    let oabar =
        OpenAnonBlindAssetRecordBuilder::from_abar(&abar, memo, &abar_keypair, &abar_deckey)
            .unwrap()
            .mt_leaf_info(create_mt_leaf_info(mt_proof.clone()))
            .build()
            .unwrap();

    // 6. prove
    let note = gen_abar_to_bar_note(
        &mut prng,
        &user_params,
        &oabar,
        &abar_keypair,
        &bar_pubkey,
        ConfidentialAmount_ConfidentialAssetType,
    )
    .unwrap();

    // 7. check bar
    let recv_bar = &note.body.output;
    let recv_memo = &note.body.memo;
    let recv_oar = open_blind_asset_record(recv_bar, recv_memo, &bar_keypair).unwrap();

    assert!(recv_memo.is_some());
    assert!(recv_bar.amount.is_confidential());
    assert_eq!(recv_oar.asset_type, FEE_TYPE);
    assert_eq!(recv_oar.amount, amount);
    assert_eq!(recv_oar.blind_asset_record.public_key, bar_pubkey);

    // 8. verify
    let node_params = VerifierParams::abar_to_bar_params().unwrap();
    verify_abar_to_bar_note(&node_params, &note, &mt.get_root().unwrap()).unwrap();

    assert!(verify_abar_to_bar_note(&node_params, &note, &BLSScalar::random(&mut prng)).is_err());

    let mut body_wrong_nullifier = note.clone();
    body_wrong_nullifier.body.input.0 = BLSScalar::random(&mut prng);
    assert!(
        verify_abar_to_bar_note(&node_params, &body_wrong_nullifier, &mt.get_root().unwrap())
            .is_err()
    );

    let mut body_wrong_pubkey = note.clone();
    body_wrong_pubkey.body.input.1 = AXfrKeyPair::generate(&mut prng).pub_key();
    assert!(
        verify_abar_to_bar_note(&node_params, &body_wrong_pubkey, &mt.get_root().unwrap()).is_err()
    );
}

#[test]
fn anon_xfr_fee() {
    // 1. load sender & abar.
    let (send_keypair, send_deckey) = AnonKeys::key(SK1);
    let send_enckey = XPublicKey::from(&send_deckey);
    let abar_bytes = include_bytes!("./migrate_files/anon_xfr_1.bin");
    let (abar, memo): (AnonBlindAssetRecord, OwnerMemo) = bincode::deserialize(abar_bytes).unwrap();

    // 2. build state merkle tree.
    let path = thread::current().name().unwrap().to_owned();
    let mut state = State::new(
        Arc::new(RwLock::new(ChainState::new(
            TempRocksDB::open(path).expect("failed to open db"),
            "test_db".to_string(),
            0,
        ))),
        false,
    );
    let store = PrefixedStore::new("my_store", &mut state);
    let mut mt = PersistentMerkleTree::new(store).unwrap();
    build_new_merkle_tree(5, &mut mt).unwrap();

    // 3. init merkle abar.
    let uid = mt
        .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
        .unwrap();
    let _ = mt.commit();
    let mt_proof = mt.generate_proof(uid).unwrap();
    assert_eq!(mt.get_root().unwrap(), mt_proof.root);

    // 4. prepare proof system.
    let mut prng = ChaChaRng::from_entropy();
    let user_params = ProverParams::anon_fee_params(TREE_DEPTH).unwrap();

    let input_amount = 10_000_000u64;
    let output_amount = input_amount - ANON_FEE_MIN;
    let asset_type = FEE_TYPE;

    // 5. prove input
    let oabar_in =
        OpenAnonBlindAssetRecordBuilder::from_abar(&abar, memo, &send_keypair, &send_deckey)
            .unwrap()
            .mt_leaf_info(create_mt_leaf_info(mt_proof.clone()))
            .build()
            .unwrap();
    assert_eq!(input_amount, oabar_in.get_amount());
    assert_eq!(asset_type, oabar_in.get_asset_type());
    assert_eq!(&send_keypair.pub_key(), oabar_in.pub_key_ref());

    // 6. prove output
    let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
        .amount(output_amount)
        .asset_type(asset_type)
        .pub_key(send_keypair.pub_key())
        .finalize(&mut prng, &send_enckey)
        .unwrap()
        .build()
        .unwrap();

    // 7. prove proof
    let (body, key_pairs) = gen_anon_fee_body(
        &mut prng,
        &user_params,
        &oabar_in,
        &oabar_out,
        &send_keypair,
    )
    .unwrap();

    // 8. check output
    let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
        &body.output,
        body.owner_memo.clone(),
        &send_keypair,
        &send_deckey,
    )
    .unwrap()
    .build()
    .unwrap();
    let rand_pk = send_keypair
        .pub_key()
        .randomize(&oabar.get_key_rand_factor());
    assert_eq!(output_amount, oabar.get_amount());
    assert_eq!(asset_type, oabar.get_asset_type());
    assert_eq!(rand_pk, body.output.public_key);

    // 9.1 verify proof
    let vk = VerifierParams::anon_fee_params().unwrap();
    assert!(verify_anon_fee_body(&vk, &body, &mt.get_root().unwrap()).is_ok());

    // 9.2 verify proof - (with note signature)
    let note = AnonFeeNote::generate_note_from_body(&mut prng, body, key_pairs).unwrap();
    assert!(note.verify_signatures().is_ok())
}
