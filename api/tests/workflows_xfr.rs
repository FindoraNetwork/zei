use rand_chacha::ChaChaRng;
use wasm_bindgen::__rt::std::collections::HashMap;
use zei::anon_creds::{self, ac_commit, ac_sign, ac_verify_commitment, Attr, Credential};
use zei::setup::BulletproofParams;
use zei::xfr::{
    asset_record::{open_blind_asset_record, AssetRecordType},
    gen_xfr_note,
    sig::{XfrKeyPair, XfrPublicKey, XfrSecretKey},
    structs::{
        AssetRecord, AssetRecordTemplate, AssetTracerKeyPair, AssetType, BlindAssetRecord,
        IdentityRevealPolicy, OwnerMemo, TracingPolicies, TracingPolicy, ASSET_TYPE_LENGTH,
    },
    test_utils::conf_blind_asset_record_from_ledger,
    trace_assets, verify_xfr_note, RecordData, XfrNotePolicies, XfrNotePoliciesRef,
};
use zei_algebra::prelude::*;

const ASSET1_TYPE: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);
const ASSET2_TYPE: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);
const ASSET3_TYPE: AssetType = AssetType([2u8; ASSET_TYPE_LENGTH]);

// PK: Zo3TnO_aW7eu35EetdphTzaTvUABkCORSNS5WuXLsE0=
const SK1: &'static str = "\"f4is51osSzRRC16Nmsadgtooy86GKYmRtfaM6Sow-g8=\"";
// PK MyC584H-Z8KY-9XSnVbwu7Caez5jsHD9Rg_BvKqxEqc=
const SK2: &'static str = "\"refljnBYtTGJe3jDJi4Pzpri1tLfbi8hZx2L8JM3BWw=\"";

fn check_record_data(
    record_data: &RecordData,
    expected_amount: u64,
    expected_asset_type: AssetType,
    expected_ids: Vec<Attr>,
    expected_pk: &XfrPublicKey,
) {
    assert_eq!(record_data.0, expected_amount);
    assert_eq!(record_data.1, expected_asset_type);
    assert_eq!(record_data.2, expected_ids);
    assert_eq!(record_data.3, *expected_pk);
}

#[test]
fn xfr_non_confidential_1_1() {
    let send_keypair = serde_json::from_str::<XfrSecretKey>(SK1)
        .unwrap()
        .into_keypair();

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = BulletproofParams::default();
    let amount = 100u64;

    // 1. setup
    // 1.1 receiver keys
    let recv_keypair = XfrKeyPair::generate(&mut prng);
    let recv_pub_key = recv_keypair.pub_key;

    // 1.2. load blind_asset_record from migration.
    let bar_bytes = include_bytes!("./migrate_files/xfr_bar_non_conf.bin");
    let (bar, memo): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar_bytes).unwrap();

    // 2. Prepare input AssetRecord
    // 2.1 user opens blind asset record, it is not confidential so no memo was received
    let oar = open_blind_asset_record(&bar, &memo, &send_keypair).unwrap();

    // 2.2. build AssetRecord from oar
    let send_asset_record = AssetRecord::from_open_asset_record_no_asset_tracing(oar);

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_no_asset_tracing(
        amount,
        ASSET1_TYPE,
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        recv_pub_key,
    );
    // 3.3 build output asset record
    //     do not attach identity tracking fields
    let recv_asset_record =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[send_asset_record], // one input
        &[recv_asset_record], // one output
        &[&send_keypair],
    )
    .unwrap(); // sender secret key

    let policies = XfrNotePolicies::empty_policies(1, 1);
    let policies_ref = policies.to_ref();

    // 5. Validator verifies xfr_note
    //    there are no policies associated with this xfr note
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies_ref).is_ok());

    // 6. receiver retrieves his BlindAssetRecord and opens it
    let recv_bar = &xfr_note.body.outputs[0];
    let recv_memo = &xfr_note.body.owners_memos[0];
    let recv_oar = open_blind_asset_record(recv_bar, recv_memo, &recv_keypair).unwrap();

    assert!(recv_memo.is_none());
    assert_eq!(recv_oar.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar.amount, amount);
    assert_eq!(recv_oar.blind_asset_record.public_key, recv_pub_key);
}

#[test]
fn xfr_amount_confidential_1_1() {
    let send_keypair = serde_json::from_str::<XfrSecretKey>(SK1)
        .unwrap()
        .into_keypair();

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = BulletproofParams::default();
    let amount = 100u64;

    // 1. setup
    // 1.1 user keys
    let recv_keypair = XfrKeyPair::generate(&mut prng);
    let recv_pub_key = recv_keypair.pub_key;

    // 1.2. load blind_asset_record from migration.
    let bar_bytes = include_bytes!("./migrate_files/xfr_bar_amount_conf.bin");
    let (bar, memo): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar_bytes).unwrap();

    // 2. Prepare input AssetRecord
    // 2.1 user opens blind asset record, it is not confidential so no memo was received
    let oar = open_blind_asset_record(&bar, &memo, &send_keypair).unwrap();

    // 2.2. build AssetRecord from oar
    let send_asset_record = AssetRecord::from_open_asset_record_no_asset_tracing(oar);

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_no_asset_tracing(
        amount,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        recv_pub_key,
    );
    // 3.3 build output asset record
    //     do not attach identity tracking fields
    let recv_asset_record =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[send_asset_record], // one input
        &[recv_asset_record], // one output
        &[&send_keypair],
    )
    .unwrap(); // sender secret key
    let policies = XfrNotePolicies::empty_policies(1, 1);
    let policies_ref = policies.to_ref();

    // 5. Validator verifies xfr_note
    //    there are no policies associated with this xfr note
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies_ref).is_ok());

    // 6. receiver retrieves his BlindAssetRecord and opens it
    let recv_bar = &xfr_note.body.outputs[0];
    let recv_memo = &xfr_note.body.owners_memos[0];
    let recv_oar = open_blind_asset_record(recv_bar, recv_memo, &recv_keypair).unwrap();

    assert!(recv_memo.is_some());
    assert!(recv_bar.amount.is_confidential());
    assert_eq!(recv_oar.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar.amount, amount);
    assert_eq!(recv_oar.blind_asset_record.public_key, recv_pub_key);
}

#[test]
fn xfr_confidential_asset_tracing_on_inputs_2_2() {
    let send1_keypair = serde_json::from_str::<XfrSecretKey>(SK1)
        .unwrap()
        .into_keypair();
    let send2_keypair = serde_json::from_str::<XfrSecretKey>(SK2)
        .unwrap()
        .into_keypair();

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = BulletproofParams::default();
    let amount_in1 = 100u64;
    let amount_in2 = 25u64;
    let amount_out1 = 75u64;
    let amount_out2 = 50u64;

    // 1. setup
    // 1.1 receiver keys
    let recv1_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_pub_key = recv1_keypair.pub_key;
    let recv2_keypair = XfrKeyPair::generate(&mut prng);
    let recv2_pub_key = recv2_keypair.pub_key;

    // setup policy
    let tracer_keys = AssetTracerKeyPair::generate(&mut prng);
    let policy = TracingPolicy {
        enc_keys: tracer_keys.enc_key.clone(),
        asset_tracing: true,    // do asset tracing
        identity_tracing: None, // do not trace identity
    };

    // 1.2. load blind_asset_record from migration.
    let bar1_bytes = include_bytes!("./migrate_files/xfr_bar_conf_1.bin");
    let (bar1, memo1): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar1_bytes).unwrap();
    let bar2_bytes = include_bytes!("./migrate_files/xfr_bar_conf_2.bin");
    let (bar2, memo2): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar2_bytes).unwrap();

    // 2. Build inputs
    // open blind asset record
    let oar_in1 = open_blind_asset_record(&bar1, &memo1, &send1_keypair).unwrap();
    let oar_in2 = open_blind_asset_record(&bar2, &memo2, &send2_keypair).unwrap();

    // create inputs from open asset record and policies
    let policies = TracingPolicies::from_policy(policy);
    let no_policy = TracingPolicies::new();

    let ar_in1 = AssetRecord::from_open_asset_record_with_asset_tracing_but_no_identity(
        &mut prng,
        oar_in1,
        policies.clone(),
    )
    .unwrap();
    let ar_in2 = AssetRecord::from_open_asset_record_with_asset_tracing_but_no_identity(
        &mut prng,
        oar_in2,
        policies.clone(),
    )
    .unwrap();

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template_out1 = AssetRecordTemplate::with_no_asset_tracing(
        amount_out1,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        recv1_pub_key,
    );
    let template_out2 = AssetRecordTemplate::with_no_asset_tracing(
        amount_out2,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        recv2_pub_key,
    );
    // 3.3 build output asset record
    //     do not attach identity tracking fields
    let ar_out1 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template_out1).unwrap();
    let ar_out2 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template_out2).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[ar_in1, ar_in2],   // one input
        &[ar_out1, ar_out2], // one output
        &[&send1_keypair, &send2_keypair],
    )
    .unwrap(); // sender secret key
    let policies = XfrNotePoliciesRef::new(
        vec![&policies; 2],
        vec![None; 2],
        vec![&no_policy; 2],
        vec![None; 2],
    );

    // 5. Validator verifies xfr_note
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

    // 6. receives retrieves his BlindAssetRecord and opens it
    let recv_bar1 = &xfr_note.body.outputs[0];
    let recv_memo1 = &xfr_note.body.owners_memos[0];
    let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &recv1_keypair).unwrap();

    assert!(recv_memo1.is_some());
    assert!(recv_bar1.amount.is_confidential());
    assert!(recv_bar1.asset_type.is_confidential());
    assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar1.amount, amount_out1);
    assert_eq!(recv_oar1.blind_asset_record.public_key, recv1_pub_key);

    let recv_bar2 = &xfr_note.body.outputs[1];
    let recv_memo2 = &xfr_note.body.owners_memos[1];
    let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &recv2_keypair).unwrap();

    assert!(recv_memo2.is_some());
    assert!(recv_bar2.amount.is_confidential());
    assert!(recv_bar2.asset_type.is_confidential());
    assert_eq!(recv_oar2.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar2.amount, amount_out2);
    assert_eq!(recv_oar2.blind_asset_record.public_key, recv2_pub_key);

    //7. Check asset tracing
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 4);
    assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 1);
    assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
    assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 0);
    assert_eq!(xfr_note.body.asset_tracing_memos[3].len(), 0);

    let records_data = trace_assets(&xfr_note.body, &tracer_keys).unwrap();

    check_record_data(
        &records_data[0],
        amount_in1,
        ASSET1_TYPE,
        vec![],
        &send1_keypair.pub_key,
    );
    check_record_data(
        &records_data[1],
        amount_in2,
        ASSET1_TYPE,
        vec![],
        &send2_keypair.pub_key,
    );
}

#[test]
fn xfr_confidential_asset_tracing_on_outputs_1_2() {
    let send_keypair = serde_json::from_str::<XfrSecretKey>(SK1)
        .unwrap()
        .into_keypair();

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = BulletproofParams::default();
    // let amount_in1 = 100u64;
    let amount_out1 = 30u64;
    let amount_out2 = 70u64;

    // 1. setup
    // 1.1 receiver keys
    let recv1_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_pub_key = recv1_keypair.pub_key;
    let recv2_keypair = XfrKeyPair::generate(&mut prng);
    let recv2_pub_key = recv2_keypair.pub_key;

    // 1.3 Instantiate issuer with his public keys
    let asset_tracing_key_pair = AssetTracerKeyPair::generate(&mut prng);

    // 1.4 Define issuer tracing policy
    let asset_tracing_policy = TracingPolicy {
        enc_keys: asset_tracing_key_pair.enc_key.clone(), // publicly available
        asset_tracing: true,                              // encrypt record info to asset issuer
        identity_tracing: None,                           // no identity tracking
    };

    let policies = TracingPolicies::from_policy(asset_tracing_policy);
    let no_policy = TracingPolicies::new();

    // 2. Prepare input AssetRecord
    // 2.1 user opens blind asset record, it is not confidential so no memo was received
    let bar_bytes = include_bytes!("./migrate_files/xfr_bar_conf_1.bin");
    let (bar, memo): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar_bytes).unwrap();
    let oar = open_blind_asset_record(&bar, &memo, &send_keypair).unwrap();

    // 2.2. build AssetRecord from oar
    let input_asset_record = AssetRecord::from_open_asset_record_no_asset_tracing(oar);

    // 3. Prepare output AssetRecord
    // 3.2. build output asset_record template
    let template1 = AssetRecordTemplate::with_asset_tracing(
        amount_out1,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        recv1_pub_key,
        policies.clone(),
    );
    let template2 = AssetRecordTemplate::with_asset_tracing(
        amount_out2,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        recv2_pub_key,
        policies.clone(),
    );

    // 3.3 build output asset record
    let output_asset_record1 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template1).unwrap();
    let output_asset_record2 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template2).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[input_asset_record],
        &[output_asset_record1, output_asset_record2],
        &[&send_keypair],
    )
    .unwrap();
    let policies = XfrNotePoliciesRef::new(
        vec![&no_policy],
        vec![None],
        vec![&policies; 2],
        vec![None; 2],
    );

    // 5. validator verify xfr_note
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

    // 6. receiver retrieved his BlindAssetRecord and opens it
    let recv_bar1 = &xfr_note.body.outputs[0];
    let recv_memo1 = &xfr_note.body.owners_memos[0];
    let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &recv1_keypair).unwrap();

    assert!(recv_memo1.is_some());
    assert!(recv_bar1.amount.is_confidential());
    assert!(!recv_bar1.asset_type.is_confidential());
    assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar1.amount, amount_out1);
    assert_eq!(recv_oar1.blind_asset_record.public_key, recv1_pub_key);

    let recv_bar2 = &xfr_note.body.outputs[1];
    let recv_memo2 = &xfr_note.body.owners_memos[1];
    let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &recv2_keypair).unwrap();

    assert!(recv_memo2.is_some());
    assert!(recv_bar2.amount.is_confidential());
    assert!(!recv_bar2.asset_type.is_confidential());
    assert_eq!(recv_oar2.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar2.amount, amount_out2);
    assert_eq!(recv_oar2.blind_asset_record.public_key, recv2_pub_key);

    // 7. Check asset tracing
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
    assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 0);
    assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
    assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 1);

    let records_data = trace_assets(&xfr_note.body, &asset_tracing_key_pair).unwrap();

    check_record_data(
        &records_data[0],
        amount_out1,
        ASSET1_TYPE,
        vec![],
        &recv1_pub_key,
    );
    check_record_data(
        &records_data[1],
        amount_out2,
        ASSET1_TYPE,
        vec![],
        &recv2_pub_key,
    );
}

#[test]
fn xfr_confidential_asset_tracing_and_identity_tracking_on_inputs_2_1() {
    let send1_keypair = serde_json::from_str::<XfrSecretKey>(SK1)
        .unwrap()
        .into_keypair();
    let send1_pubkey = send1_keypair.pub_key;
    let send2_keypair = serde_json::from_str::<XfrSecretKey>(SK2)
        .unwrap()
        .into_keypair();
    let send2_pubkey = send2_keypair.pub_key;

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = BulletproofParams::default();
    let mut air: HashMap<&[u8], _> = HashMap::new();
    let amount_in1 = 100u64;
    let amount_in2 = 25u64;
    let amount_out1 = 125u64;

    // 1. setup
    // 1.1 receiver keys
    let recv_keypair = XfrKeyPair::generate(&mut prng);
    let recv_pub_key = recv_keypair.pub_key;

    // 1.2 Credential keys
    let (cred_issuer_pk, cred_issuer_sk) = anon_creds::ac_keygen_issuer(&mut prng, 4);
    let (user1_ac_pk, user1_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let (user2_ac_pk, user2_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

    // 1.3 setup policy
    let tracer_keys = AssetTracerKeyPair::generate(&mut prng);
    let id_policy_policy = IdentityRevealPolicy {
        cred_issuer_pub_key: cred_issuer_pk.clone(),
        reveal_map: vec![true, true, false, false], // reveal first two attributes
    };
    let policy = TracingPolicy {
        enc_keys: tracer_keys.enc_key.clone(),
        asset_tracing: true,                      // do asset tracing
        identity_tracing: Some(id_policy_policy), // do not trace identity
    };
    let policies = TracingPolicies::from_policy(policy);
    let no_policies = TracingPolicies::new();

    // 2. Credential for input users
    // 2.1 credential issuance:
    let user1_attr = vec![1u32, 2u32, 3u32, 4u32];
    let user2_attr = vec![11u32, 22u32, 33u32, 44u32];
    let cred_sig_user1 = ac_sign(&mut prng, &cred_issuer_sk, &user1_ac_pk, &user1_attr);
    let cred_sig_user2 = ac_sign(&mut prng, &cred_issuer_sk, &user2_ac_pk, &user2_attr);
    let credential_user1 = Credential {
        signature: cred_sig_user1.unwrap(),
        attributes: user1_attr,
        issuer_pub_key: cred_issuer_pk.clone(),
    };
    let credential_user2 = Credential {
        signature: cred_sig_user2.unwrap(),
        attributes: user2_attr,
        issuer_pub_key: cred_issuer_pk.clone(),
    };

    // 2.2 credential commitments
    let (commitment_user1, proof_user1, commitment_key_user1) = ac_commit(
        &mut prng,
        &user1_ac_sk,
        &credential_user1,
        send1_keypair.pub_key.as_bytes(),
    )
    .unwrap();
    let (commitment_user2, proof_user2, commitment_key_user2) = ac_commit(
        &mut prng,
        &user2_ac_sk,
        &credential_user2,
        send2_keypair.pub_key.as_bytes(),
    )
    .unwrap();

    // 2.3 verifying commitment and put them on AIR
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user1,
        &proof_user1,
        send1_pubkey.as_bytes()
    )
    .is_ok());
    air.insert(send1_pubkey.as_bytes(), commitment_user1);
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user2,
        &proof_user2,
        send2_pubkey.as_bytes()
    )
    .is_ok());
    air.insert(send2_pubkey.as_bytes(), commitment_user2);

    // 3. Prepare input AssetRecord
    // 3.1 get blind asset records "from ledger" and open them
    let bar1_bytes = include_bytes!("./migrate_files/xfr_bar_conf_1.bin");
    let (bar1, memo1): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar1_bytes).unwrap();
    let bar2_bytes = include_bytes!("./migrate_files/xfr_bar_conf_2.bin");
    let (bar2, memo2): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar2_bytes).unwrap();

    let oar1 = open_blind_asset_record(&bar1, &memo1, &send1_keypair).unwrap();
    let oar2 = open_blind_asset_record(&bar2, &memo2, &send2_keypair).unwrap();

    // 3.2. build AssetRecord from oar
    let input_asset_record1 = AssetRecord::from_open_asset_record_with_tracing(
        &mut prng,
        oar1,
        policies.clone(),
        &user1_ac_sk,
        &credential_user1,
        &commitment_key_user1.unwrap(),
    )
    .unwrap();

    let input_asset_record2 = AssetRecord::from_open_asset_record_with_tracing(
        &mut prng,
        oar2,
        policies.clone(),
        &user2_ac_sk,
        &credential_user2,
        &commitment_key_user2.unwrap(),
    )
    .unwrap();

    // 3. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_no_asset_tracing(
        amount_out1,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        recv_pub_key,
    );
    // 3.3 build output asset record
    let output_asset_record =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[input_asset_record1, input_asset_record2],
        &[output_asset_record],
        &[&send1_keypair, &send2_keypair],
    )
    .unwrap();

    let policies = XfrNotePoliciesRef::new(
        vec![&policies, &policies],
        vec![
            Some(&air[xfr_note.body.inputs[0].public_key.as_bytes()]),
            Some(&air[xfr_note.body.inputs[1].public_key.as_bytes()]),
        ],
        vec![&no_policies],
        vec![None],
    );

    // 5. validator verify xfr_note
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

    // 6. receiver retrieved his BlindAssetRecord
    let recv_bar = &xfr_note.body.outputs[0];
    let recv_memo = &xfr_note.body.owners_memos[0];
    let recv_oar = open_blind_asset_record(recv_bar, recv_memo, &recv_keypair).unwrap();

    assert!(recv_memo.is_some());
    assert!(recv_bar.amount.is_confidential());
    assert!(!recv_bar.asset_type.is_confidential());
    assert_eq!(recv_oar.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar.amount, amount_out1);
    assert_eq!(recv_oar.blind_asset_record.public_key, recv_pub_key);

    // 7. asset tracing on inputs
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
    assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 1);
    assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
    assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 0);

    let records_data = trace_assets(&xfr_note.body, &tracer_keys).unwrap();

    assert_eq!(records_data.len(), 2);
    check_record_data(
        &records_data[0],
        amount_in1,
        ASSET1_TYPE,
        vec![1u32, 2],
        &send1_pubkey,
    );
    check_record_data(
        &records_data[1],
        amount_in2,
        ASSET1_TYPE,
        vec![11u32, 22],
        &send2_pubkey,
    );
}

#[test]
fn xfr_confidential_asset_tracing_and_identity_tracking_on_outputs_1_2() {
    let send_keypair = serde_json::from_str::<XfrSecretKey>(SK1)
        .unwrap()
        .into_keypair();

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = BulletproofParams::default();
    let mut air: HashMap<&[u8], _> = HashMap::new();
    //let amount_in1 = 100u64;
    let amount_out1 = 75u64;
    let amount_out2 = 25u64;

    // 1. setup
    // 1.1 receiver keys
    let recv1_keypair = XfrKeyPair::generate(&mut prng);
    let recv1_pub_key = recv1_keypair.pub_key;
    let recv2_keypair = XfrKeyPair::generate(&mut prng);
    let recv2_pub_key = recv2_keypair.pub_key;

    // 1.2 Credential keys
    let (cred_issuer_pk, cred_issuer_sk) = anon_creds::ac_keygen_issuer(&mut prng, 4);
    let (recv1_ac_pk, recv1_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let (recv2_ac_pk, recv2_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

    // 1.3 setup policy
    let tracer_keys = AssetTracerKeyPair::generate(&mut prng);
    let id_policy_policy = IdentityRevealPolicy {
        cred_issuer_pub_key: cred_issuer_pk.clone(),
        reveal_map: vec![false, true, true, true], // reveal last three attributes
    };
    let policy = TracingPolicy {
        enc_keys: tracer_keys.enc_key.clone(),
        asset_tracing: true,                      // do asset tracing
        identity_tracing: Some(id_policy_policy), // do not trace identity
    };
    let policies = TracingPolicies::from_policy(policy);
    let no_policy = TracingPolicies::new();

    // 2. Credential for input users
    // 2.1 credential issuance:
    let recv1_attr = vec![1u32, 2u32, 3u32, 4u32];
    let recv2_attr = vec![11u32, 22u32, 33u32, 44u32];
    let cred_sig_user1 = ac_sign(&mut prng, &cred_issuer_sk, &recv1_ac_pk, &recv1_attr).unwrap();
    let cred_sig_user2 = ac_sign(&mut prng, &cred_issuer_sk, &recv2_ac_pk, &recv2_attr).unwrap();
    let credential_user1 = Credential {
        signature: cred_sig_user1,
        attributes: recv1_attr,
        issuer_pub_key: cred_issuer_pk.clone(),
    };
    let credential_user2 = Credential {
        signature: cred_sig_user2,
        attributes: recv2_attr,
        issuer_pub_key: cred_issuer_pk.clone(),
    };

    // 2.2 credential commitments
    let (commitment_user1, proof_user1, commitment_key_user1) = ac_commit(
        &mut prng,
        &recv1_ac_sk,
        &credential_user1,
        recv1_keypair.pub_key.as_bytes(),
    )
    .unwrap();
    let (commitment_user2, proof_user2, commitment_key_user2) = ac_commit(
        &mut prng,
        &recv2_ac_sk,
        &credential_user2,
        recv2_keypair.pub_key.as_bytes(),
    )
    .unwrap();

    // 2.3 verifying commitment and put them on AIR
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user1,
        &proof_user1,
        recv1_pub_key.as_bytes()
    )
    .is_ok());
    air.insert(recv1_pub_key.as_bytes(), commitment_user1);
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user2,
        &proof_user2,
        recv2_pub_key.as_bytes()
    )
    .is_ok());
    air.insert(recv2_pub_key.as_bytes(), commitment_user2);

    // 3. Prepare input AssetRecord
    // 3.1 get blind asset records "from ledger" and open them
    let bar_bytes = include_bytes!("./migrate_files/xfr_bar_conf_1.bin");
    let (bar, memo): (BlindAssetRecord, Option<OwnerMemo>) =
        bincode::deserialize(bar_bytes).unwrap();
    let oar = open_blind_asset_record(&bar, &memo, &send_keypair).unwrap();

    // 3.2. build AssetRecord from oar
    let input_asset_record = AssetRecord::from_open_asset_record_no_asset_tracing(oar);

    // 4. Prepare output AssetRecord
    // 3.1. build output asset_record template
    let template = AssetRecordTemplate::with_asset_tracing(
        amount_out1,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        recv1_pub_key,
        policies.clone(),
    );
    let output_asset_record_1 = AssetRecord::from_template_with_identity_tracing(
        &mut prng,
        &template,
        &recv1_ac_sk,
        &credential_user1,
        &commitment_key_user1.unwrap(),
    )
    .unwrap();

    let template = AssetRecordTemplate::with_asset_tracing(
        amount_out2,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        recv2_pub_key,
        policies.clone(),
    );
    let output_asset_record_2 = AssetRecord::from_template_with_identity_tracing(
        &mut prng,
        &template,
        &recv2_ac_sk,
        &credential_user2,
        &commitment_key_user2.unwrap(),
    )
    .unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[input_asset_record],
        &[output_asset_record_1, output_asset_record_2],
        &[&send_keypair],
    )
    .unwrap();

    let policies = XfrNotePoliciesRef::new(
        vec![&no_policy],
        vec![None],
        vec![&policies, &policies],
        vec![
            Some(&air[xfr_note.body.outputs[0].public_key.as_bytes()]),
            Some(&air[xfr_note.body.outputs[1].public_key.as_bytes()]),
        ],
    );

    // 5. validator verify xfr_note
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

    //6. receiver retrieved his BlindAssetRecord
    let recv_bar1 = &xfr_note.body.outputs[0];
    let recv_memo1 = &xfr_note.body.owners_memos[0];
    let recv_oar1 = open_blind_asset_record(recv_bar1, recv_memo1, &recv1_keypair).unwrap();

    assert!(recv_memo1.is_some());
    assert!(recv_bar1.amount.is_confidential());
    assert!(!recv_bar1.asset_type.is_confidential());
    assert_eq!(recv_oar1.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar1.amount, amount_out1);
    assert_eq!(recv_oar1.blind_asset_record.public_key, recv1_pub_key);

    let recv_bar2 = &xfr_note.body.outputs[1];
    let recv_memo2 = &xfr_note.body.owners_memos[1];
    let recv_oar2 = open_blind_asset_record(recv_bar2, recv_memo2, &recv2_keypair).unwrap();

    assert!(recv_memo2.is_some());
    assert!(recv_bar2.amount.is_confidential());
    assert!(!recv_bar2.asset_type.is_confidential());
    assert_eq!(recv_oar2.asset_type, ASSET1_TYPE);
    assert_eq!(recv_oar2.amount, amount_out2);
    assert_eq!(recv_oar2.blind_asset_record.public_key, recv2_pub_key);

    //7. asset tracing on inputs
    assert_eq!(xfr_note.body.asset_tracing_memos.len(), 3);
    assert_eq!(xfr_note.body.asset_tracing_memos[0].len(), 0);
    assert_eq!(xfr_note.body.asset_tracing_memos[1].len(), 1);
    assert_eq!(xfr_note.body.asset_tracing_memos[2].len(), 1);

    let records_data = trace_assets(&xfr_note.body, &tracer_keys).unwrap();

    assert_eq!(records_data.len(), 2);
    check_record_data(
        &records_data[0],
        amount_out1,
        ASSET1_TYPE,
        vec![2u32, 3, 4],
        &recv1_pub_key,
    );
    check_record_data(
        &records_data[1],
        amount_out2,
        ASSET1_TYPE,
        vec![22u32, 33, 44],
        &recv2_pub_key,
    );
}

/// Complex transaction with
/// * M = 3 inputs
/// * N = 4 outputs
/// * Some inputs are confidentials others are not
/// * Some outputs are confidentials others are not
/// * Some inputs are tracked, others are not
/// * Some outputs are tracked, others are not
/// * Three asset types and two asset issuers
#[test]
fn xfr_complex_transaction() {
    // 4 total users, 1 sender three receivers
    // 3 asset types, 2 different tracing policies and one with no policy

    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = BulletproofParams::default();
    let mut air: HashMap<&[u8], _> = HashMap::new();
    let amount_asset1_in1 = 25;
    let amount_asset2_in2 = 50;
    let amount_asset3_in3 = 75;

    let amount_asset1_out1 = 20;
    let amount_asset1_out2 = 5;
    let amount_asset2_out3 = 50;
    let amount_asset3_out4 = 75;

    // credential keys
    let (cred_issuer_pk, cred_issuer_sk) = anon_creds::ac_keygen_issuer(&mut prng, 4);

    // asset tracing keys
    let asset1_tracing_key = AssetTracerKeyPair::generate(&mut prng);
    let asset2_tracing_key = AssetTracerKeyPair::generate(&mut prng);

    // 1. setup
    // 1.1 users keys
    let user1_key_pair1 = XfrKeyPair::generate(&mut prng);
    let user1_key_pair2 = XfrKeyPair::generate(&mut prng);
    let user1_key_pair3 = XfrKeyPair::generate(&mut prng);

    let (user1_ac_pk, user1_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user2_key_pair1 = XfrKeyPair::generate(&mut prng);
    let (user2_ac_pk, user2_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user3_key_pair1 = XfrKeyPair::generate(&mut prng);
    let (user3_ac_pk, user3_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
    let user4_key_pair1 = XfrKeyPair::generate(&mut prng);
    let (user4_ac_pk, user4_ac_sk) = anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);

    //2.1 generate credential for each of the 4 users
    let user1_attrs = vec![0u32, 1, 2, 3];
    let user2_attrs = vec![4u32, 5, 6, 7];
    let user3_attrs = vec![8u32, 9, 10, 11];
    let user4_attrs = vec![12u32, 13, 14, 15];
    let credential_user1 = Credential {
        signature: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user1_ac_pk,
            user1_attrs.as_slice(),
        )
        .unwrap(),
        attributes: user1_attrs,
        issuer_pub_key: cred_issuer_pk.clone(),
    };
    let credential_user2 = Credential {
        signature: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user2_ac_pk,
            user2_attrs.as_slice(),
        )
        .unwrap(),
        attributes: user2_attrs,
        issuer_pub_key: cred_issuer_pk.clone(),
    };
    let credential_user3 = Credential {
        signature: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user3_ac_pk,
            user3_attrs.as_slice(),
        )
        .unwrap(),
        attributes: user3_attrs,
        issuer_pub_key: cred_issuer_pk.clone(),
    };
    let credential_user4 = Credential {
        signature: ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &user4_ac_pk,
            user4_attrs.as_slice(),
        )
        .unwrap(),
        attributes: user4_attrs,
        issuer_pub_key: cred_issuer_pk.clone(),
    };

    // 1.4 Register address/identity in AIR
    let (commitment_user1_addr1, proof, commitment_user1_addr1_key) = ac_commit(
        &mut prng,
        &user1_ac_sk,
        &credential_user1,
        user1_key_pair1.pub_key.as_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user1_addr1,
        &proof,
        user1_key_pair1.pub_key.as_bytes()
    )
    .is_ok());
    air.insert(user1_key_pair1.pub_key.as_bytes(), commitment_user1_addr1);

    let (commitment_user2_addr1, proof, _commitment_user2_addr1_key) = ac_commit(
        &mut prng,
        &user2_ac_sk,
        &credential_user2,
        user2_key_pair1.pub_key.as_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user2_addr1,
        &proof,
        user2_key_pair1.pub_key.as_bytes()
    )
    .is_ok());
    air.insert(user2_key_pair1.pub_key.as_bytes(), commitment_user2_addr1);

    let (commitment_user3_addr1, proof, commitment_user3_addr1_key) = ac_commit(
        &mut prng,
        &user3_ac_sk,
        &credential_user3,
        user3_key_pair1.pub_key.as_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user3_addr1,
        &proof,
        user3_key_pair1.pub_key.as_bytes()
    )
    .is_ok());
    air.insert(user3_key_pair1.pub_key.as_bytes(), commitment_user3_addr1);

    let (commitment_user4_addr1, proof, _commitment_user4_addr1_key) = ac_commit(
        &mut prng,
        &user4_ac_sk,
        &credential_user4,
        user4_key_pair1.pub_key.as_bytes(),
    )
    .unwrap();
    assert!(ac_verify_commitment(
        &cred_issuer_pk,
        &commitment_user4_addr1,
        &proof,
        user4_key_pair1.pub_key.as_bytes()
    )
    .is_ok());
    air.insert(user4_key_pair1.pub_key.as_bytes(), commitment_user4_addr1);

    // 1.5 Define asset issuer tracing policies
    let id_tracing_policy1 = IdentityRevealPolicy {
        cred_issuer_pub_key: cred_issuer_pk.clone(),
        reveal_map: vec![false, true, false, true],
    }; // revealing attr2 and attr4

    let id_tracing_policy2 = IdentityRevealPolicy {
        cred_issuer_pub_key: cred_issuer_pk,
        reveal_map: vec![true, true, false, true],
    }; // revealing attr1 , attr2 and attr4

    let asset_tracing_policy_asset1_input = TracingPolicies::from_policy(TracingPolicy {
        // use in asset 1 when it is an input of a Xfr
        enc_keys: asset1_tracing_key.enc_key.clone(), // publicly available
        asset_tracing: true,                          // encrypt record info to asset issuer
        identity_tracing: Some(id_tracing_policy1),   // no identity tracking
    });
    let asset_tracing_policy_asset2_output = TracingPolicies::from_policy(TracingPolicy {
        // use in asset 2 when it is an output of a Xfr
        enc_keys: asset2_tracing_key.enc_key.clone(), // publicly available
        asset_tracing: true,                          // encrypt record info to asset issuer
        identity_tracing: Some(id_tracing_policy2),   // no identity tracking
    });

    // 2. Prepare inputs
    // 2.1 get "from ledger" blind asset records
    let (bar_user1_addr1, memo1) = conf_blind_asset_record_from_ledger(
        &user1_key_pair1.pub_key,
        amount_asset1_in1,
        ASSET1_TYPE,
    );
    let (bar_user1_addr2, memo2) = conf_blind_asset_record_from_ledger(
        &user1_key_pair2.pub_key,
        amount_asset2_in2,
        ASSET2_TYPE,
    );
    let (bar_user1_addr3, memo3) = conf_blind_asset_record_from_ledger(
        &user1_key_pair3.pub_key,
        amount_asset3_in3,
        ASSET3_TYPE,
    );
    // 2.2 open asset records
    let oar_user1_addr1 =
        open_blind_asset_record(&bar_user1_addr1, &Some(memo1), &user1_key_pair1).unwrap();
    let oar_user1_addr2 =
        open_blind_asset_record(&bar_user1_addr2, &Some(memo2), &user1_key_pair2).unwrap();
    let oar_user1_addr3 =
        open_blind_asset_record(&bar_user1_addr3, &Some(memo3), &user1_key_pair3).unwrap();
    // 2.3 prepare inputs
    let ar_in1 = AssetRecord::from_open_asset_record_with_tracing(
        &mut prng,
        oar_user1_addr1,
        asset_tracing_policy_asset1_input.clone(),
        &user1_ac_sk,
        &credential_user1,
        &commitment_user1_addr1_key.unwrap(),
    )
    .unwrap();
    let ar_in2 = AssetRecord::from_open_asset_record_no_asset_tracing(oar_user1_addr2);
    let ar_in3 = AssetRecord::from_open_asset_record_no_asset_tracing(oar_user1_addr3);

    // 3. Prepare outputs

    let template1 = AssetRecordTemplate::with_no_asset_tracing(
        amount_asset1_out1,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user1_key_pair1.pub_key,
    );

    let template2 = AssetRecordTemplate::with_no_asset_tracing(
        amount_asset1_out2,
        ASSET1_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user2_key_pair1.pub_key,
    );

    let template3 = AssetRecordTemplate::with_asset_tracing(
        amount_asset2_out3,
        ASSET2_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user3_key_pair1.pub_key,
        asset_tracing_policy_asset2_output.clone(),
    );

    let template4 = AssetRecordTemplate::with_no_asset_tracing(
        amount_asset3_out4,
        ASSET3_TYPE,
        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
        user4_key_pair1.pub_key,
    );

    let output_asset_record1 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template1).unwrap();

    let output_asset_record2 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template2).unwrap();

    let output_asset_record3 = AssetRecord::from_template_with_identity_tracing(
        &mut prng,
        &template3,
        &user3_ac_sk,
        &credential_user3,
        &commitment_user3_addr1_key.unwrap(),
    )
    .unwrap();

    let output_asset_record4 =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &template4).unwrap();

    // 4. create xfr_note
    let xfr_note = gen_xfr_note(
        &mut prng,
        &[ar_in1, ar_in2, ar_in3],
        &[
            output_asset_record1,
            output_asset_record2,
            output_asset_record3,
            output_asset_record4,
        ],
        &[&user1_key_pair1, &user1_key_pair2, &user1_key_pair3],
    )
    .unwrap();

    // 5. Verify xfr_note
    let no_policy = TracingPolicies::new();
    let input1_credential_commitment = &air[xfr_note.body.inputs[0].public_key.as_bytes()];
    let input_policies = vec![&asset_tracing_policy_asset1_input, &no_policy, &no_policy];
    let inputs_sig_commitments = vec![Some(input1_credential_commitment), None, None];

    let output3_credential_commitment = &air[xfr_note.body.outputs[2].public_key.as_bytes()];
    let output_policies = vec![
        &no_policy,
        &no_policy,
        &asset_tracing_policy_asset2_output,
        &no_policy,
    ];
    let output_sig_commitments = vec![None, None, Some(output3_credential_commitment), None];

    let policies = XfrNotePoliciesRef::new(
        input_policies,
        inputs_sig_commitments,
        output_policies,
        output_sig_commitments,
    );
    assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).is_ok());

    // 5. check tracing
    // 5.1 tracer 1
    let records_data = trace_assets(&xfr_note.body, &asset1_tracing_key).unwrap();

    assert_eq!(records_data.len(), 1);
    check_record_data(
        &records_data[0],
        amount_asset1_in1,
        ASSET1_TYPE,
        vec![1, 3], // expect second and last attribute
        &user1_key_pair1.pub_key,
    );

    let records_data = trace_assets(&xfr_note.body, &asset2_tracing_key).unwrap();

    assert_eq!(records_data.len(), 1);
    check_record_data(
        &records_data[0],
        amount_asset2_out3,
        ASSET2_TYPE,
        vec![8u32, 9, 11], // expect first, second and last attribute of user 3
        &user3_key_pair1.pub_key,
    );
}
