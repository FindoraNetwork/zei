use crate::api::anon_creds;
use crate::api::anon_creds::{ac_commit, ACCommitment, Credential};
use crate::setup::PublicParams;
use crate::xfr::asset_record::AssetRecordType;
use crate::xfr::lib::{
    batch_verify_xfr_body_asset_records, batch_verify_xfr_notes,
    compute_transfer_multisig, gen_xfr_note, verify_xfr_body, verify_xfr_note,
    XfrNotePolicies,
};
use crate::xfr::sig::XfrKeyPair;
use crate::xfr::structs::{
    AssetRecord, AssetRecordTemplate, AssetTracerEncKeys, AssetTracerKeyPair, AssetType,
    IdentityRevealPolicy, TracerMemo, TracingPolicy, XfrAmount, XfrAssetType, XfrBody,
    XfrNote, ASSET_TYPE_LENGTH,
};
use algebra::groups::Scalar as _;
use algebra::ristretto::RistrettoScalar as Scalar;
use crypto::basics::elgamal::{elgamal_encrypt, elgamal_key_gen};
use crypto::pedersen_elgamal::{pedersen_elgamal_eq_prove, PedersenElGamalEqProof};
use ruc::*;

use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
use itertools::Itertools;
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use utils::errors::ZeiError;
use utils::errors::ZeiError::{
    XfrVerifyAssetTracingAssetAmountError, XfrVerifyAssetTracingIdentityError,
};
use utils::u64_to_u32_pair;

pub(crate) fn create_xfr(
    prng: &mut ChaChaRng,
    input_templates: &[AssetRecordTemplate],
    output_templates: &[AssetRecordTemplate],
    inkeys: &[&XfrKeyPair],
) -> (XfrNote, Vec<AssetRecord>, Vec<AssetRecord>) {
    let inputs = input_templates
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(prng, template).unwrap()
        })
        .collect_vec();
    let outputs = output_templates
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(prng, &template).unwrap()
        })
        .collect_vec();

    let xfr_note =
        gen_xfr_note(prng, inputs.as_slice(), outputs.as_slice(), inkeys).unwrap();

    (xfr_note, inputs, outputs)
}

pub(crate) fn gen_key_pair_vec(size: usize, prng: &mut ChaChaRng) -> Vec<XfrKeyPair> {
    let mut keys = vec![];
    for _i in 0..size {
        keys.push(XfrKeyPair::generate(prng));
    }
    keys
}

fn do_transfer_tests_single_asset(
    params: &mut PublicParams,
    inputs_template: &[AssetRecordType],
    outputs_template: &[AssetRecordType],
) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let asset_type = AssetType::from_identical_byte(0u8);

    let input_amount = 100u64 * outputs_template.len() as u64;
    let total_amount = input_amount * inputs_template.len() as u64;
    let output_amount = total_amount / outputs_template.len() as u64;
    // make sure no truncation during integer division, and that total input == total output
    assert_eq!(total_amount, output_amount * outputs_template.len() as u64);

    let inkeys = gen_key_pair_vec(inputs_template.len(), &mut prng);
    let inkeys_ref = inkeys.iter().collect_vec();

    let outkeys = gen_key_pair_vec(outputs_template.len(), &mut prng);

    let inputs = inputs_template
        .iter()
        .zip(inkeys.iter())
        .map(|(asset_record_type, key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                input_amount,
                asset_type,
                *asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let outputs = outputs_template
        .iter()
        .zip(outkeys.iter())
        .map(|(asset_record_type, key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                output_amount,
                asset_type,
                *asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let pc_gens = RistrettoPedersenGens::default();

    let tuple = create_xfr(
        &mut prng,
        inputs.as_slice(),
        outputs.as_slice(),
        inkeys_ref.as_slice(),
    );

    let xfr_note = tuple.0;
    let mut inputs = tuple.1;
    let mut outputs = tuple.2;

    let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
    // test 1: simple transfer
    pnk!(verify_xfr_note(
        &mut prng,
        params,
        &xfr_note,
        &policies.to_ref()
    ));

    // 1.1 test batching
    pnk!(batch_verify_xfr_notes(
        &mut prng,
        params,
        &[&xfr_note, &xfr_note, &xfr_note],
        &[&policies.to_ref(); 3]
    ));

    // test 2: overflow transfer
    let old_output3: AssetRecord = outputs[3].clone();
    let asset_record = AssetRecordTemplate::with_no_asset_tracing(
        total_amount + 1,
        asset_type,
        outputs[3].open_asset_record.get_record_type(),
        outputs[3].open_asset_record.blind_asset_record.public_key,
    );
    outputs[3] =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &asset_record)
            .unwrap();
    let xfr_note = gen_xfr_note(
        &mut prng,
        inputs.as_slice(),
        outputs.as_slice(),
        inkeys_ref.as_slice(),
    );
    msg_eq!(
        ZeiError::XfrCreationAssetAmountError,
        xfr_note.unwrap_err(),
        "Xfr cannot be build if output total amount is greater than input amounts"
    );

    // output 3 back to original
    outputs[3] = old_output3;
    let mut xfr_note = gen_xfr_note(
        &mut prng,
        inputs.as_slice(),
        outputs.as_slice(),
        inkeys_ref.as_slice(),
    )
    .unwrap();

    match outputs[3].open_asset_record.get_record_type() {
        AssetRecordType::ConfidentialAmount_ConfidentialAssetType
        | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => {
            let (low, high) = u64_to_u32_pair(total_amount + 1);
            let commitment_low = pc_gens
                .commit(Scalar::from_u32(low), Scalar::random(&mut prng))
                .compress();
            let commitment_high = pc_gens
                .commit(Scalar::from_u32(high), Scalar::random(&mut prng))
                .compress();
            xfr_note.body.outputs[3].amount =
                XfrAmount::Confidential((commitment_low, commitment_high));
        }
        _ => {
            xfr_note.body.outputs[3].amount = XfrAmount::NonConfidential(0xFFFFFFFFFF);
        }
    }

    assert!(
        batch_verify_xfr_body_asset_records(&mut prng, params, &[&xfr_note.body])
            .is_err(),
        "Confidential transfer with invalid amounts should fail verification"
    );

    //test 3: one output asset type different from rest
    let old_output3 = outputs[3].clone();
    let asset_record = AssetRecordTemplate::with_no_asset_tracing(
        old_output3.open_asset_record.amount,
        AssetType::from_identical_byte(1u8),
        outputs[3].open_asset_record.get_record_type(),
        old_output3.open_asset_record.blind_asset_record.public_key,
    );
    outputs[3] =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &asset_record)
            .unwrap();
    let xfr_note = gen_xfr_note(
        &mut prng,
        inputs.as_slice(),
        outputs.as_slice(),
        inkeys_ref.as_slice(),
    );
    msg_eq!(
        ZeiError::XfrCreationAssetAmountError,
        xfr_note.unwrap_err(),
        "Xfr cannot be build if output asset types are different"
    );

    outputs[3] = old_output3;

    let mut xfr_note = gen_xfr_note(
        &mut prng,
        inputs.as_slice(),
        outputs.as_slice(),
        inkeys_ref.as_slice(),
    )
    .unwrap();

    // check state is clean
    assert!(
        batch_verify_xfr_body_asset_records(&mut prng, params, &[&xfr_note.body])
            .is_ok()
    );
    // modify xfr_note asset on an output

    let old_output1 = outputs[1].clone();
    let mut out1 = old_output1.open_asset_record.blind_asset_record.clone();
    out1.asset_type = match old_output1.open_asset_record.get_record_type() {
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => {
            XfrAssetType::NonConfidential(AssetType::from_identical_byte(1u8))
        }
        _ => XfrAssetType::Confidential(
            pc_gens
                .commit(
                    Scalar::from_u32(10),
                    old_output1.open_asset_record.type_blind,
                )
                .compress(),
        ),
    };
    xfr_note.body.outputs[1] = out1;
    assert!(
        batch_verify_xfr_body_asset_records(&mut prng, params, &[&xfr_note.body])
            .is_err(),
        "Transfer with different asset types should fail verification"
    );

    //test 4:  one input asset different from rest
    outputs[1] = old_output1;
    let old_input1 = inputs[1].clone();

    let ar_template = AssetRecordTemplate::with_no_asset_tracing(
        input_amount,
        AssetType::from_identical_byte(1u8),
        inputs_template[1],
        inputs[1].open_asset_record.blind_asset_record.public_key,
    );
    inputs[1] =
        AssetRecord::from_template_no_identity_tracing(&mut prng, &ar_template).unwrap();
    let xfr_note = gen_xfr_note(
        &mut prng,
        inputs.as_slice(),
        outputs.as_slice(),
        inkeys_ref.as_slice(),
    );

    msg_eq!(
        ZeiError::XfrCreationAssetAmountError,
        xfr_note.unwrap_err(),
        "Xfr cannot be build if output asset types are different"
    );
    inputs[1] = old_input1;

    let mut xfr_note = gen_xfr_note(
        &mut prng,
        inputs.as_slice(),
        outputs.as_slice(),
        inkeys_ref.as_slice(),
    )
    .unwrap();
    // modify xfr_note asset on an input

    let old_input1: AssetRecord = inputs[1].clone();
    let mut in1 = old_input1.open_asset_record.blind_asset_record.clone();
    in1.asset_type = match old_input1.open_asset_record.get_record_type() {
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => {
            XfrAssetType::NonConfidential(AssetType::from_identical_byte(1u8))
        }
        _ => XfrAssetType::Confidential(
            pc_gens
                .commit(
                    Scalar::from_u32(10),
                    old_input1.open_asset_record.type_blind,
                )
                .compress(),
        ),
    };
    xfr_note.body.inputs[1] = in1;
    assert!(
        batch_verify_xfr_body_asset_records(&mut prng, params, &[&xfr_note.body])
            .is_err(),
        "Confidential transfer with different asset types should fail verification ok"
    );
}

mod single_asset_no_tracing {

    use super::*;
    use crate::setup::{PublicParams, DEFAULT_BP_NUM_GENS};

    #[test]
    fn test_transfer_not_confidential() {
        /*! Test non confidential transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let inputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 4];
        let outputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_confidential_amount_plain_asset() {
        /*! Test confidential amount in all inputs and all outputs transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let inputs_template =
            [AssetRecordType::ConfidentialAmount_NonConfidentialAssetType; 4];
        let outputs_template =
            [AssetRecordType::ConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_confidential_asset_plain_amount() {
        /*! Test confidential asset types in all inputs and all outputs transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let inputs_template =
            [AssetRecordType::NonConfidentialAmount_ConfidentialAssetType; 4];
        let outputs_template =
            [AssetRecordType::NonConfidentialAmount_ConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_confidential() {
        /*! Test confidential amount and confidential asset in all inputs and outputs*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let inputs_template =
            [AssetRecordType::ConfidentialAmount_ConfidentialAssetType; 4];
        let outputs_template =
            vec![AssetRecordType::ConfidentialAmount_ConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_input_some_amount_confidential_output_non_confidential() {
        /*! Test confidential amount in some inputs transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let inputs_template = [
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let outputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_inputs_some_asset_confidential_output_non_confidential() {
        /*! Test confidential asset_types in some inputs transfers*/
        let mut params = PublicParams::default();
        let inputs_template = [
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let outputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_input_some_confidential_amount_and_asset_type_output_non_confidential(
    ) {
        /*! Test confidential amount and asset type in some input AssetRecords transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let inputs_template = [
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let outputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_input_some_confidential_amount_other_confidential_asset_type_output_non_confidential(
    ) {
        /*! Test confidential amount in some input and confidential asset type in other input AssetRecords transfers*/
        let mut params = PublicParams::default();
        let inputs_template = [
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let outputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_output_some_amount_confidential_input_non_confidential() {
        /*! Test confidential amount in some outputs transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let outputs_template = [
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let inputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_output_some_asset_confidential_input_non_confidential() {
        /*! Test some confidential asset types in the output transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let outputs_template = [
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let inputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_output_some_confidential_amount_and_asset_type_input_non_confidential(
    ) {
        /*! I test confidential amount and asset type in some output AssetRecords transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let outputs_template = [
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let inputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }

    #[test]
    fn test_transfer_output_some_confidential_amount_other_confidential_asset_type_input_non_confidential(
    ) {
        /*! I test confidential amount in some output and confidential asset type in other output AssetRecords transfers*/
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        let outputs_template = [
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        ];

        let inputs_template =
            [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
        do_transfer_tests_single_asset(&mut params, &inputs_template, &outputs_template);
    }
}

mod multi_asset_no_tracing {

    use super::*;
    use crate::setup::DEFAULT_BP_NUM_GENS;
    use crate::xfr::lib::XfrNotePolicies;

    #[test]
    fn do_multiasset_transfer_tests() {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::from_file_if_exists(DEFAULT_BP_NUM_GENS, None);
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_type0 = AssetType::from_identical_byte(0u8);
        let asset_type1 = AssetType::from_identical_byte(1u8);
        let asset_type2 = AssetType::from_identical_byte(2u8);
        let asset_record_type =
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType;

        let inkeys = gen_key_pair_vec(6, &mut prng);
        let inkeys_ref = inkeys.iter().collect_vec();
        let input_amount = [
            (10u64, asset_type0),
            (10u64, asset_type1),
            (10u64, asset_type0),
            (10u64, asset_type1),
            (10u64, asset_type1),
            (10u64, asset_type2),
        ];
        let input_record = input_amount
            .iter()
            .zip(inkeys.iter())
            .map(|((amount, asset_type), key_pair)| {
                AssetRecordTemplate::with_no_asset_tracing(
                    *amount,
                    *asset_type,
                    asset_record_type,
                    key_pair.pub_key,
                )
            })
            .collect_vec();

        let out_keys = gen_key_pair_vec(6, &mut prng);

        let out_amount = [
            (30u64, asset_type1),
            (5u64, asset_type2),
            (1u64, asset_type2),
            (4u64, asset_type2),
            (0u64, asset_type0),
            (20u64, asset_type0),
        ];
        let output_record = out_amount
            .iter()
            .zip(out_keys.iter())
            .map(|((amount, asset_type), key_pair)| {
                AssetRecordTemplate::with_no_asset_tracing(
                    *amount,
                    *asset_type,
                    asset_record_type,
                    key_pair.pub_key,
                )
            })
            .collect_vec();

        let (xfr_note, _, _) =
            create_xfr(&mut prng, &input_record, &output_record, &inkeys_ref);

        let policies =
            XfrNotePolicies::empty_policies(input_record.len(), output_record.len());

        // test 1: simple transfer using confidential asset mixer
        pnk!(verify_xfr_note(
            &mut prng,
            &mut params,
            &xfr_note,
            &policies.to_ref()
        ));

        let asset_record_type =
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType;

        let input_amount = [
            (10u64, asset_type0),
            (10u64, asset_type1),
            (10u64, asset_type0),
            (10u64, asset_type1),
            (10u64, asset_type1),
            (10u64, asset_type2),
        ];

        let inkeys = gen_key_pair_vec(6, &mut prng);
        let inkeys_ref = inkeys.iter().collect_vec();

        let input_record = input_amount
            .iter()
            .zip(inkeys.iter())
            .map(|((amount, asset_type), key_pair)| {
                AssetRecordTemplate::with_no_asset_tracing(
                    *amount,
                    *asset_type,
                    asset_record_type,
                    key_pair.pub_key,
                )
            })
            .collect_vec();

        let out_keys = gen_key_pair_vec(6, &mut prng);

        let output_record = input_amount
            .iter()
            .zip(out_keys.iter())
            .map(|((amount, asset_type), key_pair)| {
                AssetRecordTemplate::with_no_asset_tracing(
                    *amount,
                    *asset_type,
                    asset_record_type,
                    key_pair.pub_key,
                )
            })
            .collect_vec();

        let (mut xfr_note, _, _) = create_xfr(
            &mut prng,
            &input_record,
            &output_record,
            inkeys_ref.as_slice(),
        );

        let policies =
            XfrNotePolicies::empty_policies(input_record.len(), output_record.len());

        pnk!(verify_xfr_note(
            &mut prng,
            &mut params,
            &xfr_note,
            &policies.to_ref()
        ));

        xfr_note.body.inputs[0].amount = XfrAmount::NonConfidential(8u64);

        xfr_note.multisig =
            compute_transfer_multisig(&xfr_note.body, inkeys_ref.as_slice()).unwrap();

        msg_eq!(
            ZeiError::XfrVerifyAssetAmountError,
            verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies.to_ref())
                .unwrap_err(),
            "Multi asset transfer non confidential"
        );
    }
}

mod keys {

    use super::*;

    #[test]
    fn xfr_keys_error() {
        let amounts = [
            (10, AssetType::from_identical_byte(0u8)),
            (10, AssetType::from_identical_byte(1u8)),
        ]; //input and output

        let mut inputs = vec![];
        let mut outputs = vec![];

        let mut outkeys = vec![];
        let mut inkeys = vec![];
        let mut in_asset_records = vec![];
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let asset_record_type =
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType;

        for x in amounts.iter() {
            let keypair = XfrKeyPair::generate(&mut prng);
            let asset_record = AssetRecordTemplate::with_no_asset_tracing(
                x.0,
                x.1,
                asset_record_type,
                keypair.pub_key,
            );

            inputs.push(
                AssetRecord::from_template_no_identity_tracing(&mut prng, &asset_record)
                    .unwrap(),
            );

            in_asset_records.push(asset_record);
            inkeys.push(keypair);
        }

        for x in amounts.iter() {
            let keypair = XfrKeyPair::generate(&mut prng);

            let ar_template = AssetRecordTemplate::with_no_asset_tracing(
                x.0,
                x.1,
                asset_record_type,
                keypair.pub_key,
            );
            outputs.push(
                AssetRecord::from_template_no_identity_tracing(&mut prng, &ar_template)
                    .unwrap(),
            );
            outkeys.push(keypair);
        }

        let xfr_note = gen_xfr_note(
            &mut prng,
            inputs.as_slice(),
            outputs.as_slice(),
            &[], //no keys
        );
        msg_eq!(ZeiError::ParameterError, xfr_note.unwrap_err());

        let key1 = XfrKeyPair::generate(&mut prng);
        let key2 = XfrKeyPair::generate(&mut prng);
        let xfr_note = gen_xfr_note(
            &mut prng,
            inputs.as_slice(),
            outputs.as_slice(),
            &[&key1, &key2],
        );

        msg_eq!(ZeiError::ParameterError, xfr_note.unwrap_err());
    }
}

mod identity_tracing {

    //////////////////////////////////////////////////////////////////////////////////////////////////
    ////    Tests with identity tracing                                                          ////
    //////////////////////////////////////////////////////////////////////////////////////////////////

    use super::*;
    use crate::xfr::lib::XfrNotePoliciesRef;
    use crate::xfr::structs::TracingPolicies;

    fn check_identity_tracing_for_asset_type(asset_record_type: AssetRecordType) {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let addr = b"0x7789654"; // receiver address

        let tracer_keys = AssetTracerKeyPair::generate(&mut prng);

        let attrs = vec![1u32, 2, 3, 4];
        let (cred_issuer_pk, cred_issuer_sk) =
            anon_creds::ac_keygen_issuer(&mut prng, 4);
        let (receiver_ac_pk, receiver_ac_sk) =
            anon_creds::ac_keygen_user(&mut prng, &cred_issuer_pk);
        let ac_signature = anon_creds::ac_sign(
            &mut prng,
            &cred_issuer_sk,
            &receiver_ac_pk,
            attrs.as_slice(),
        )
        .unwrap();

        let credential = Credential {
            signature: ac_signature,
            attributes: attrs,
            issuer_pub_key: cred_issuer_pk.clone(),
        };

        let (sig_commitment, _, key) =
            ac_commit(&mut prng, &receiver_ac_sk, &credential, addr).unwrap();

        let id_tracing_policy = IdentityRevealPolicy {
            cred_issuer_pub_key: cred_issuer_pk,
            reveal_map: vec![false, true, false, true],
        }; // revealing attr2 and attr4

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: tracer_keys.enc_key,
            asset_tracing: false,
            identity_tracing: Some(id_tracing_policy),
        });

        let input_keypair = XfrKeyPair::generate(&mut prng);

        let input_asset_record = AssetRecordTemplate::with_no_asset_tracing(
            10,
            AssetType::from_identical_byte(0u8),
            asset_record_type,
            input_keypair.pub_key,
        );

        let input = AssetRecord::from_template_no_identity_tracing(
            &mut prng,
            &input_asset_record,
        )
        .unwrap();

        let output_asset_record = AssetRecordTemplate::with_asset_tracing(
            10,
            AssetType::from_identical_byte(0u8),
            asset_record_type,
            input_keypair.pub_key,
            tracing_policy.clone(),
        );

        let outputs = [AssetRecord::from_template_with_identity_tracing(
            &mut prng,
            &output_asset_record,
            &receiver_ac_sk,
            &credential,
            &key.unwrap(),
        )
        .unwrap()];

        let xfr_note =
            gen_xfr_note(&mut prng, &[input], &outputs, &[&input_keypair]).unwrap();

        let null_policies_input = &TracingPolicies::new();

        let policies = XfrNotePoliciesRef::new(
            vec![null_policies_input],
            vec![None; 1],
            vec![&tracing_policy],
            vec![Some(&sig_commitment)],
        );

        pnk!(verify_xfr_note(
            &mut prng,
            &mut params,
            &xfr_note,
            &policies
        ));
        let policies = XfrNotePoliciesRef::new(
            vec![&tracing_policy],
            vec![Some(&sig_commitment)],
            vec![null_policies_input],
            vec![None; 1],
        );
        msg_eq!(
            XfrVerifyAssetTracingIdentityError,
            verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies).unwrap_err(),
        );

        //test serialization
        //to msg pack whole Xfr
        let mut vec = vec![];
        assert_eq!(
            true,
            xfr_note.serialize(&mut Serializer::new(&mut vec)).is_ok()
        );
        let mut de = Deserializer::new(&vec[..]);
        let xfr_de = XfrNote::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note, xfr_de);
    }

    #[test]
    fn test_identity_tracing_for_conf_assets() {
        check_identity_tracing_for_asset_type(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        );
    }

    #[test]
    fn test_identity_tracing_for_non_conf_assets() {
        check_identity_tracing_for_asset_type(
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
    }
}

mod asset_tracing {

    //////////////////////////////////////////////////////////////////////////////////////////////////
    ////    Tests with asset tracing                                                              ///
    //////////////////////////////////////////////////////////////////////////////////////////////////

    use super::*;
    use crate::xfr::lib::{
        trace_assets, trace_assets_brute_force, XfrNotePolicies, XfrNotePoliciesRef,
    };
    use crate::xfr::structs::XfrAmount::NonConfidential;
    use crate::xfr::structs::{AssetTracerKeyPair, TracingPolicies};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::GroupArithmetic;
    use algebra::jubjub::JubjubScalar;
    use algebra::ristretto::{RistrettoPoint, RistrettoScalar};
    use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
    use crypto::basics::elgamal::ElGamalCiphertext;

    const GOLD_ASSET: AssetType = AssetType([0; ASSET_TYPE_LENGTH]);
    const BITCOIN_ASSET: AssetType = AssetType([1; ASSET_TYPE_LENGTH]);

    fn create_wrong_proof() -> PedersenElGamalEqProof {
        let m = Scalar::from_u32(10);
        let r = Scalar::from_u32(7657);
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = RistrettoPedersenGens::default();

        let (_sk, pk) = elgamal_key_gen::<_, RistrettoPoint>(&mut prng, &pc_gens.B);

        let ctext = elgamal_encrypt(&pc_gens.B, &m, &r, &pk);
        let commitment = pc_gens.commit(m, r);

        let mut prover_transcript = Transcript::new(b"test");

        let proof = pedersen_elgamal_eq_prove(
            &mut prover_transcript,
            &mut prng,
            &m,
            &r,
            &pk,
            &ctext,
            &commitment,
        );
        proof
    }

    fn do_test_asset_tracing(
        params: &mut PublicParams,
        input_templates: &[(
            AssetRecordType,
            &TracingPolicies,
            &AssetTracerKeyPair,
            AssetType,
        )],
        output_templates: &[(
            AssetRecordType,
            &TracingPolicies,
            &AssetTracerKeyPair,
            AssetType,
        )],
    ) {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);

        let input_amount = 100u64;

        let pc_gens = RistrettoPedersenGens::default();

        let in_keys = gen_key_pair_vec(input_templates.len(), &mut prng);
        let in_keys_ref = in_keys.iter().collect_vec();
        let inputs = input_templates
            .iter()
            .zip(in_keys.iter())
            .map(
                |(
                    (asset_record_type, tracing_policies, _tracer_keypair, asset_type),
                    key_pair,
                )| {
                    AssetRecordTemplate::with_asset_tracing(
                        input_amount,
                        *asset_type,
                        *asset_record_type,
                        key_pair.pub_key,
                        (*tracing_policies).clone(),
                    )
                },
            )
            .collect_vec();
        let out_keys = gen_key_pair_vec(output_templates.len(), &mut prng);
        let outputs = output_templates
            .iter()
            .zip(out_keys.iter())
            .map(
                |(
                    (asset_record_type, tracing_policies, _tracer_keypair, asset_type),
                    key_pair,
                )| {
                    AssetRecordTemplate::with_asset_tracing(
                        input_amount,
                        *asset_type,
                        *asset_record_type,
                        key_pair.pub_key,
                        (*tracing_policies).clone(),
                    )
                },
            )
            .collect_vec();

        let (xfr_note, inputs, outputs) = create_xfr(
            &mut prng,
            inputs.as_slice(),
            outputs.as_slice(),
            in_keys_ref.as_slice(),
        );

        let xfr_body = &xfr_note.body;

        let input_policies = input_templates
            .iter()
            .map(|(_, tracing_policies, _, _)| *tracing_policies)
            .collect_vec();
        let output_policies = output_templates
            .iter()
            .map(|(_, tracing_policies, _, _)| *tracing_policies)
            .collect_vec();

        let input_sig_commitment: Vec<Option<&ACCommitment>> = vec![None; inputs.len()];
        let output_sig_commitment: Vec<Option<&ACCommitment>> =
            vec![None; outputs.len()];

        let policies = XfrNotePoliciesRef::new(
            input_policies.clone(),
            input_sig_commitment.clone(),
            output_policies.clone(),
            output_sig_commitment.clone(),
        );

        // test 1: the verification is successful
        pnk!(verify_xfr_body(
            &mut prng,
            params,
            &xfr_body.clone(),
            &policies
        ));

        // check that we can recover amount and type from memos
        let candidate_assets = input_templates
            .iter()
            .chain(output_templates)
            .map(|x| x.3)
            .collect_vec();
        let records_data_brute_force = trace_assets_brute_force(
            &xfr_note.body,
            &input_templates[0].2,
            &candidate_assets,
        )
        .unwrap();
        let records_data = trace_assets(&xfr_note.body, &input_templates[0].2).unwrap();
        assert_eq!(records_data, records_data_brute_force);
        if input_templates[0].1.len() == 1 {
            assert_eq!(records_data[0].0, input_amount);
            assert_eq!(records_data[0].1, input_templates[0].3);
        }

        // test 2: alter the memo so that the verification fails
        let mut new_xfr_body = xfr_body.clone();

        let first_asset_tracer_memos = new_xfr_body.asset_tracing_memos[0].clone();

        if first_asset_tracer_memos[0].lock_asset_type.is_some() {
            let old_enc = new_xfr_body.asset_tracing_memos[0]
                .get(0)
                .unwrap()
                .lock_asset_type
                .as_ref()
                .unwrap()
                .clone();

            let new_enc = old_enc.e2.add(&pc_gens.B); //adding 1 to the exponent

            let tracer_memo = TracerMemo {
                lock_asset_type: Some(ElGamalCiphertext {
                    e1: old_enc.e1,
                    e2: new_enc,
                }),
                lock_amount: xfr_body.clone().asset_tracing_memos[0]
                    .get(0)
                    .unwrap()
                    .lock_amount
                    .clone(),
                enc_key: xfr_body.clone().asset_tracing_memos[0]
                    .get(0)
                    .unwrap()
                    .enc_key
                    .clone(),
                lock_attributes: vec![],

                lock_info: xfr_body.clone().asset_tracing_memos[0]
                    .get(0)
                    .unwrap()
                    .lock_info
                    .clone(),
            };
            new_xfr_body.asset_tracing_memos[0] = vec![tracer_memo];

            let policies = XfrNotePoliciesRef::new(
                input_policies.clone(),
                input_sig_commitment.clone(),
                output_policies.clone(),
                output_sig_commitment.clone(),
            );

            msg_eq!(
                XfrVerifyAssetTracingAssetAmountError,
                verify_xfr_body(&mut prng, params, &new_xfr_body, &policies)
                    .unwrap_err(),
                "Asset tracing verification fails as the ciphertext has been altered."
            );
        }

        // Restore body
        let mut new_xfr_body: XfrBody = xfr_body.clone();
        pnk!(verify_xfr_body(&mut prng, params, &new_xfr_body, &policies));

        // test 3: without proof
        new_xfr_body
            .proofs
            .asset_tracing_proof
            .asset_type_and_amount_proofs = vec![];

        let check = verify_xfr_body(&mut prng, params, &new_xfr_body, &policies);

        msg_eq!(
            XfrVerifyAssetTracingAssetAmountError,
            check.unwrap_err(),
            "Transfer should fail without proof."
        );

        // test 4: with wrong proof

        // Restore body
        let mut new_xfr_body: XfrBody = xfr_body.clone();
        pnk!(verify_xfr_body(&mut prng, params, &new_xfr_body, &policies));

        // Assign the first proof to the second proof
        let wrong_proof = create_wrong_proof();

        new_xfr_body
            .proofs
            .asset_tracing_proof
            .asset_type_and_amount_proofs[0] = wrong_proof;

        let check = verify_xfr_body(&mut prng, params, &new_xfr_body, &policies);

        msg_eq!(
            XfrVerifyAssetTracingAssetAmountError,
            check.unwrap_err(),
            "Transfer should fail as the proof is not correctly computed."
        );
    }

    #[test]
    fn asset_tracing_for_non_conf_assets_should_work() {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_type = AssetType::from_identical_byte(0u8);

        let asset_tracer_public_keys = AssetTracerKeyPair::generate(&mut prng);

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_public_keys.enc_key,
            asset_tracing: true,
            identity_tracing: None,
        });

        let input_keypair = XfrKeyPair::generate(&mut prng);
        let asset_record_type =
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType;
        let input_asset_record = AssetRecordTemplate::with_asset_tracing(
            10,
            asset_type,
            asset_record_type,
            input_keypair.pub_key,
            tracing_policy.clone(),
        );

        let input = AssetRecord::from_template_no_identity_tracing(
            &mut prng,
            &input_asset_record,
        )
        .unwrap();

        let output_asset_record = AssetRecordTemplate::with_asset_tracing(
            10,
            asset_type,
            asset_record_type,
            input_keypair.pub_key,
            tracing_policy.clone(),
        );

        let outputs = [AssetRecord::from_template_no_identity_tracing(
            &mut prng,
            &output_asset_record,
        )
        .unwrap()];

        let xfr_note =
            gen_xfr_note(&mut prng, &[input], &outputs, &[&input_keypair]).unwrap();

        let policies = XfrNotePoliciesRef::new(
            vec![&tracing_policy],
            vec![None; 1],
            vec![&tracing_policy],
            vec![None; 1],
        );

        pnk!(verify_xfr_note(
            &mut prng,
            &mut params,
            &xfr_note,
            &policies
        ));
    }

    #[test]
    fn test_one_input_one_output_all_confidential() {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_tracer_keypair = AssetTracerKeyPair::generate(&mut prng);
        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_keypair.enc_key.clone(),
            asset_tracing: true,
            identity_tracing: None,
        });

        let input_templates = [(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            &tracing_policy,
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];
        let output_templates = [(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            &TracingPolicies::new(), // no policy
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];

        do_test_asset_tracing(&mut params, &input_templates, &output_templates);

        // Both input and output with asset tracing
        let input_templates = [(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            &tracing_policy,
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];

        let output_templates = vec![(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            &tracing_policy,
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];

        do_test_asset_tracing(
            &mut params,
            &input_templates,
            output_templates.as_slice(),
        );
    }

    #[test]
    fn test_one_input_one_output_amount_confidential() {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_tracer_keypair = AssetTracerKeyPair::generate(&mut prng);

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_keypair.enc_key.clone(),
            asset_tracing: true,
            identity_tracing: None,
        });

        // Input with asset tracing, output without asset tracing
        let input_templates = [(
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            &tracing_policy,
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];

        let output_templates = [(
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            &TracingPolicies::new(), // no policy
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];

        do_test_asset_tracing(&mut params, &input_templates, &output_templates);
    }

    #[test]
    fn test_one_input_one_output_asset_confidential() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let mut params = PublicParams::default();
        let asset_tracer_keypair = AssetTracerKeyPair::generate(&mut prng);

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_keypair.enc_key.clone(),
            asset_tracing: true,
            identity_tracing: None,
        });

        // Input with asset tracing, output without asset tracing
        let input_templates = vec![(
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            &tracing_policy,
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];

        let no_policy = TracingPolicies::new();
        let output_templates = vec![(
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            &no_policy, // no policy
            &asset_tracer_keypair,
            BITCOIN_ASSET,
        )];

        do_test_asset_tracing(
            &mut params,
            input_templates.as_slice(),
            output_templates.as_slice(),
        );
    }

    #[test]
    fn test_two_inputs_two_outputs_all_confidential_tracing_on_inputs() {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_tracer_keypair = AssetTracerKeyPair::generate(&mut prng);

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_keypair.enc_key.clone(),
            asset_tracing: true,
            identity_tracing: None,
        });
        // Input with asset tracing, output without asset tracing
        let input_templates = [
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];

        let output_templates = [
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &TracingPolicies::new(), // no policy
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &TracingPolicies::new(),
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];

        do_test_asset_tracing(&mut params, &input_templates, &output_templates);
    }

    #[test]
    fn test_two_inputs_two_outputs_all_confidential_tracing_on_inputs_and_outputs() {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_tracer_keypair = AssetTracerKeyPair::generate(&mut prng);

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_keypair.enc_key.clone(),
            asset_tracing: true,
            identity_tracing: None,
        });

        let input_templates = [
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];

        let output_templates = [
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];

        do_test_asset_tracing(&mut params, &input_templates, &output_templates);
    }

    #[test]
    fn test_single_asset_first_input_asset_tracing() {
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_tracer_keypair = AssetTracerKeyPair::generate(&mut prng);

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_keypair.enc_key.clone(),
            asset_tracing: true,
            identity_tracing: None,
        });

        // Only a single asset tracing policy for the first input
        let no_policies = TracingPolicies::new();
        let input_templates = [
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];
        let output_templates = [
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];
        do_test_asset_tracing(&mut params, &input_templates, &output_templates);
    }

    #[test]
    fn test_single_asset_two_first_input_asset_tracing() {
        // The first two inputs have asset tracing policies
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_tracer_keypair = AssetTracerKeyPair::generate(&mut prng);

        let tracing_policy = TracingPolicies::from_policy(TracingPolicy {
            enc_keys: asset_tracer_keypair.enc_key.clone(),
            asset_tracing: true,
            identity_tracing: None,
        });
        let no_policies = TracingPolicies::new();

        let input_templates = vec![
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &tracing_policy,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];
        let output_templates = [
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
            (
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &no_policies,
                &asset_tracer_keypair,
                BITCOIN_ASSET,
            ),
        ];
        do_test_asset_tracing(&mut params, &input_templates, &output_templates);
    }

    fn gen_asset_tracing_policy(public_keys: &AssetTracerEncKeys) -> TracingPolicy {
        TracingPolicy {
            enc_keys: public_keys.clone(),
            asset_tracing: true,
            identity_tracing: None,
        }
    }

    #[test]
    fn test_complex_transaction() {
        // Multiple asset types
        // Multiple asset tracers
        // Mix of asset_tracing policies for inputs / outputs
        // Mix of asset record type for inputs /outputs
        let mut prng: ChaChaRng;
        let mut params = PublicParams::default();
        prng = ChaChaRng::from_seed([0u8; 32]);

        let tracer1_keypair = AssetTracerKeyPair::generate(&mut prng);
        let tracer2_keypair = AssetTracerKeyPair::generate(&mut prng);

        let input1_tracing_policy = TracingPolicies::from_policy(
            gen_asset_tracing_policy(&tracer1_keypair.enc_key),
        );

        let input2_tracing_policy = TracingPolicies::from_policy(
            gen_asset_tracing_policy(&tracer1_keypair.enc_key),
        );

        let input3_tracing_policy = TracingPolicies::from_policy(
            gen_asset_tracing_policy(&tracer2_keypair.enc_key),
        );

        let output1_tracing_policy = TracingPolicies::from_policy(
            gen_asset_tracing_policy(&tracer2_keypair.enc_key),
        );

        let output2_tracing_policy = TracingPolicies::from_policy(
            gen_asset_tracing_policy(&tracer2_keypair.enc_key),
        );

        let output3_tracing_policy = TracingPolicies::from_policy(
            gen_asset_tracing_policy(&tracer1_keypair.enc_key),
        );

        let input_templates = [
            (
                10u64,
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &input1_tracing_policy,
                &tracer1_keypair,
                BITCOIN_ASSET,
            ),
            (
                10u64,
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &input2_tracing_policy,
                &tracer1_keypair,
                BITCOIN_ASSET,
            ),
            (
                20u64,
                AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
                &input3_tracing_policy,
                &tracer2_keypair,
                GOLD_ASSET,
            ),
            (
                10u64,
                AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
                &TracingPolicies::new(), // no policy
                &tracer1_keypair,
                BITCOIN_ASSET,
            ),
        ];

        let output_templates = [
            (
                10u64,
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &output1_tracing_policy,
                &tracer2_keypair,
                GOLD_ASSET,
            ),
            (
                10u64,
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                &output2_tracing_policy,
                &tracer2_keypair,
                GOLD_ASSET,
            ),
            (
                20u64,
                AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
                &output3_tracing_policy,
                &tracer1_keypair,
                BITCOIN_ASSET,
            ),
            (
                5u64,
                AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
                &TracingPolicies::new(), // no policy
                &tracer1_keypair,
                BITCOIN_ASSET,
            ),
            (
                5u64,
                AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
                &TracingPolicies::new(), // no policy
                &tracer1_keypair,
                BITCOIN_ASSET,
            ),
        ];

        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);

        let in_keys = gen_key_pair_vec(input_templates.len(), &mut prng);
        let in_keys_ref = in_keys.iter().collect_vec();
        let inputs = input_templates
            .iter()
            .zip(in_keys.iter())
            .map(
                |(
                    (amount, asset_record_type, tracing_policies, _, asset_type),
                    key_pair,
                )| {
                    AssetRecordTemplate::with_asset_tracing(
                        *amount,
                        *asset_type,
                        *asset_record_type,
                        key_pair.pub_key,
                        (*tracing_policies).clone(),
                    )
                },
            )
            .collect_vec();

        let out_keys = gen_key_pair_vec(output_templates.len(), &mut prng);
        let outputs = output_templates
            .iter()
            .zip(out_keys.iter())
            .map(
                |(
                    (amount, asset_record_type, tracing_policies, _, asset_type),
                    key_pair,
                )| {
                    AssetRecordTemplate::with_asset_tracing(
                        *amount,
                        *asset_type,
                        *asset_record_type,
                        key_pair.pub_key,
                        (*tracing_policies).clone(),
                    )
                },
            )
            .collect_vec();

        let (xfr_note, inputs, outputs) = create_xfr(
            &mut prng,
            inputs.as_slice(),
            outputs.as_slice(),
            in_keys_ref.as_slice(),
        );

        // test serialization
        let string = serde_json::to_string(&xfr_note).unwrap();
        let xfr_note2 = serde_json::from_str(&string).unwrap();
        assert_eq!(xfr_note, xfr_note2);

        let xfr_body = &xfr_note.body;

        let input_policies = input_templates
            .iter()
            .map(|(_, _, tracing_policy, _, _)| *tracing_policy)
            .collect_vec();
        let output_policies = output_templates
            .iter()
            .map(|(_, _, tracing_policy, _, _)| *tracing_policy)
            .collect_vec();

        let input_sig_commitment = vec![None; inputs.len()];
        let output_sig_commitment = vec![None; outputs.len()];

        let policies = XfrNotePoliciesRef::new(
            input_policies,
            input_sig_commitment,
            output_policies,
            output_sig_commitment,
        );
        // test 1: the verification is successful
        pnk!(verify_xfr_body(
            &mut prng,
            &mut params,
            &xfr_body.clone(),
            &policies
        ));
        let candidate_assets = [BITCOIN_ASSET, GOLD_ASSET];
        let records_data_brute_force = trace_assets_brute_force(
            &xfr_note.body,
            &tracer1_keypair,
            &candidate_assets,
        )
        .unwrap();
        let records_data = trace_assets(&xfr_note.body, &tracer1_keypair).unwrap();
        assert_eq!(records_data, records_data_brute_force);
        let ids: Vec<u32> = vec![];
        assert_eq!(records_data.len(), 3);
        assert_eq!(records_data[0].0, 10); // first input amount
        assert_eq!(records_data[0].1, BITCOIN_ASSET); // first input asset type
        assert_eq!(records_data[0].2, ids); // first input no id tracing
        assert_eq!(records_data[0].3, in_keys[0].pub_key); // first input no id tracing
        assert_eq!(records_data[1].0, 10); // second input amount
        assert_eq!(records_data[1].1, BITCOIN_ASSET); // second input asset_type
        assert_eq!(records_data[1].2, ids); // second input no ide tracing
        assert_eq!(records_data[1].3, in_keys[1].pub_key); // second input no id tracing
        assert_eq!(records_data[2].0, 20); // third output amount
        assert_eq!(records_data[2].1, BITCOIN_ASSET); // third output asset type
        assert_eq!(records_data[2].2, ids); // third output no id tracing
        assert_eq!(records_data[2].3, out_keys[2].pub_key); // third output no id tracing

        let records_data_brute_force = trace_assets_brute_force(
            &xfr_note.body,
            &tracer2_keypair,
            &candidate_assets,
        )
        .unwrap();
        let records_data = trace_assets(&xfr_note.body, &tracer2_keypair).unwrap();
        assert_eq!(records_data, records_data_brute_force);
        let ids: Vec<u32> = vec![];
        assert_eq!(records_data.len(), 3);
        assert_eq!(records_data[0].0, 20); // third input amount
        assert_eq!(records_data[0].1, GOLD_ASSET); // third input asset type
        assert_eq!(records_data[0].2, ids); // third input no id tracing
        assert_eq!(records_data[0].3, in_keys[2].pub_key); // third input no id tracing
        assert_eq!(records_data[1].0, 10); // second input amount
        assert_eq!(records_data[1].1, GOLD_ASSET); // second input asset_type
        assert_eq!(records_data[1].2, ids); // second input no ide tracing
        assert_eq!(records_data[1].3, out_keys[0].pub_key); // second input no id tracing
        assert_eq!(records_data[2].0, 10); // third output amount
        assert_eq!(records_data[2].1, GOLD_ASSET); // third output asset type
        assert_eq!(records_data[2].2, ids); // third output no id tracing
        assert_eq!(records_data[2].3, out_keys[1].pub_key); // third output no id tracing
    }

    fn do_integer_overflow(asset_record_type: AssetRecordType) {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let mut params = PublicParams::default();

        let asset_type = AssetType::from_identical_byte(0u8);

        let inkeys = gen_key_pair_vec(1, &mut prng);
        let inkeys_ref = inkeys.iter().collect_vec();

        let outkeys = gen_key_pair_vec(2, &mut prng);

        let input_amount = 10u64;
        let output_amount_1 = 5_u64;
        let output_amount_2 = 5_u64;

        let inputs = vec![AssetRecordTemplate::with_no_asset_tracing(
            input_amount,
            asset_type,
            asset_record_type,
            inkeys[0].pub_key,
        )];

        let outputs = vec![
            AssetRecordTemplate::with_no_asset_tracing(
                output_amount_1,
                asset_type,
                asset_record_type,
                outkeys[0].pub_key,
            ),
            AssetRecordTemplate::with_no_asset_tracing(
                output_amount_2,
                asset_type,
                asset_record_type,
                outkeys[1].pub_key,
            ),
        ];

        let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
        let policies_ref = policies.to_ref();
        let (xfr_note, _, _) = create_xfr(
            &mut prng,
            inputs.as_slice(),
            outputs.as_slice(),
            &inkeys_ref,
        );

        pnk!(verify_xfr_note(
            &mut prng,
            &mut params,
            &xfr_note,
            &policies_ref
        ));

        // Modify the input so that we trigger an integer overflow
        let mut xfr_body_new = xfr_note.body;

        xfr_body_new.inputs[0].amount = NonConfidential(0_u64);
        xfr_body_new.outputs[0].amount = NonConfidential(1_u64);
        xfr_body_new.outputs[1].amount = NonConfidential(u64::max_value());

        msg_eq!(
            ZeiError::XfrVerifyAssetAmountError,
            verify_xfr_body(&mut prng, &mut params, &xfr_body_new, &policies_ref)
                .unwrap_err(),
            "An integer overflow error must be raised"
        );
    }

    #[test]
    fn test_integer_overflow() {
        do_integer_overflow(
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
        );
        do_integer_overflow(
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
    }

    #[test]
    fn test_asset_type_handling() {
        let at1 = AssetType([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1,
        ]);
        let at2 = AssetType([
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1,
        ]);
        let at3 = AssetType([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 0,
        ]);
        let at1_rist_scalar = at1.as_scalar::<RistrettoScalar>();
        let at2_rist_scalar = at2.as_scalar::<RistrettoScalar>();
        let at3_rist_scalar = at3.as_scalar::<RistrettoScalar>();
        assert_ne!(at1_rist_scalar, at2_rist_scalar);
        assert_ne!(at1_rist_scalar, at3_rist_scalar);
        assert_ne!(at2_rist_scalar, at3_rist_scalar);

        let at1_bls_scalar = at1.as_scalar::<BLSScalar>();
        let at1_jubjub_scalar = at1.as_scalar::<JubjubScalar>();
        let v1 = at1_rist_scalar.to_bytes();
        let v2 = at1_bls_scalar.to_bytes();
        let v3 = at1_jubjub_scalar.to_bytes();
        assert_eq!(v1, v2);
        assert_eq!(v1, v3);
        assert_eq!(v2, v3);
    }
}
