use crate::xfr::{
    asset_record::open_blind_asset_record,
    sig::XfrKeyPair,
    structs::{AssetType, BlindAssetRecord, OpenAssetRecord, OwnerMemo},
};
use algebra::groups::{GroupArithmetic, Scalar as _, ScalarArithmetic};
use algebra::ristretto::RistrettoScalar as Scalar;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::BulletproofGens;
use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
use crypto::bp_circuits::cloak::{CloakCommitment, CloakValue};
use crypto::solvency;
use ruc::*;
use std::collections::HashSet;
use std::fmt;
use utils::errors::ZeiError;

/// record for solvency proof, indicates asset or liability
pub enum SolvencyRecordType {
    Asset,
    Liability,
}

/// Stages of an audit, modeling Audit preparation as a state machine
/// There are 3 personas: Auditor, Prover(i.e. Asset Owner), Verifier.
/// Sometimes, the verifier can be auditor him/herself, or it can be general public(anyone).
///
/// - `RecordCollection`: auditors and provers provide assets and liabilities records as `BlindAssetReord`, usually
/// liabilities are added by the auditor, assets are added by the prover. But in some scenarios, provers can add a list
/// of liabilities which will be verified through challenges by the users for their inclusion.
///
/// - `LiabilitiesVerification`: when records are all added and finalized, an optional stage of verification of liabilities
/// will begin. If the liability records are added by a trusted auditor, then they will be considered as verified, thus
/// no longer require this step. But for prover's self-assembled list, Prover will commit to the liability list and publish
/// the merkle root of such list on the ledger for everyone's challenge. When challenged about a certain record, the prover
/// will have to provide a MerkleInclusionProof. This feature and API is still work in progress.
///
/// - `LiabilitiesVerified`: when all liabilities are verified, we enter this stage and wait for the auditor to provide
/// a list of conversion rate for all the asset types. Please be noted that since there are many assets records whose asset type
/// are blinded, thus the auditor might not be able to provide the "exact" list of conversion rates.
/// Our current approach is let auditor provide an overarching, all-encompassing list of rates whose length could be much
/// larger than the record lists.
/// Alternative options would be the auditor publishing a conversion rate of all possible asset types, and the prover will
/// input the conversion rates for this particular solvency proof by attaching a subset proof. (~ set membership). However,
/// this approach will incur longer proof size and more computation.
///
/// - `ReadyForProof`: when all records are finalized and verified, conversion rates are finalized, we enter the stage
/// where we are ready to prove solvency. At this stage, prover and verifier can derive their own objects of type
/// `SolvencyProver` and `SolvencyVerifier` that contains all necessary values they need to prove and verify.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum SolvencyAuditStage {
    RecordCollection,
    LiabilitiesVerification, // optional
    LiabilitiesVerified,
    ReadyForProof,
}

impl Default for SolvencyAuditStage {
    fn default() -> SolvencyAuditStage {
        SolvencyAuditStage::RecordCollection
    }
}

impl fmt::Display for SolvencyAuditStage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            SolvencyAuditStage::RecordCollection => "Record Collection",
            SolvencyAuditStage::LiabilitiesVerification => {
                "Liability Records Verification"
            }
            SolvencyAuditStage::LiabilitiesVerified => "Liabilitiy Records Verified",
            SolvencyAuditStage::ReadyForProof => "Ready for Proof",
        })
    }
}

/// Represent a solvency audit, owned by an Auditor
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SolvencyAudit {
    assets: Vec<BlindAssetRecord>,
    liabilities: Vec<BlindAssetRecord>,
    conv_rates: Vec<(Scalar, Scalar)>,
    asset_types: HashSet<AssetType>,
    stage: SolvencyAuditStage,
}

impl SolvencyAudit {
    /// invokable by Auditor and/or Prover
    /// usually liability records are added by the auditor (can only be added by the prover)
    /// usually asset records are added by the prover (i.e. the asset owner)
    pub fn add_record(
        &mut self,
        record_type: SolvencyRecordType,
        record: &BlindAssetRecord,
    ) -> Result<()> {
        if not_matches!(self.stage, SolvencyAuditStage::RecordCollection) {
            return Err(eg!(ZeiError::SolvencyInputError));
        }
        match record_type {
            SolvencyRecordType::Asset => self.assets.push(record.clone()),
            SolvencyRecordType::Liability => self.liabilities.push(record.clone()),
        }
        // if non-confidential asset_type, then add to the list for minimum conversion rate check
        if !record.asset_type.is_confidential() {
            self.asset_types
                .insert(record.asset_type.get_asset_type().unwrap());
        }
        Ok(())
    }

    // TODO: (alex) API to finalize all records and returns Pedersen commitments of liability set
    // the Merkle Root of this liability set will be published on ledger for challenges from users
    //
    /// finalize input collection and move on to input verification stage
    // pub fn finalize_records(&mut self) -> MerkleRoot {
    //   if not_matches!(self.stage, SolvencyAuditStage::RecordCollection) {
    //     return Err(ZeiError::SolvencyInputError);
    //   }
    //   self.stage = SolvencyAuditStage::LiabilitiesVerification;
    // }

    // TODO: (alex) API for users to challenge the inclusion of a liability records
    //
    // pub fn liability_inclusion_challenge(&self,
    //                                      asset_type: &AssetType,
    //                                      amount: u64)
    //                                      -> MerkleInclusionProof {
    // }

    /// Finalize all assets and liabilities as all of them are verified.
    /// For scenarios where liability records are added by a trusted auditor, liability verification stage
    /// is unnecessary, thus can be skipped and directly proceed to `LiabilitiesVerified` stage.
    pub fn finalize_verified_records(&mut self) -> Result<()> {
        if not_matches!(self.stage, SolvencyAuditStage::RecordCollection) {
            return Err(eg!(ZeiError::SolvencyInputError));
        }
        self.stage = SolvencyAuditStage::LiabilitiesVerified;
        Ok(())
    }

    /// Finalize a list of conversion rates of each asset_type, provided by Auditor.
    /// Noted that the list can be much longer than the `self.asset_types` list, because many of records may
    /// have confidential asset type, thus an auditor may provide an overarching list of rates
    pub fn finalize_rates(&mut self, rates: &[(AssetType, u64)]) -> Result<()> {
        if not_matches!(self.stage, SolvencyAuditStage::LiabilitiesVerified)
            || rates.len() < self.asset_types.len()
        {
            return Err(eg!(ZeiError::SolvencyInputError));
        }

        // make sure at least all non-confidential asset types are provided with a rate
        for asset_type in self.asset_types.iter() {
            if rates.binary_search_by_key(&asset_type, |(a, _)| a).is_err() {
                return Err(eg!(ZeiError::SolvencyInputError));
            }
        }

        for (asset_type, rate) in rates.iter() {
            self.conv_rates
                .push((asset_type.as_scalar(), Scalar::from_u64(*rate)));
        }

        // with records and rates finalized, we are ready to build Prover and Verifier for proof
        self.stage = SolvencyAuditStage::ReadyForProof;
        Ok(())
    }

    /// invoked by Prover once all BAR records and rates are finalized
    pub fn build_prover(
        &self,
        owner_memos_for_assets: &[&Option<OwnerMemo>],
        keypairs_for_assets: &[&XfrKeyPair],
        owner_memos_for_liabilities: &[&Option<OwnerMemo>],
        keypairs_for_liabilities: &[&XfrKeyPair],
    ) -> Result<SolvencyProver> {
        if owner_memos_for_assets.len() != self.assets.len()
            || keypairs_for_assets.len() != self.assets.len()
            || owner_memos_for_liabilities.len() != self.liabilities.len()
            || keypairs_for_liabilities.len() != self.liabilities.len()
        {
            return Err(eg!(ZeiError::SolvencyInputError));
        }

        let mut prover: SolvencyProver = Default::default();

        // 1. open all BlindAssetRecord into OpenAssetRecord(OAR)
        let mut asset_oars = vec![];
        let mut liability_oars = vec![];
        for (i, rec) in self.assets.iter().enumerate() {
            asset_oars.push(
                open_blind_asset_record(
                    &rec,
                    owner_memos_for_assets[i],
                    keypairs_for_assets[i],
                )
                .c(d!())?,
            );
        }
        for (i, rec) in self.liabilities.iter().enumerate() {
            liability_oars.push(
                open_blind_asset_record(
                    &rec,
                    owner_memos_for_liabilities[i],
                    keypairs_for_liabilities[i],
                )
                .c(d!())?,
            );
        }

        // 2. build SolvencyProver from OAR
        for record in asset_oars.iter() {
            if record.blind_asset_record.is_public() {
                prover
                    .public_assets
                    .push(SolvencyAudit::get_record_entry_from_oar(&record));
            } else {
                prover
                    .hidden_assets
                    .push(SolvencyAudit::get_record_entry_from_oar(&record));
                prover
                    .hidden_assets_blinds
                    .push(SolvencyAudit::get_hidden_record_blinds(&record));
            }
        }

        for record in liability_oars.iter() {
            if record.blind_asset_record.is_public() {
                prover
                    .public_liabilities
                    .push(SolvencyAudit::get_record_entry_from_oar(&record));
            } else {
                prover
                    .hidden_liabilities
                    .push(SolvencyAudit::get_record_entry_from_oar(&record));
                prover
                    .hidden_liabilities_blinds
                    .push(SolvencyAudit::get_hidden_record_blinds(&record));
            }
        }

        prover.conv_rates = self.conv_rates.clone();
        Ok(prover)
    }

    /// invoked by Verifier once all records and rates are finalized
    pub fn build_verifier(&self) -> SolvencyVerifier {
        let mut verifier: SolvencyVerifier = Default::default();
        for record in self.assets.iter() {
            if record.is_public() {
                verifier
                    .public_assets
                    .push(SolvencyAudit::get_record_entry_from_bar(&record));
            } else {
                verifier
                    .hidden_assets_commitments
                    .push(SolvencyAudit::get_hidden_record_commitments(&record));
            }
        }

        for record in self.liabilities.iter() {
            if record.is_public() {
                verifier
                    .public_liabilities
                    .push(SolvencyAudit::get_record_entry_from_bar(&record));
            } else {
                verifier
                    .hidden_liabilities_commitments
                    .push(SolvencyAudit::get_hidden_record_commitments(&record));
            }
        }

        verifier.conv_rates = self.conv_rates.clone();
        verifier
    }
}

// internal helper functions
impl SolvencyAudit {
    fn get_record_entry_from_oar(record: &OpenAssetRecord) -> CloakValue {
        CloakValue::new(
            Scalar::from_u64(record.amount),
            record.asset_type.as_scalar(),
        )
    }

    fn get_record_entry_from_bar(record: &BlindAssetRecord) -> CloakValue {
        assert!(record.is_public());
        CloakValue::new(
            Scalar::from_u64(record.amount.get_amount().unwrap()),
            record.asset_type.get_asset_type().unwrap().as_scalar(),
        )
    }

    fn get_hidden_record_blinds(record: &OpenAssetRecord) -> CloakValue {
        let (amount_blind_lo, amount_blind_hi) = record.amount_blinds;
        let amount_blind =
            amount_blind_lo.add(&amount_blind_hi.mul(&Scalar::from_u64(1u64 << 32)));
        CloakValue::new(amount_blind, record.type_blind)
    }

    fn get_hidden_record_commitments(record: &BlindAssetRecord) -> CloakCommitment {
        let pc_gens = RistrettoPedersenGens::default();
        let amount_com = if record.amount.is_confidential() {
            let (amount_com_lo, amount_com_hi) =
                record.amount.get_commitments().unwrap();
            (amount_com_lo.decompress().unwrap().add(
                &amount_com_hi
                    .decompress()
                    .unwrap()
                    .mul(&Scalar::from_u64(1u64 << 32)),
            ))
            .compress()
        } else {
            pc_gens
                .commit(
                    Scalar::from_u64(record.amount.get_amount().unwrap()),
                    Scalar::from_u32(0),
                )
                .compress()
        };

        let type_com = if record.asset_type.is_confidential() {
            record.asset_type.get_commitment().unwrap()
        } else {
            pc_gens
                .commit(
                    record.asset_type.get_asset_type().unwrap().as_scalar(),
                    Scalar::from_u32(0),
                )
                .compress()
        };

        CloakCommitment {
            amount: amount_com,
            asset_type: type_com,
        }
    }
}

/// Represents a prover object in a solvency proof
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SolvencyProver {
    public_assets: Vec<CloakValue>,
    public_liabilities: Vec<CloakValue>,
    hidden_assets: Vec<CloakValue>,
    hidden_assets_blinds: Vec<CloakValue>,
    hidden_liabilities: Vec<CloakValue>,
    hidden_liabilities_blinds: Vec<CloakValue>,
    pub conv_rates: Vec<(Scalar, Scalar)>,
}

impl SolvencyProver {
    /// generate solvency proof
    pub fn prove(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &RistrettoPedersenGens,
    ) -> Result<Vec<u8>> {
        if self.conv_rates.is_empty() {
            return Err(eg!(ZeiError::SolvencyProveError));
        }

        let proof = solvency::prove_solvency(
            &bp_gens,
            &pc_gens,
            &self.hidden_assets,
            &self.hidden_assets_blinds,
            &self.public_assets,
            &self.hidden_liabilities,
            &self.hidden_liabilities_blinds,
            &self.public_liabilities,
            &self.conv_rates,
        )
        .c(d!())?;
        Ok(proof.to_bytes())
    }
}

/// Represents a verifier object in a solvency proof
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SolvencyVerifier {
    public_assets: Vec<CloakValue>,
    public_liabilities: Vec<CloakValue>,
    hidden_assets_commitments: Vec<CloakCommitment>,
    hidden_liabilities_commitments: Vec<CloakCommitment>,
    pub conv_rates: Vec<(Scalar, Scalar)>,
}
impl SolvencyVerifier {
    /// verify a solvency proof
    pub fn verify(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &RistrettoPedersenGens,
        proof: &[u8],
    ) -> Result<()> {
        if self.conv_rates.is_empty() {
            return Err(eg!(ZeiError::SolvencyVerificationError));
        }

        solvency::verify_solvency(
            &bp_gens,
            &pc_gens,
            &self.hidden_assets_commitments,
            &self.public_assets,
            &self.hidden_liabilities_commitments,
            &self.public_liabilities,
            &self.conv_rates,
            &R1CSProof::from_bytes(proof).unwrap(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::{
        api::solvency::{
            SolvencyAudit, SolvencyProver, SolvencyRecordType, SolvencyVerifier,
        },
        xfr::{
            asset_record::{build_blind_asset_record, AssetRecordType},
            sig::{XfrKeyPair, XfrPublicKey},
            structs::{AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo},
        },
    };
    use bulletproofs::BulletproofGens;
    use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
    use rand_chacha::ChaChaRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    // helper function
    fn build_bar<R: CryptoRng + RngCore>(
        pubkey: &XfrPublicKey,
        prng: &mut R,
        pc_gens: &RistrettoPedersenGens,
        amt: u64,
        asset_type: AssetType,
        ar_type: AssetRecordType,
    ) -> (BlindAssetRecord, Option<OwnerMemo>) {
        let ar = AssetRecordTemplate::with_no_asset_tracing(
            amt, asset_type, ar_type, *pubkey,
        );
        let (bar, _, memo) = build_blind_asset_record(prng, &pc_gens, &ar, vec![]);
        (bar, memo)
    }

    fn build_bars<R: CryptoRng + RngCore>(
        pubkey: &[&XfrPublicKey],
        prng: &mut R,
        pc_gens: &RistrettoPedersenGens,
    ) -> Vec<(BlindAssetRecord, Option<OwnerMemo>)> {
        vec![
            build_bar(
                pubkey[0],
                prng,
                &pc_gens,
                10,
                AssetType::from_identical_byte(1),
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            ),
            build_bar(
                pubkey[1],
                prng,
                &pc_gens,
                20,
                AssetType::from_identical_byte(1),
                AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            ),
            build_bar(
                pubkey[2],
                prng,
                &pc_gens,
                30,
                AssetType::from_identical_byte(2),
                AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            ),
            build_bar(
                pubkey[3],
                prng,
                &pc_gens,
                40,
                AssetType::from_identical_byte(3),
                AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            ),
            build_bar(
                pubkey[4],
                prng,
                &pc_gens,
                50,
                AssetType::from_identical_byte(4),
                AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            ),
        ]
    }

    fn build_rates() -> Vec<(AssetType, u64)> {
        vec![
            (AssetType::from_identical_byte(1), 5),
            (AssetType::from_identical_byte(2), 4),
            (AssetType::from_identical_byte(3), 3),
            (AssetType::from_identical_byte(4), 2),
            (AssetType::from_identical_byte(5), 9),
            (AssetType::from_identical_byte(6), 1098),
            (AssetType::from_identical_byte(7), 3432),
        ]
    }

    // The following function tests the correctness property of the solvency proof
    #[test]
    fn test_solvency_correctness() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let mut key_pairs = vec![];
        for _ in 0..5 {
            key_pairs.push(XfrKeyPair::generate(&mut prng));
        }
        let pubkeys: Vec<_> = key_pairs.iter().map(|x| &x.pub_key).collect();

        let bp_gens = BulletproofGens::new(512, 1);
        let pc_gens = RistrettoPedersenGens::default();

        let bars = build_bars(&pubkeys, &mut prng, &pc_gens);
        let rates = build_rates();

        // Step 1. Auditor creates a `SolvencyAudit` object, signifying the start of a solvency process
        let mut audit: SolvencyAudit = Default::default();

        // Step 2. Auditor inputs all liabilities
        assert!(audit
            .add_record(SolvencyRecordType::Liability, &bars[0].0)
            .is_ok()); // 10 * 5 = 50
        assert!(audit
            .add_record(SolvencyRecordType::Liability, &bars[2].0)
            .is_ok()); // 30 * 4 = 120

        // Step 3. Prover(asset owner) inputs all assets
        assert!(audit
            .add_record(SolvencyRecordType::Asset, &bars[1].0)
            .is_ok()); // 20 * 5 = 100
        assert!(audit
            .add_record(SolvencyRecordType::Asset, &bars[4].0)
            .is_ok()); // 50 * 2 = 100

        // Step 4a. Finalize assets, assuming all liabilities are verified by the auditor
        assert!(audit.finalize_verified_records().is_ok());
        // Step 4b. (Alternatively) go through liability verification stage

        // Step 5. Auditor input and finalize the conversion rates
        assert!(audit.finalize_rates(&rates).is_ok());

        // Step 6. Derive `SolvencyProver` and `SolvencyVerifier` separately
        let memo_for_assets = vec![&bars[1].1, &bars[4].1];
        let keypairs_for_assets = vec![&key_pairs[1], &key_pairs[4]];
        let memo_for_liabilities = vec![&bars[0].1, &bars[2].1];
        let keypairs_for_liabilities = vec![&key_pairs[0], &key_pairs[2]];
        let prover = audit
            .build_prover(
                &memo_for_assets,
                &keypairs_for_assets,
                &memo_for_liabilities,
                &keypairs_for_liabilities,
            )
            .unwrap();
        let verifier = audit.build_verifier();

        // Step 7. Generate proof and pass on to the verifier to verify
        let proof_result = prover.prove(&bp_gens, &pc_gens);
        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();

        assert!(verifier.verify(&bp_gens, &pc_gens, &proof).is_ok());
    }

    // The following function tests the soundness property of the solvency proof
    #[test]
    fn test_solvency_soundness() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let mut key_pairs = vec![];
        for _ in 0..5 {
            key_pairs.push(XfrKeyPair::generate(&mut prng));
        }
        let pubkeys: Vec<_> = key_pairs.iter().map(|x| &x.pub_key).collect();

        let bp_gens = BulletproofGens::new(512, 1);
        let pc_gens = RistrettoPedersenGens::default();

        let bars = build_bars(&pubkeys, &mut prng, &pc_gens);
        let rates = build_rates();

        let mut audit: SolvencyAudit = Default::default();
        assert!(audit
            .add_record(SolvencyRecordType::Liability, &bars[1].0)
            .is_ok()); // 20 * 5 = 100
        assert!(audit
            .add_record(SolvencyRecordType::Liability, &bars[3].0)
            .is_ok()); // 40 * 3 = 120
        assert!(audit
            .add_record(SolvencyRecordType::Asset, &bars[1].0)
            .is_ok()); // 20 * 5 = 100
        assert!(audit
            .add_record(SolvencyRecordType::Asset, &bars[4].0)
            .is_ok()); // 50 * 2 = 100
        assert!(audit.finalize_verified_records().is_ok());
        assert!(audit.finalize_rates(&rates).is_ok());

        let memo_for_assets = vec![&bars[1].1, &bars[4].1];
        let keypairs_for_assets = vec![&key_pairs[1], &key_pairs[4]];
        let memo_for_liabilities = vec![&bars[1].1, &bars[3].1];
        let keypairs_for_liabilities = vec![&key_pairs[1], &key_pairs[3]];
        let prover = audit
            .build_prover(
                &memo_for_assets,
                &keypairs_for_assets,
                &memo_for_liabilities,
                &keypairs_for_liabilities,
            )
            .unwrap();
        let verifier = audit.build_verifier();

        let proof_result = prover.prove(&bp_gens, &pc_gens);
        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();
        assert!(verifier.verify(&bp_gens, &pc_gens, &proof).is_err());
    }

    #[test]
    fn test_solvency_ser_de() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let mut key_pairs = vec![];
        for _ in 0..5 {
            key_pairs.push(XfrKeyPair::generate(&mut prng));
        }
        let pubkeys: Vec<_> = key_pairs.iter().map(|x| &x.pub_key).collect();
        let pc_gens = RistrettoPedersenGens::default();
        let bars = build_bars(&pubkeys, &mut prng, &pc_gens);
        let rates = build_rates();
        let mut audit: SolvencyAudit = Default::default();
        assert!(audit
            .add_record(SolvencyRecordType::Liability, &bars[0].0)
            .is_ok()); // 10 * 5 = 50
        assert!(audit
            .add_record(SolvencyRecordType::Liability, &bars[2].0)
            .is_ok()); // 30 * 4 = 120
        assert!(audit
            .add_record(SolvencyRecordType::Asset, &bars[1].0)
            .is_ok()); // 20 * 5 = 100
        assert!(audit
            .add_record(SolvencyRecordType::Asset, &bars[4].0)
            .is_ok()); // 50 * 2 = 100
        assert!(audit.finalize_verified_records().is_ok());
        assert!(audit.finalize_rates(&rates).is_ok());
        let memo_for_assets = vec![&bars[1].1, &bars[4].1];
        let keypairs_for_assets = vec![&key_pairs[1], &key_pairs[4]];
        let memo_for_liabilities = vec![&bars[0].1, &bars[2].1];
        let keypairs_for_liabilities = vec![&key_pairs[0], &key_pairs[2]];
        let prover = audit
            .build_prover(
                &memo_for_assets,
                &keypairs_for_assets,
                &memo_for_liabilities,
                &keypairs_for_liabilities,
            )
            .unwrap();
        let verifier = audit.build_verifier();

        // test serialization and deserialization
        let audit_se = serde_json::to_string(&audit).unwrap();
        let audit_de: SolvencyAudit = serde_json::from_str(&audit_se).unwrap();
        assert_eq!(audit, audit_de);

        let prover_se = serde_json::to_string(&prover).unwrap();
        let prover_de: SolvencyProver = serde_json::from_str(&prover_se).unwrap();
        assert_eq!(prover, prover_de);

        let verifier_se = serde_json::to_string(&verifier).unwrap();
        let verifier_de: SolvencyVerifier = serde_json::from_str(&verifier_se).unwrap();
        assert_eq!(verifier, verifier_de);
    }
}
