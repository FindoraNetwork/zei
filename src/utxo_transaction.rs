use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use crate::asset::Asset;
use rand::CryptoRng;
use rand::Rng;
use crate::setup::PublicParams;
use bulletproofs::{PedersenGens, RangeProof};
use blake2::{Blake2b,Digest};
use crate::errors::Error as ZeiError;
use crate::proofs::chaum_perdersen::{chaum_pedersen_prove_multiple_eq, ChaumPedersenCommitmentEqProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use crate::setup::BULLET_PROOF_RANGE;
use crate::proofs::chaum_perdersen::chaum_pedersen_verify_multiple_eq;
use crate::encryption::ZeiRistrettoCipher;
use schnorr::Signature;
use std::collections::HashSet;
use schnorr::PublicKey;
use schnorr::SecretKey;
use core::borrow::Borrow;
use crate::utils::u64_to_bigendian_u8array;
use crate::utils::u8_bigendian_slice_to_u64;


#[derive(Default)]
pub struct TxAddressParams{
    amount: u64, //input or output amount
    amount_commitment: Option<CompressedRistretto>, //input or output balance
    amount_blinding: Option<Scalar>, //none for output
    asset_type: String,
    asset_type_commitment: Option<CompressedRistretto>, //None if non confidential asset or account is new, or Utxo model
    asset_type_blinding: Option<Scalar>, //None if non confidential asset or account is new or Utxo model
    public_key: PublicKey,
    secret_key: Option<SecretKey>,
}

pub struct TxPublicAddressInfo{
    amount: Option<u64>, //None only if confidential
    amount_commitment: Option<CompressedRistretto>, //None if not confidential balance
    asset_type: Option<String>, //None only if confidential asset
    asset_type_commitment: Option<CompressedRistretto>,  //None if not confidential balance
    public_key: PublicKey, //source or destination
}

pub struct TxDestinationInfo{
    public_info: TxPublicAddressInfo,
    lock_box: Option<ZeiRistrettoCipher>,
}

pub struct TxProofs{
    range_proof: Option<RangeProof>,
    asset_proof: Option<(ChaumPedersenCommitmentEqProof, ChaumPedersenCommitmentEqProof)>,
}

pub struct TxBody{
    source_info: Vec<TxPublicAddressInfo>,
    destination_info: Vec<TxDestinationInfo>,
    proofs: TxProofs,
    confidential_amount:bool,
    confidential_asset: bool,
}

pub struct Tx{
    body: TxBody,
    signatures: Vec<Signature>,
}

impl Tx{
    pub fn new<R: CryptoRng + Rng>(
        prng: &mut R,
        input: &[TxAddressParams],
        output: &[TxAddressParams],
        confidential_amount: bool,
        confidential_asset: bool,
    ) -> Result<Tx, ZeiError> {

        let pc_gens = PedersenGens::default();

        //output values to be build
        let mut range_proof = None;
        let mut asset_proof = None;
        let mut source_info = Vec::new();
        let mut destination_info= Vec::new();

        //tmp values
        let mut src_amount_option = vec![];
        let mut dst_amount_option = vec![];
        let mut dst_amount_blind = vec![];
        let mut dst_asset_com: Vec<Option<CompressedRistretto>>;
        let mut dst_asset_blind: Vec<Option<Scalar>>;
        let mut out_amount_coms_option: Vec<Option<CompressedRistretto>>;

        //extract values from input struct
        let src_asset_type_com_option: Vec<Option<CompressedRistretto>> =
            input.iter().map(|x| x.asset_type_commitment).collect();
        let src_pks: Vec<PublicKey> =
            input.iter().map(|x| x.public_key).collect();

        //extract values from output struct
        let dst_asset_type_com_option: Vec<Option<CompressedRistretto>> =
            output.iter().map(|x| x.asset_type_commitment).collect();
        let dst_asset_type_blind_option: Vec<Option<Scalar>> =
            output.iter().map(|x| x.asset_type_blinding).collect();
        let destination_public_keys: Vec<PublicKey> =
            output.iter().map(|x| x.public_key ).collect();

        //do amount handling
        if confidential_amount {
            let (range_pf, out_coms, out_blinds)
                = Tx::do_confidential_amount_range_proof(prng, input, output)?;

            out_amount_coms_option = out_coms.into_iter().map(|x| Some(x)).collect();
            range_proof = Some(range_pf);
            dst_amount_blind = out_blinds;

            //in confidential amount transaction, amounts are hidden, use None value
            for _ in 0..input.len(){
               src_amount_option.push(None);
            }
            for _ in 0..output.len(){
               dst_amount_option.push(None);
            }
        }
        else{
            src_amount_option = input.iter().map(|x| Some(x.amount)).collect();
            dst_amount_option = output.iter().map(|x| Some(x.amount)).collect();
            out_amount_coms_option = (0..output.len()).map(|_| None).collect();
        }

        if confidential_asset{
            let src_asset_com: Vec<CompressedRistretto> = src_asset_type_com_option.iter().map(|x| x.unwrap()).collect();
            let src_asset_blind: Vec<Scalar> =
                input.iter().map(|x| x.asset_type_blinding.unwrap()).collect();


            let (proof_asset, out_asset_com, out_asset_blind) = Tx::build_asset_proof(
                prng,
                &pc_gens,
                &input[0].asset_type,
                src_asset_com.as_slice(),
                src_asset_blind.as_slice(),
                dst_asset_type_com_option,
                dst_asset_type_blind_option,
                &destination_public_keys,
            )?;

            asset_proof = Some(proof_asset);
            dst_asset_com = vec![];
            dst_asset_blind = vec![];
            for (x,y) in out_asset_com.iter().zip(out_asset_blind.iter()) {
                dst_asset_com.push(Some(*x));
                dst_asset_blind.push(Some(*y))
            }
        }
        else{
            dst_asset_com = dst_asset_type_com_option;
            dst_asset_blind = dst_asset_type_blind_option;
        }

        //compute input struct
        for i in 0..input.len(){
            source_info.push(
                TxPublicAddressInfo{
                    amount: src_amount_option[i],
                    amount_commitment: input[i].amount_commitment,
                    asset_type: match confidential_asset{ true => None, false => Some(input[i].asset_type.clone())},
                    asset_type_commitment: src_asset_type_com_option[i],
                    public_key: src_pks[i],
                    }
            );
        }

        //compute output struct
        for i in 0..output.len(){
            let lbox: Option<ZeiRistrettoCipher>;
            if confidential_amount || confidential_asset{
                let mut memo = vec![];
                if confidential_amount {
                    memo.extend_from_slice(&u64_to_bigendian_u8array(output[i].amount));
                    memo.extend_from_slice(dst_amount_blind[i].as_bytes());
                }
                if confidential_asset {
                    memo.extend_from_slice(dst_asset_blind[i].unwrap().as_bytes());
                }
                let ciphertext = ZeiRistrettoCipher::encrypt(
                    prng,
                    &destination_public_keys[i].get_curve_point()?.compress(),
                    memo.as_slice(),
                )?;
                lbox = Some(ciphertext);
            }
            else {
                lbox = None;
            }

            destination_info.push(
                TxDestinationInfo{
                    public_info: TxPublicAddressInfo{
                        amount: dst_amount_option[i],
                        amount_commitment: out_amount_coms_option[i],
                        asset_type: match confidential_asset {
                            true => None,
                            false => Some(output[i].asset_type.clone()),
                        },
                        asset_type_commitment: dst_asset_com[i],
                        public_key: destination_public_keys[i],
                    },
                    lock_box: lbox,
                }
            );
        }

        //compute signatures on transaction
        let mut signatures = vec![];
        let mut pk_set = HashSet::new();
        for i in 0..input.len(){
            let pk = src_pks[i].as_bytes();
            if pk_set.contains(pk) == false {
                pk_set.insert(pk);
                let sk = &input[i].secret_key;
                signatures.push(sk.as_ref().unwrap().sign::<blake2::Blake2b, R>(prng, &[0u8,0u8], &src_pks[i]));
            }
        }

        Ok(Tx::build_tx_struct(source_info, destination_info, range_proof, asset_proof, signatures))
    }

    fn do_confidential_amount_range_proof<R: CryptoRng + Rng>(prng: &mut R,
        input: &[TxAddressParams],
        output: &[TxAddressParams]
    ) -> Result<(RangeProof, Vec<CompressedRistretto>, Vec<Scalar>), ZeiError>
    {

        let in_amount_blinds: Vec<Scalar> =
            input.iter().map(|x| x.amount_blinding.unwrap()).collect();
        let in_amounts: Vec<u64> = input.iter().map(|x| x.amount ).collect();
        let out_amounts: Vec<u64> = output.iter().map(|x| x.amount ).collect();
        let destination_public_keys: Vec<PublicKey> =
            output.iter().map(|x| x.public_key ).collect();

        let (proof, tx_coms, tx_blinds) =
            Tx::build_range_proof(
                prng,
                in_amount_blinds.as_slice(),
                in_amounts.as_slice(),
                out_amounts.as_slice(),
                destination_public_keys.as_slice()
            )?;
        Ok((proof, tx_coms, tx_blinds))
    }

    fn build_range_proof<R: CryptoRng + Rng>(
        prng: &mut R,
        source_blindings: &[Scalar],
        source_amounts: &[u64],
        destination_amounts: &[u64],
        destination_public_keys: &[PublicKey],
    )-> Result<(RangeProof, Vec<CompressedRistretto>, Vec<Scalar>),ZeiError>
    {

        let num_output = destination_amounts.len();

        let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;
        let mut params = PublicParams::new(upper_power2);

        //build blindings for output commitments
        let mut blindings = Vec::new(); //for all outputs and sum(inputs) - sum(outputs)
        for i in 0..num_output {
            let blind = sample_blinding_factor(prng, &destination_public_keys[i])?;
            blindings.push(blind);
        }

        let blind_diff =
            source_blindings.iter().sum::<Scalar>() - blindings.iter().sum::<Scalar>();

        blindings.push(blind_diff);
        for _ in blindings.len()..upper_power2 {
            blindings.push(Scalar::from(0u8));
        }

        let source_amounts_addition = source_amounts.into_iter().sum::<u64>();
        let destination_amounts_addition = destination_amounts.into_iter().sum::<u64>();
        let tx_diff = if source_amounts_addition > destination_amounts_addition{
            source_amounts_addition - destination_amounts_addition
        }
        else{
            return Err(ZeiError::TxProofError);
        };

        let mut values = vec![];
        values.extend_from_slice(destination_amounts);
        values.push(tx_diff);
        for _ in values.len()..upper_power2 {
            values.push(0);
        }

        let (proof,commitments) = RangeProof::prove_multiple(
            &params.bp_gens,
            &params.pc_gens,
            &mut params.transcript,
            values.as_slice(),
            blindings.as_slice(),
            BULLET_PROOF_RANGE)?;

        Ok((proof, commitments, blindings))
    }

    fn build_asset_proof<R: CryptoRng + Rng>(
        prng: &mut R,
        pc_gens: &PedersenGens,
        asset_type: &str,
        source_asset_commitments: &[CompressedRistretto],
        source_asset_blindings: &[Scalar],
        destination_asset_commitments: Vec<Option<CompressedRistretto>>,
        destination_asset_blindings: Vec<Option<Scalar>>,
        destination_public_keys: &Vec<PublicKey>,

    ) -> Result<((ChaumPedersenCommitmentEqProof, ChaumPedersenCommitmentEqProof),
                 Vec<CompressedRistretto>, Vec<Scalar>), ZeiError>
    {
        let num_output = destination_public_keys.len();
        let mut out_asset_com = vec![];
        let mut out_asset_blind = vec![];
        let asset = Asset {id: String::from(asset_type)};

        let mut all_asset_com = Vec::new();
        all_asset_com.extend_from_slice(source_asset_commitments);

        let mut all_asset_blind = Vec::new();
        all_asset_blind.extend_from_slice(source_asset_blindings);

        //create commitments and blindings if they don't exits (UTXO or new type for account)
        for i in 0..num_output{
            if destination_asset_commitments.len() >= i || destination_asset_commitments[i].is_none() {
                let (asset_comm, asset_blind) =
                    compute_asset_commitment(
                        prng, pc_gens, &destination_public_keys[i], &asset)?;
                out_asset_com.push(asset_comm.compress());
                out_asset_blind.push(asset_blind);
            }
            else{
                out_asset_com.push(destination_asset_commitments[i].unwrap());
                out_asset_blind.push(destination_asset_blindings[i].unwrap());

            }
        }

        all_asset_com.extend(out_asset_com.iter());
        all_asset_blind.extend(out_asset_blind.iter());

        let asset_as_scalar = asset.compute_scalar_hash();

        let proof_asset = chaum_pedersen_prove_multiple_eq(
            prng,
            pc_gens,
            &asset_as_scalar,
            all_asset_com.as_slice(),
            all_asset_blind.as_slice())?;

        Ok((proof_asset, out_asset_com, out_asset_blind))
    }


    fn build_tx_struct(
        source_info: Vec<TxPublicAddressInfo>,
        destination_info: Vec<TxDestinationInfo>,
        range_proof: Option<RangeProof>,
        asset_proof: Option<(ChaumPedersenCommitmentEqProof, ChaumPedersenCommitmentEqProof)>,
        signatures: Vec<Signature>) -> Tx
    {
        let confidential_amount = range_proof.is_some();
        let confidential_asset = asset_proof.is_some();
        let proofs = TxProofs{
            range_proof,
            asset_proof,
        };
        let body = TxBody{
            source_info,
            destination_info,
            proofs,
            confidential_amount,
            confidential_asset,
        };
        Tx{
            body,
            signatures,
        }
    }

    pub fn verify(&self) -> bool{
        //1 signature TODO
        //2 amounts
        if self.body.confidential_amount {
            if !self.verify_confidential_amount(){
                return false;
            }
        }
        else {
            let in_amount: Vec<u64> = self.body.source_info.iter().map(|x| x.amount.unwrap()).collect();
            let in_amount_sum = in_amount.iter().sum::<u64>();
            let out_amount: Vec<u64> = self.body.destination_info.iter().map(|x| x.public_info.amount.unwrap()).collect();
            let out_amount_sum = out_amount.iter().sum::<u64>();

            if out_amount_sum > in_amount_sum {
                return false;
            }
        }

        //3 asset
        if self.body.confidential_asset {
            return self.verify_confidential_asset();
        }
        //else
        let asset_id_option = self.body.source_info[0].asset_type.as_ref().unwrap();
        for x in self.body.source_info.iter(){
            let asset_id_option_i = x.asset_type.as_ref().unwrap();
            if asset_id_option_i != asset_id_option {
                return false;
            }
        }

        for x in self.body.destination_info.iter(){
            let asset_id_option_i = x.public_info.asset_type.as_ref().unwrap();
            if asset_id_option_i != asset_id_option {
                return false;
            }
        }
        true
    }

    fn verify_confidential_amount(&self) -> bool {
        let num_output = self.body.destination_info.len();
        let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;

        let params = PublicParams::new(upper_power2);
        let mut transcript = Transcript::new(b"Zei Range Proof");

        let input_com: Vec<RistrettoPoint> = self.body.source_info.iter().
            map(|x| x.amount_commitment.unwrap().decompress().unwrap()).collect();

        let output_com: Vec<RistrettoPoint> = self.body.destination_info.iter().
            map(|x| x.public_info.amount_commitment.
                unwrap().decompress().unwrap()).collect();

        let diff_com = input_com.iter().sum::<RistrettoPoint>() -
            output_com.iter().sum::<RistrettoPoint>();

        let mut ranges_com: Vec<CompressedRistretto> = output_com.iter().
            map(|x| x.compress()).collect();

        ranges_com.push(diff_com.compress());

        for _ in (num_output + 1)..upper_power2 {
            ranges_com.push(CompressedRistretto::identity());
        }

        let verify_range_proof = self.body.proofs.range_proof.
            as_ref().unwrap().verify_multiple(
            &params.bp_gens,
            &params.pc_gens,
            &mut transcript,
            ranges_com.as_slice(),
            BULLET_PROOF_RANGE,
        );

        verify_range_proof.is_ok()

    }

    fn verify_confidential_asset(&self) -> bool{
        let pc_gens = PedersenGens::default();
        let mut asset_commitments: Vec<CompressedRistretto> = self.body.source_info.iter().
            map(|x| x.asset_type_commitment.unwrap()).collect();

        let out_asset_commitments: Vec<CompressedRistretto> = self.body.destination_info.iter().
            map(|x| x.public_info.asset_type_commitment.unwrap()).collect();

        asset_commitments.extend(out_asset_commitments.iter());

        let proof = self.body.proofs.asset_proof.borrow().as_ref().unwrap();
        let r = chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            asset_commitments.as_slice(),
            proof,
        );

        r.unwrap()
    }

    pub fn receiver_unlock_memo(
        lbox: &ZeiRistrettoCipher,
        sk: &Scalar,
        confidential_amount: bool,
        confidential_asset: bool,
    ) -> Result<(Option<u64>, Option<Scalar>, Option<Scalar>), ZeiError>
    {
        let mut amount = None;
        let mut amount_blind = None;
        let mut asset_blind = None;

        let mut bytes = [0u8;32];

        let message = lbox.decrypt(sk)?;
        if confidential_amount {
            let (value, scalars) = message.split_at(8);
            amount = Some(u8_bigendian_slice_to_u64(value));

            bytes.copy_from_slice(&scalars[0..32]);
            amount_blind = Some(Scalar::from_bits(bytes));

            if confidential_asset {
                bytes.copy_from_slice(&scalars[32..64]);
                asset_blind = Some(Scalar::from_bits(bytes));
            }
        }
        else if confidential_asset {
            bytes.copy_from_slice(message.as_slice());
            asset_blind = Some(Scalar::from_bits(bytes));
        }

        Ok((amount, amount_blind, asset_blind))

    }

}


#[inline]
fn smallest_greater_power_of_two(n: u32) -> u32{
    2.0f64.powi((n as f64).log2().ceil() as i32) as u32
}

fn compute_asset_commitment<R>(
    csprng: &mut R,
    pc_gens: &PedersenGens,
    address: &PublicKey,
    asset_type: &Asset) -> Result<(RistrettoPoint,Scalar), ZeiError>
    where R:CryptoRng + Rng,
{
    let blinding_factor = sample_blinding_factor(csprng, address)?;
    let asset_hash = asset_type.compute_scalar_hash();

    Ok((pc_gens.commit(asset_hash, blinding_factor), blinding_factor))
}

fn sample_blinding_factor<R>(csprng: &mut R, address: &PublicKey) -> Result<Scalar, ZeiError>
    where R: CryptoRng + Rng,
{
    let blinding_key = Scalar::random(csprng);
    let aux: RistrettoPoint = blinding_key * address.get_curve_point()?;
    let mut hasher = Blake2b::new();
    hasher.input(&aux.compress().to_bytes());
    Ok(Scalar::from_hash(hasher))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use schnorr::Keypair;
    use crate::encryption::from_secret_key_to_scalar;

    fn build_address_params<R: CryptoRng + Rng>(prng: &mut R, amount: u64, asset: &str,
                                                input: bool, //input or output
                                                confidential_amount: bool,
                                                confidential_asset: bool) -> (TxAddressParams, Scalar) {
        let pc_gens = PedersenGens::default();


        let mut amount_commitment = None;
        let mut amount_blinding = None;
        let mut asset_type_commitment = None;
        let mut asset_type_blinding = None;
        let mut sk = None;

        if confidential_amount && input {
            let blind = Scalar::random(prng);
            let com = pc_gens.commit(Scalar::from(amount), blind);

            amount_commitment = Some(com.compress());
            amount_blinding = Some(blind);
        }
        if confidential_asset {
            let a = Asset {
                id: String::from(asset),
            };
            let (com, blind) = a.compute_commitment(prng);
            asset_type_commitment = Some(com.compress());
            asset_type_blinding = Some(blind);
        }
        let key = Keypair::generate(prng);

        let secret_key_bytes = key.secret.to_bytes();

        let scalar_secret_key = from_secret_key_to_scalar(&secret_key_bytes);

        if input {
            sk = Some(key.secret);
        }
        (TxAddressParams {
            amount,
            amount_commitment,
            amount_blinding,
            asset_type: String::from(asset),
            asset_type_commitment,
            asset_type_blinding,
            public_key: key.public,
            secret_key: sk,
        }, scalar_secret_key)
    }

    #[test]
    fn test_transaction_not_confidential() {
        /*! I test simple transaction from 3 input to 4 output that do not provide any
        confidentiality*/
        let asset_id = "default_currency";
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let num_inputs = 3;
        let num_outputs = 4;
        let input_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks: Vec<Scalar> = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, input_amount[i], asset_id,
                                     true,false, false);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false,false, false);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();

        assert_eq!(true, tx.verify(), "Not confidential simple transaction should verify ok");

        for i in 0..num_outputs {
            assert_eq!(None, tx.body.destination_info[i].lock_box);
        }

        //overflow transfer
        out_addrs[3].amount = 0xFFFFFFFFFF;
        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Output amounts are greater than input, should fail in verify");

        //exact transfer
        out_addrs[3].amount = 24;
        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(true, tx.verify(),
                   "Not confidential tx with exact input and output should pass");

        //first different from rest
        in_addrs[0].asset_type = String::from("another asset");
        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Not confidential transaction with different asset type on first input should \
                   fail verification ok");

        //input does not match
        in_addrs[0].asset_type = String::from(asset_id);
        in_addrs[1].asset_type = String::from("another asset");
        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Not confidential transaction with different asset type on non first input \
                   should fail verification ok");

        //output does not match
        in_addrs[1].asset_type = String::from(asset_id);
        out_addrs[1].asset_type = String::from("another asset");
        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Not confidential transaction with different asset type on output \
                   should fail verification ok");
    }

    #[test]
    fn test_transaction_confidential_asset() {
        /*! I test transaction from 3 input to 4 output that hide the asset type
        but not the amount*/
        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let num_inputs = 3;
        let num_outputs = 4;
        let input_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks: Vec<Scalar> = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, input_amount[i], asset_id,
                                     true,false, true);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false,false, true);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, true).unwrap();

        assert_eq!(true, tx.verify(), "Conf. asset tx: Transaction is valid");

        //check receivers memos decryption
        for i in 0..4 {
            let (amount, amount_blind, asset_blind) =
                Tx::receiver_unlock_memo(
                    tx.body.destination_info[i].lock_box.as_ref().unwrap(),
                    &out_sks[i], false, true).unwrap();

            assert_eq!(None, amount, "Conf. asset tx: Decryption should not contain amount");
            assert_eq!(None, amount_blind, " Conf. asset tx: Decryption should not contain amount blinding");
            let blind_com = pc_gens.commit(Asset { id: String::from(asset_id) }.
                compute_scalar_hash(), asset_blind.unwrap());
            assert_eq!(blind_com.compress(),
                       tx.body.destination_info[i].public_info.asset_type_commitment.unwrap(),
                       "Conf. asset tx: Decryption should contain valit asset blinding");
            //TODO what if output blinding was provided (account based)
        }

        //one input does not match
        let (new_in1,_) =
            build_address_params(&mut prng, 10, "another asset",
                                 true, false, true);
        in_addrs[1] = new_in1;
        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, true).unwrap();
        assert_eq!(false, tx.verify(), "Confidential asset tx, one input asset does not match");

        //one output does not match
        let (new_in1, _) =
            build_address_params(&mut prng, 10, asset_id,
                                 true, false, true);
        in_addrs[1] = new_in1;
        let (new_out2, _) =
            build_address_params(&mut prng, 1, "another asset",
                                 false, false, true);
        out_addrs[2] = new_out2;
        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(), "Confidential asset tx, one output asset does not match");
    }

    #[test]
    fn test_confidential_amount() {
        /*! I test transactions from 3 input to 4 output that hide the amount
        but not the asset type*/

        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let num_inputs = 3;
        let num_outputs = 4;
        let in_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks: Vec<Scalar> = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, in_amount[i], asset_id,
                                     true, true, false);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false, true, false);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         true, false).unwrap();
        assert_eq!(true, tx.verify(),
                   "Conf. amount tx: Transaction should be valid");

        //check receivers memos decryption
        for i in 0..num_outputs {
            let (amount, amount_blind, asset_blind) =
                Tx::receiver_unlock_memo(tx.body.destination_info[i].lock_box.as_ref().unwrap(),
                                         &out_sks[i],
                                         true, false).unwrap();

            assert_eq!(None, asset_blind,
                       "Conf. amount tx: memo decryption should not contain asset blinding,\
                       since it is not a confidential asset tx");
            assert_eq!(out_amount[i], amount.unwrap(),
                       "Conf. amount tx: memo decryption should contain original tx amount");
            let amount_com = pc_gens.commit(Scalar::from(out_amount[i]),
                                            amount_blind.unwrap());
            assert_eq!(amount_com.compress(),
                       tx.body.destination_info[i].public_info.amount_commitment.unwrap(),
                       "Conf. amount tx: memo decryption should contain valid amount blinding");
        }

        let (new_out3, _) =
            build_address_params(&mut prng, 50, asset_id,
                                 false, true, false);
        out_addrs[3] = new_out3;

        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         true, false);

        assert_eq!(ZeiError::TxProofError, tx.err().unwrap(),
                   "Conf. amount tx: tx should have not be able to produce range proof");
    }
}