use crate::xfr::sig::{XfrPublicKey, XfrSecretKey, XfrSignature};
use crate::xfr::structs::{AssetType, ASSET_TYPE_LENGTH};
use ed25519_dalek::{PublicKey, SecretKey};
use ruc::*;
use serde::Serializer;
use utils::errors::ZeiError;
pub use utils::serialization::ZeiFromToBytes;

/*
impl ZeiFromToBytes for AXfrPubKey {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.zei_to_bytes()
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
    let point = JubjubGroup::zei_from_bytes(bytes).c(d!())?;
    Ok(AXfrPubKey(point))
  }
}

serialize_deserialize!(AXfrPubKey);

impl ZeiFromToBytes for AXfrSecKey {
  fn zei_to_bytes(&self) -> Vec<u8> {
    self.0.zei_to_bytes()
  }

  fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
    let scalar = JubjubScalar::zei_from_bytes(bytes).c(d!())?;
    Ok(AXfrSecKey(scalar))
  }
}

serialize_deserialize!(AXfrSecKey);
*/

impl ZeiFromToBytes for AssetType {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ASSET_TYPE_LENGTH {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let mut array = [0u8; ASSET_TYPE_LENGTH];
            array.copy_from_slice(bytes);
            Ok(AssetType(array))
        }
    }
}

// serialize_deserialize!(AssetType);

impl ZeiFromToBytes for XfrPublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        let pk = PublicKey::from_bytes(bytes).c(d!(ZeiError::DeserializationError))?;
        Ok(XfrPublicKey(pk))
    }
}
serialize_deserialize!(XfrPublicKey);

impl ZeiFromToBytes for XfrSecretKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(XfrSecretKey(
            SecretKey::from_bytes(bytes).c(d!(ZeiError::DeserializationError))?,
        ))
    }
}

serialize_deserialize!(XfrSecretKey);

impl ZeiFromToBytes for XfrSignature {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(&bytes[..]);
        vec
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        match ed25519_dalek::Signature::from_bytes(bytes) {
            Ok(e) => Ok(XfrSignature(e)),
            Err(_) => Err(eg!(ZeiError::DeserializationError)),
        }
    }
}

serialize_deserialize!(XfrSignature);

/*
// XXX keep this for future reference
// use with #[serde(with = "serialization::option_bytes")]
pub mod option_bytes {
  use crate::serialization::ZeiFromToBytes;
  use serde::{self, Deserialize, Deserializer, Serializer};

  pub fn serialize<S, T>(object: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
          T: ZeiFromToBytes
  {
    if object.is_none() {
      serializer.serialize_none()
    } else {
      let bytes = object.as_ref().unwrap().zei_to_bytes();
      //let encoded = hex::encode(&bytes[..]);
      if serializer.is_human_readable() {
        serializer.serialize_str(&b64enc(bytes.as_slice()))
      } else {
        serializer.serialize_bytes(bytes.as_slice())
      }
    }
  }

  pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where D: Deserializer<'de>,
          T: ZeiFromToBytes
  {
    let vec: Option<Vec<u8>> = Option::deserialize(deserializer)?;

    if let Some(value) = vec {
      Ok(Some(T::zei_from_bytes(value.as_slice())))
    } else {
      Ok(None)
    }
  }
}
*/

#[cfg(test)]
mod test {
    use crate::anon_xfr::keys::{AXfrKeyPair, AXfrPubKey};
    use crate::ristretto::CompressedRistretto;
    use crate::serialization::ZeiFromToBytes;
    use crate::xfr::asset_tracer::RecordDataEncKey;
    use crate::xfr::sig::{XfrKeyPair, XfrPublicKey, XfrSecretKey, XfrSignature};
    use crate::xfr::structs::{
        BlindAssetRecord, OpenAssetRecord, XfrAmount, XfrAssetType,
    };
    use algebra::ristretto::RistrettoPoint;
    use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
    use crypto::basics::elgamal::elgamal_key_gen;
    use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use rmp_serde::{Deserializer, Serializer};
    use ruc::*;
    use serde::de::Deserialize;
    use serde::ser::Serialize;
    use std::convert::TryFrom;

    #[test]
    fn xfr_amount_u64_to_string_serde() {
        let amt = XfrAmount::NonConfidential(1844674407370955161);
        let actual_to_string_res = serde_json::to_string(&amt).unwrap();
        let expected_to_string_res = r##"{"NonConfidential":"1844674407370955161"}"##;
        assert_eq!(actual_to_string_res, expected_to_string_res);
    }

    #[test]
    fn xfr_amount_u64_from_string_serde() {
        let serialized_str = r##"{"NonConfidential":"1844674407370955161"}"##;
        let actual_amt: XfrAmount =
            serde_json::from_str::<XfrAmount>(&serialized_str).unwrap();

        let val = 1844674407370955161;
        let expected_amt = XfrAmount::NonConfidential(val);
        assert_eq!(expected_amt.get_amount(), actual_amt.get_amount());
    }

    #[test]
    fn oar_amount_u64_to_string_serde() {
        use curve25519_dalek::ristretto::CompressedRistretto as CR;
        let default_cr = CompressedRistretto(CR(<[u8; 32]>::try_from(
            vec![0_u8; 32].as_slice(),
        )
        .unwrap()));
        let blind_amount = XfrAmount::Confidential((default_cr, default_cr));
        let blind_type = XfrAssetType::Confidential(default_cr);
        let amt = 1844674407370955161;
        let oar = OpenAssetRecord {
            blind_asset_record: BlindAssetRecord {
                amount: blind_amount,
                asset_type: blind_type,
                public_key: Default::default(),
            },
            amount: amt,
            amount_blinds: (Default::default(), Default::default()),
            asset_type: Default::default(),
            type_blind: Default::default(),
        };
        let actual_to_string_res = serde_json::to_string(&oar).unwrap();
        let expected_to_string_res = r##"{"blind_asset_record":{"amount":{"Confidential":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},"asset_type":{"Confidential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"amount":"1844674407370955161","amount_blinds":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"asset_type":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"type_blind":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"##;
        assert_eq!(actual_to_string_res, expected_to_string_res);
    }

    #[test]
    fn oar_amount_u64_from_string_serde() {
        let serialized_str = r##"{"blind_asset_record":{"amount":{"Confidential":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},"asset_type":{"Confidential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"amount":"1844674407370955161","amount_blinds":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"asset_type":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"type_blind":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"##;
        let oar: OpenAssetRecord =
            serde_json::from_str::<OpenAssetRecord>(&serialized_str).unwrap();
        let val = 1844674407370955161_u64;
        assert_eq!(val, *oar.get_amount());
    }

    #[test]
    fn anon_xfr_pub_key_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = AXfrKeyPair::generate(&mut prng);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .pub_key()
                .serialize(&mut Serializer::new(&mut pk_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: AXfrPubKey = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(keypair.pub_key(), pk2);

        let mut keypair_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .serialize(&mut Serializer::new(&mut keypair_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&keypair_mp_vec[..]);
        let keypair_2: AXfrKeyPair = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(keypair, keypair_2);
    }

    #[test]
    fn public_key_message_pack_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = XfrKeyPair::generate(&mut prng);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .pub_key
                .serialize(&mut Serializer::new(&mut pk_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: XfrPublicKey = Deserialize::deserialize(&mut de).unwrap();

        assert_eq!(&keypair.pub_key, &pk2);
    }

    #[test]
    fn x25519_public_key_message_pack_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let sk = XSecretKey::new(&mut prng);
        let pk = XPublicKey::from(&sk);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            pk.serialize(&mut Serializer::new(&mut pk_mp_vec)).is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: XPublicKey = Deserialize::deserialize(&mut de).unwrap();

        assert_eq!(&pk, &pk2);
    }

    #[test]
    fn signature_message_pack_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = XfrKeyPair::generate(&mut prng);
        let message = [10u8; 55];

        let signature = keypair.sign(&message);

        let mut vec = vec![];
        assert_eq!(
            true,
            signature.serialize(&mut Serializer::new(&mut vec)).is_ok()
        );

        let mut de = Deserializer::new(&vec[..]);
        let signature2 = XfrSignature::deserialize(&mut de).unwrap();

        assert_eq!(signature, signature2);
    }

    #[derive(Serialize, Deserialize, Default)]
    struct StructWithPubKey {
        key: XfrPublicKey,
    }

    #[derive(Serialize, Deserialize)]
    struct StructWithSecKey {
        key: XfrSecretKey,
    }

    #[test]
    fn serialize_and_deserialize_as_json() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = XfrKeyPair::generate(&mut prng);
        let test_struct = StructWithPubKey {
            key: keypair.pub_key,
        };
        let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize XfrPublicKey to JSON")))
        };
        if let Ok(restored) = serde_json::from_str::<StructWithPubKey>(&as_json) {
            assert_eq!(test_struct.key, restored.key);
        } else {
            pnk!(Err(eg!("Failed to deserialize XfrPublicKey from JSON")));
        }

        let test_struct = StructWithSecKey {
            key: keypair.sec_key,
        };
        let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize XfrSecretKey to JSON")))
        };
        if let Ok(restored) = serde_json::from_str::<StructWithSecKey>(&as_json) {
            assert_eq!(test_struct.key.zei_to_bytes(), restored.key.zei_to_bytes());
        } else {
            pnk!(Err(eg!("Failed to deserialize XfrSecretKey from JSON")));
        }
    }

    #[test]
    fn serialize_and_deserialize_elgamal() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = RistrettoPedersenGens::default();
        let (_sk, xfr_pub_key) =
            elgamal_key_gen::<_, RistrettoPoint>(&mut prng, &pc_gens.B);
        let serialized = if let Ok(res) = serde_json::to_string(&xfr_pub_key) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize Elgamal public key")))
        };
        if let Ok(restored) = serde_json::from_str::<RecordDataEncKey>(&serialized) {
            assert_eq!(xfr_pub_key, restored);
        } else {
            pnk!(Err(eg!("Failed to deserialize XfrPublicKey from JSON")));
        }
    }
}
