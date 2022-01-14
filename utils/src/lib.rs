#![deny(warnings)]
#![allow(clippy::upper_case_acronyms)]

pub mod errors;
pub mod macros;
pub mod serialization;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use ruc::*;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[macro_export]
macro_rules! msg_eq {
    ($zei_err: expr, $ruc_err: expr $(,)?) => {
        assert!($ruc_err.msg_has_overloop(ruc::eg!($zei_err).as_ref()));
    };
    ($zei_err: expr, $ruc_err: expr, $msg: expr $(,)?) => {
        assert!($ruc_err.msg_has_overloop(ruc::eg!($zei_err).as_ref()), $msg);
    };
}

#[macro_export]
macro_rules! serialize_deserialize {
    ($t:ident) => {
        impl serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&utils::b64enc(&self.zei_to_bytes()))
                } else {
                    serializer.serialize_bytes(&self.zei_to_bytes())
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let bytes = if deserializer.is_human_readable() {
                    deserializer.deserialize_str(
                        utils::serialization::zei_obj_serde::BytesVisitor,
                    )?
                } else {
                    deserializer.deserialize_bytes(
                        utils::serialization::zei_obj_serde::BytesVisitor,
                    )?
                };
                $t::zei_from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// I convert a 8 byte array big-endian into a u64 (bigendian)
pub fn u8_be_slice_to_u64(slice: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(slice);
    u64::from_be_bytes(a)
}

/// I convert a 8 byte array little-endian into a u64 (bigendian)
pub fn u8_le_slice_to_u64(slice: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(slice);
    u64::from_le_bytes(a)
}

/// I convert a slice into a u32 (bigendian)
pub fn u8_be_slice_to_u32(slice: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(slice);
    u32::from_be_bytes(a)
}

/// I convert a slice into a u32 (littleendian)
pub fn u8_le_slice_to_u32(slice: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(slice);
    u32::from_le_bytes(a)
}

/// I compute the minimum power of two that is greater or equal to the input
pub fn min_greater_equal_power_of_two(n: u32) -> u32 {
    2.0f64.powi((n as f64).log2().ceil() as i32) as u32
}

pub fn u64_to_u32_pair(x: u64) -> (u32, u32) {
    ((x & 0xFFFF_FFFF) as u32, (x >> 32) as u32)
}

pub fn b64enc<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, base64::URL_SAFE)
}
pub fn b64dec<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>> {
    base64::decode_config(input, base64::URL_SAFE).c(d!())
}

pub fn derive_prng_from_hash<D, R>(hash: D) -> R
where
    D: Digest<OutputSize = U64> + Default,
    R: CryptoRng + RngCore + SeedableRng<Seed = [u8; 32]>,
{
    const SEED_SIZE: usize = 32;
    let mut seed: [u8; SEED_SIZE] = [0; SEED_SIZE];
    let result = hash.finalize();
    seed.copy_from_slice(&result[0..SEED_SIZE]);
    R::from_seed(seed)
}

/// I shift a big integer (represented as a littleendian bytes vector) by one bit.
pub fn shift_u8_vec(r: &mut Vec<u8>) {
    let mut next = 0u8;
    for e in r.iter_mut().rev() {
        let prev = *e;
        *e = (*e >> 1) | next;
        next = (prev % 2) << 7;
    }
    if *r.last().unwrap() == 0 && r.len() > 1 {
        r.pop();
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_shift_u8_vec() {
        let mut v = vec![0];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![0]);

        let mut v = vec![1];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![0]);

        let mut v = vec![2];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![1]);

        let mut v = vec![255];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![127]);

        let mut v = vec![0, 1];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![128]);
        let mut v = vec![0, 0, 1];
        super::shift_u8_vec(&mut v);
        assert_eq!(v, vec![0, 128]);
    }

    #[test]
    fn test_u8_be_slice_to_u32() {
        let array = [0xFA_u8, 0x01, 0xC6, 0x73];
        let n = super::u8_be_slice_to_u32(&array);
        assert_eq!(0xFA01C673, n);
    }

    #[test]
    fn u8_be_slice_to_u64() {
        let array = [0xFA_u8, 0x01, 0xC6, 0x73, 0x22, 0xE4, 0x98, 0xA2];
        let n = super::u8_be_slice_to_u64(&array);
        assert_eq!(0xFA01C67322E498A2, n);
    }

    #[test]
    fn min_greater_equal_power_of_two() {
        assert_eq!(16, super::min_greater_equal_power_of_two(16));
        assert_eq!(16, super::min_greater_equal_power_of_two(15));
        assert_eq!(16, super::min_greater_equal_power_of_two(9));
        assert_eq!(8, super::min_greater_equal_power_of_two(8));
        assert_eq!(8, super::min_greater_equal_power_of_two(6));
        assert_eq!(8, super::min_greater_equal_power_of_two(5));
        assert_eq!(4, super::min_greater_equal_power_of_two(4));
        assert_eq!(4, super::min_greater_equal_power_of_two(3));
        assert_eq!(2, super::min_greater_equal_power_of_two(2));
        assert_eq!(1, super::min_greater_equal_power_of_two(1));
        assert_eq!(0, super::min_greater_equal_power_of_two(0));
    }

    #[test]
    fn u64_to_u32_pair() {
        assert_eq!((32, 0), super::u64_to_u32_pair(32u64));
        assert_eq!(
            (0xFFFFFFFF, 0xFFFFFFFF),
            super::u64_to_u32_pair(0xFFFFFFFFFFFFFFFFu64)
        );
        assert_eq!(
            (0, 0xFFFFFFFF),
            super::u64_to_u32_pair(0xFFFFFFFF00000000u64)
        );
    }
}

pub fn save_to_file(params_ser: &[u8], out_filename: PathBuf) {
    let filename = out_filename.to_str().unwrap();
    let mut f = File::create(&filename).expect("Unable to create file");
    f.write_all(params_ser).expect("Unable to write data");
    println!("Public parameters written in file {}.", filename);
}
