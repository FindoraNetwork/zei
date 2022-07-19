use crate::errors::AlgebraError;
use crate::prelude::*;
use ark_ec::ProjectiveCurve;
use ark_ff::{BigInteger, FftField, FftParameters, Field, FpParameters, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    fmt::{Debug, Display, Formatter},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    result::Result as StdResult,
    str::FromStr,
    One, UniformRand, Zero,
};
use bulletproofs_bs257::curve::bs257::{Fr, FrParameters, G1Affine, G1Projective};
use digest::{generic_array::typenum::U64, Digest};
use num_bigint::BigUint;
use ruc::eg;
use wasm_bindgen::prelude::*;

/// The number of bytes for a scalar value over BS-257
pub const BS257_SCALAR_LEN: usize = 33;

/// The wrapped struct for `bulletproofs_bs257::curve::bs257::Fr`
#[wasm_bindgen]
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct BS257Scalar(pub(crate) Fr);

impl Debug for BS257Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let biguint = BigUint::from(self.0.clone());
        <BigUint as Display>::fmt(&biguint, f)
    }
}

/// The wrapped struct for `bulletproofs_bs257::curve::bs257::G1Projective`
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq, Debug)]
pub struct BS257G1(pub(crate) G1Projective);

impl FromStr for BS257Scalar {
    type Err = AlgebraError;

    fn from_str(string: &str) -> StdResult<Self, AlgebraError> {
        let res = Fr::from_str(string);

        if res.is_ok() {
            Ok(Self(res.unwrap()))
        } else {
            Err(AlgebraError::DeserializationError)
        }
    }
}

impl Into<BigUint> for &BS257Scalar {
    fn into(self) -> BigUint {
        self.0.into_repr().into()
    }
}

impl From<&BigUint> for BS257Scalar {
    fn from(src: &BigUint) -> Self {
        Self(Fr::from(src.clone()))
    }
}

impl One for BS257Scalar {
    #[inline]
    fn one() -> Self {
        BS257Scalar(Fr::one())
    }
}

impl Zero for BS257Scalar {
    #[inline]
    fn zero() -> Self {
        Self(Fr::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for BS257Scalar {
    type Output = BS257Scalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Mul for BS257Scalar {
    type Output = BS257Scalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> Add<&'a BS257Scalar> for BS257Scalar {
    type Output = BS257Scalar;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BS257Scalar> for BS257Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        (self.0).add_assign(&rhs.0);
    }
}

impl<'a> Sub<&'a BS257Scalar> for BS257Scalar {
    type Output = BS257Scalar;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> SubAssign<&'a BS257Scalar> for BS257Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        (self.0).sub_assign(&rhs.0);
    }
}

impl<'a> Mul<&'a BS257Scalar> for BS257Scalar {
    type Output = BS257Scalar;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> MulAssign<&'a BS257Scalar> for BS257Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        (self.0).mul_assign(&rhs.0);
    }
}

impl Neg for BS257Scalar {
    type Output = BS257Scalar;

    #[inline]
    fn neg(self) -> Self {
        Self(self.0.neg())
    }
}

impl From<u32> for BS257Scalar {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<u64> for BS257Scalar {
    #[inline]
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl Scalar for BS257Scalar {
    #[inline]
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(Fr::rand(rng))
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self::random(&mut prng)
    }

    #[inline]
    fn capacity() -> usize {
        bulletproofs_bs257::curve::bs257::FrParameters::CAPACITY as usize
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(Fr::multiplicative_generator())
    }

    #[inline]
    fn get_field_size_le_bytes() -> Vec<u8> {
        [
            0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]
        .to_vec()
    }

    #[inline]
    fn get_little_endian_u64(&self) -> Vec<u64> {
        let a = self.0.into_repr().to_bytes_le();
        let a1 = u8_le_slice_to_u64(&a[0..8]);
        let a2 = u8_le_slice_to_u64(&a[8..16]);
        let a3 = u8_le_slice_to_u64(&a[16..24]);
        let a4 = u8_le_slice_to_u64(&a[24..32]);
        let a5 = u8_le_slice_to_u64(&a[32..]);
        vec![a1, a2, a3, a4, a5]
    }

    #[inline]
    fn bytes_len() -> usize {
        BS257_SCALAR_LEN
    }

    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()[..BS257_SCALAR_LEN].to_vec()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::bytes_len() {
            return Err(eg!(AlgebraError::DeserializationError));
        }
        let mut array = vec![0u8; Self::bytes_len()];
        array[0..bytes.len()].copy_from_slice(bytes);
        Ok(Self(Fr::from_le_bytes_mod_order(bytes)))
    }

    #[inline]
    fn inv(&self) -> Result<Self> {
        let a = self.0.inverse();
        if a.is_none() {
            return Err(eg!(AlgebraError::GroupInversionError));
        }
        Ok(Self(a.unwrap()))
    }

    #[inline]
    fn pow(&self, exponent: &[u64]) -> Self {
        let len = exponent.len();
        let mut array = [0u64; 5];
        array[..len].copy_from_slice(exponent);
        Self(self.0.pow(&array))
    }
}

impl Group for BS257G1 {
    type ScalarType = BS257Scalar;
    const COMPRESSED_LEN: usize = 33;

    #[inline]
    fn double(&self) -> Self {
        Self(ProjectiveCurve::double(&self.0))
    }

    #[inline]
    fn get_identity() -> Self {
        Self(G1Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G1Projective::prime_subgroup_generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self::get_base().mul(&BS257Scalar::random(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_unchecked(&mut buf).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize(&mut reader);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize_unchecked(&mut reader);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        let g = G1Affine::from(Self::get_base().0);
        g.uncompressed_size()
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(G1Projective::rand(&mut prng))
    }

    #[inline]
    fn multi_exp(scalars: &[&Self::ScalarType], points: &[&Self]) -> Self {
        let scalars_raw = scalars
            .iter()
            .map(|r| r.0.into_repr())
            .collect::<Vec<<FrParameters as FftParameters>::BigInt>>();
        let points_raw = G1Projective::batch_normalization_into_affine(
            &points.iter().map(|r| r.0).collect::<Vec<G1Projective>>(),
        );

        Self(ark_ec::msm::VariableBase::msm(&points_raw, &scalars_raw))
    }
}

impl<'a> Add<&'a BS257G1> for BS257G1 {
    type Output = BS257G1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a BS257G1> for BS257G1 {
    type Output = BS257G1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a BS257Scalar> for BS257G1 {
    type Output = BS257G1;

    #[inline]
    fn mul(self, rhs: &BS257Scalar) -> Self::Output {
        Self(self.0.mul(&rhs.0.into_repr()))
    }
}

impl<'a> AddAssign<&'a BS257G1> for BS257G1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a BS257G1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BS257G1> for BS257G1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BS257G1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a BS257Scalar> for BS257G1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BS257Scalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}

#[cfg(test)]
mod bs257_groups_test {
    use crate::{
        bs257::{BS257Scalar, BS257G1},
        prelude::*,
        traits::group_tests::{test_scalar_operations, test_scalar_serialization},
    };
    use ark_ec::ProjectiveCurve;
    use bulletproofs_bs257::curve::bs257::G1Affine;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_scalar_ops() {
        test_scalar_operations::<BS257Scalar>();
    }

    #[test]
    fn scalar_deser() {
        test_scalar_serialization::<BS257Scalar>();
    }

    #[test]
    fn scalar_from_to_bytes() {
        let small_value = BS257Scalar::from(165747u32);
        let small_value_bytes = small_value.to_bytes();
        let expected_small_value_bytes: [u8; 33] = [
            115, 135, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        assert_eq!(small_value_bytes, expected_small_value_bytes);

        let small_value_from_bytes = BS257Scalar::from_bytes(&small_value_bytes).unwrap();
        assert_eq!(small_value_from_bytes, small_value);
    }

    #[test]
    fn curve_points_respresentation_of_g1() {
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BS257G1::get_base();
        let s1 = BS257Scalar::from(50 + rng.next_u32() % 50);

        let g1 = g1.mul(&s1);

        let g1_prime = BS257G1::random(&mut rng);

        // This is the projective representation of g1
        let g1_projective = g1.0;
        let g1_prime_projective = g1_prime.0;

        // This is the affine representation of g1_prime
        let g1_prime_affine = G1Affine::from(g1_prime_projective);

        let g1_pr_plus_g1_prime_pr = g1_projective.add(&g1_prime_projective);

        // These two operations correspond to summation of points,
        // one in projective form and the other in affine form
        let g1_pr_plus_g1_prime_af = g1_projective.add_mixed(&g1_prime_affine);
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);

        let g1_pr_plus_g1_prime_af = g1_projective.add_mixed(&g1_prime_projective.into_affine());
        assert_eq!(g1_pr_plus_g1_prime_pr, g1_pr_plus_g1_prime_af);
    }

    #[test]
    fn test_serialization_of_points() {
        let mut rng = ChaCha20Rng::from_entropy();

        let g1 = BS257G1::random(&mut rng);
        let g1_bytes = g1.to_compressed_bytes();
        let g1_recovered = BS257G1::from_compressed_bytes(&g1_bytes).unwrap();
        assert_eq!(g1, g1_recovered);
    }
}