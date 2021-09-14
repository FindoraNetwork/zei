use crate::commitments::pcs::{
    HomomorphicPolyComElem, PolyComScheme, PolyComSchemeError, ToBytes,
};
use crate::polynomials::field_polynomial::FpPolynomial;
use algebra::bls12_381::{BLSScalar, Bls12381, BLSG1};
use algebra::groups::{Group, GroupArithmetic, One, Scalar, ScalarArithmetic};
use algebra::multi_exp::MultiExp;
use algebra::pairing::Pairing;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
/// Implementation of KZG polynomial commitment scheme
/// https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf
/// This polynomial scheme relies on a bilinear map e:G1 x G2 -> Gt,
/// where G1,G2,Gt are cyclic groups of prime order p.
/// Let g1 be a generator of G1 and g2 be a generator of G_2.
/// The operations of the scheme are as follows:
///
/// setup(n: max polynomial degree)
///    Pick a random scalar s in Z_p
///    Compute public_parameter_group_1:= (g1,g1^s,g1^{s^2},...,g1^{s^n})
///    Compute public_parameter_group_2:= (g2,g2^s)
///    return (public_parameter_group_1,public_parameter_group_2)
///
/// commit(P: polynomial)
///    let P(x) = a0 + a1X + a2X^2 + ...+ a_nX^n
///    let C := g1^{P(s)} = \pi_{i=0}^n (g_i^{s^i})^{a_i}
///    return C
///
/// prove_eval(P:polynomial,x: evaluation point)
///    Let y=P(x)
///    Compute Q(X) = (P(X)-P(x))/(X-x)  # if indeed y==P(x) then (X-x)|P(X)-y
///    return g1^{Q(s)}
///
/// verify_eval(C: commitment, x: evaluation point, y: evaluation of P on x, proof: proof of evaluation)
///    The goal of this verification procedure is to check that indeed P(X)-y=Q(X)(X-x) using pairings
///    Check that e(C/g1^y,g2) == e(proof,g2^s/g2^x)
///
use std::fs;
use utils::errors::ZeiError;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KZGCommitment<G> {
    value: G,
}
impl<'a, G> ToBytes for KZGCommitment<G>
where
    G: Group,
{
    fn to_bytes(&self) -> Vec<u8> {
        self.value.to_compressed_bytes()
    }
}
impl HomomorphicPolyComElem for KZGCommitment<BLSG1> {
    type Scalar = BLSScalar;
    fn get_base() -> Self {
        KZGCommitment {
            value: BLSG1::get_base(),
        }
    }

    fn get_identity() -> Self {
        KZGCommitment {
            value: BLSG1::get_identity(),
        }
    }

    fn op(&self, other: &Self) -> Self {
        KZGCommitment {
            value: self.value.add(&other.value),
        }
    }

    fn op_assign(&mut self, other: &Self) {
        self.value = self.value.add(&other.value); // TODO have real add_assign
    }

    fn exp(&self, exp: &BLSScalar) -> Self {
        KZGCommitment {
            value: self.value.mul(exp),
        }
    }

    fn exp_assign(&mut self, exp: &BLSScalar) {
        self.value = self.value.mul(&exp); // TODO have real add_assign
    }

    fn inv(&self) -> Self {
        let minus_one_scalar = BLSScalar::one().neg();
        KZGCommitment {
            value: self.value.mul(&minus_one_scalar),
        }
    }
}

impl<F: Scalar> ToBytes for FpPolynomial<F> {
    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
}

impl<F: Scalar> HomomorphicPolyComElem for FpPolynomial<F> {
    type Scalar = F;

    fn get_base() -> Self {
        unimplemented!()
    }

    fn get_identity() -> Self {
        unimplemented!()
    }

    fn op(&self, other: &Self) -> Self {
        self.add(other)
    }

    fn op_assign(&mut self, other: &Self) {
        self.add_assign(other)
    }

    fn exp(&self, exp: &F) -> Self {
        self.mul_scalar(exp)
    }

    fn exp_assign(&mut self, exp: &F) {
        self.mul_scalar_assign(exp)
    }

    fn inv(&self) -> Self {
        self.neg()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct KZGEvalProof<G1>(G1);

impl<G: Group> ToBytes for KZGEvalProof<G> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed_bytes()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KZGCommitmentScheme<P: Pairing> {
    public_parameter_group_1: Vec<P::G1>,
    public_parameter_group_2: Vec<P::G2>,
}

impl<P: Pairing> KZGCommitmentScheme<P> {
    /// Creates a new instance of a KZG polynomial commitment scheme
    /// `max_degree` - max degree of the polynomial
    /// `prng` - pseudo-random generator
    pub fn new<R: CryptoRng + RngCore>(
        max_degree: usize,
        prng: &mut R,
    ) -> KZGCommitmentScheme<P> {
        let s = P::ScalarField::random(prng);

        let mut public_parameter_group_1: Vec<P::G1> = Vec::new();

        let mut elem_g1 = P::G1::get_base();

        for _ in 0..max_degree + 1 {
        //for _ in 0..max_degree + 1 {
            public_parameter_group_1.push(elem_g1.clone());
            elem_g1 = elem_g1.mul(&s);
        }

        let mut public_parameter_group_2: Vec<P::G2> = Vec::new();
        let elem_g2 = P::G2::get_base();
        public_parameter_group_2.push(elem_g2.clone());
        public_parameter_group_2.push(elem_g2.mul(&s));

        KZGCommitmentScheme {
            public_parameter_group_1,
            public_parameter_group_2,
        }
    }

    /// Get the public parameters from a file
    /// This file is generated by the executable `zkp-params-utils`
    /// * `filename` - name of the file containing the data of the public parameters
    /// This file must be in the directory `test_data` at the root of this crate.
    pub fn from_file(filename: &str) -> Result<KZGCommitmentScheme<P>> {
        let contents = fs::read(filename);
        if contents.is_err() {
            return Err(eg!(ZeiError::ParameterError));
        }
        let commitment_scheme: Result<KZGCommitmentScheme<P>> =
            bincode::deserialize(&contents.unwrap()).c(d!());
        match commitment_scheme {
            Ok(c) => Ok(c),
            _ => Err(eg!(ZeiError::ParameterError)),
        }
    }
}
pub type KZGCommitmentSchemeBLS = KZGCommitmentScheme<Bls12381>;
impl<'b> PolyComScheme for KZGCommitmentSchemeBLS {
    type Field = BLSScalar;
    type Commitment = KZGCommitment<BLSG1>;
    type EvalProof = KZGEvalProof<BLSG1>;
    type Opening = FpPolynomial<Self::Field>;

    fn commit(
        &self,
        polynomial: FpPolynomial<BLSScalar>,
    ) -> Result<(Self::Commitment, Self::Opening)> {
        let coefs_poly = polynomial.get_coefs_ref();

        let pol_degree = polynomial.degree();
        if pol_degree + 1 > self.public_parameter_group_1.len() {
            return Err(eg!(PolyComSchemeError::PCSProveEvalError));
        }

        let coefs_poly_bls_scalar_ref: Vec<&BLSScalar> = coefs_poly.iter().collect();
        let pub_param_group_1_as_ref: Vec<&BLSG1> = self.public_parameter_group_1
            [0..pol_degree + 1]
            .iter()
            .collect();
        let commitment_value = BLSG1::vartime_multi_exp(
            &coefs_poly_bls_scalar_ref[..],
            &pub_param_group_1_as_ref[..],
        );

        Ok((
            KZGCommitment {
                value: commitment_value,
            },
            polynomial,
        ))
    }

    fn opening(&self, polynomial: &FpPolynomial<Self::Field>) -> Self::Opening {
        (*polynomial).clone()
    }

    fn eval_opening(
        &self,
        opening: &FpPolynomial<Self::Field>,
        point: &Self::Field,
    ) -> Self::Field {
        opening.eval(point)
    }

    fn commitment_from_opening(&self, opening: &Self::Opening) -> Self::Commitment {
        let poly = self.polynomial_from_opening_ref(opening);
        let (c, _) = self.commit(poly).unwrap();
        c
    }

    fn polynomial_from_opening_ref(
        &self,
        opening: &Self::Opening,
    ) -> FpPolynomial<Self::Field> {
        (*opening).clone()
    }

    fn polynomial_from_opening(
        &self,
        opening: Self::Opening,
    ) -> FpPolynomial<Self::Field> {
        opening
    }

    fn prove_eval(
        &self,
        _transcript: &mut Transcript,
        opening: &FpPolynomial<Self::Field>,
        x: &Self::Field,
        max_degree: usize,
    ) -> Result<(Self::Field, Self::EvalProof)> {
        let polynomial = opening;
        let evaluation = polynomial.eval(x);

        // Compute the proof value
        if polynomial.degree() > max_degree {
            return Err(eg!(PolyComSchemeError::DegreeError));
        }

        let y = FpPolynomial::from_coefs(vec![evaluation]); // P(x)
        let f_eval_polynomial = polynomial.sub(&y); // P(X)-P(x)

        // Negation must happen in Fq
        let point_neg = x.neg();

        let divisor_polynomial =
            FpPolynomial::from_coefs(vec![point_neg, Self::Field::one()]); // X-x
        let (quotient_polynomial, remainder_polynomial) =
            f_eval_polynomial.div_rem(&divisor_polynomial); // P(X)-P(x) / (X-x)

        if !remainder_polynomial.is_zero() {
            return Err(eg!(PolyComSchemeError::PCSProveEvalError));
        }

        let proof_value = self.commit(quotient_polynomial).unwrap().0.value;

        let res = (
            evaluation,
            KZGEvalProof::<algebra::bls12_381::BLSG1>(proof_value),
        );
        Ok(res)
    }

    #[allow(non_snake_case)]
    fn verify_eval(
        &self,
        _transcript: &mut Transcript,
        C: &Self::Commitment,
        _degree: usize,
        x: &Self::Field,
        y: &Self::Field,
        proof: &Self::EvalProof,
    ) -> Result<()> {
        let g1_0 = self.public_parameter_group_1[0].clone();
        let g2_0 = self.public_parameter_group_2[0].clone();
        let g2_1 = self.public_parameter_group_2[1].clone();

        let x_minus_point_group_element_group_2 = &g2_1.sub(&g2_0.mul(x));

        // e(g1^{P(X)-P(x)},g2)
        let left_pairing_eval =
            algebra::bls12_381::Bls12381::pairing(&C.value.sub(&g1_0.mul(y)), &g2_0);

        // e(g1^{Q(X)},g1^{X-x})
        let right_pairing_eval = algebra::bls12_381::Bls12381::pairing(
            &proof.0,
            &x_minus_point_group_element_group_2,
        );

        // e(g1^{P(X)-P(x)},g2) == e(g1^{Q(X)},g2^{X-v})
        if left_pairing_eval == right_pairing_eval {
            Ok(())
        } else {
            Err(eg!(PolyComSchemeError::PCSProveEvalError))
        }
    }
}

#[cfg(test)]
mod tests_kzg_impl {
    use crate::commitments::kzg_poly_com::{
        KZGCommitmentScheme, KZGCommitmentSchemeBLS,
    };
    use crate::commitments::pcs::{HomomorphicPolyComElem, PolyComScheme};
    use algebra::groups::Group;
    use algebra::pairing::Pairing;

    use crate::polynomials::field_polynomial::FpPolynomial;
    use algebra::bls12_381::{BLSScalar, Bls12381, BLSG1};
    use algebra::groups::{GroupArithmetic, One, ScalarArithmetic};
    use itertools::Itertools;
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ruc::*;

    fn _check_public_parameters_generation<P: Pairing>() {
        let param_size = 5;
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let kzg_scheme = KZGCommitmentScheme::<P>::new(param_size, &mut prng);
        let g1_power1 = kzg_scheme.public_parameter_group_1[1].clone();
        let g2_power1 = kzg_scheme.public_parameter_group_2[1].clone();

        // Check parameters for G1
        for i in 0..param_size - 1 {
            let elem_first_group_1 = kzg_scheme.public_parameter_group_1[i].clone();
            let elem_next_group_1 = kzg_scheme.public_parameter_group_1[i + 1].clone();
            let elem_next_group_1_target =
                P::pairing(&elem_next_group_1, &P::G2::get_base());
            let elem_next_group_1_target_recomputed =
                P::pairing(&elem_first_group_1, &g2_power1);
            assert_eq!(
                elem_next_group_1_target_recomputed,
                elem_next_group_1_target
            );
        }

        // Check parameters for G2
        let elem_first_group_2 = kzg_scheme.public_parameter_group_2[0].clone();
        let elem_second_group_2 = kzg_scheme.public_parameter_group_2[1].clone();
        let elem_next_group_2_target =
            P::pairing(&P::G1::get_base(), &elem_second_group_2);
        let elem_next_group_2_target_recomputed =
            P::pairing(&g1_power1, &elem_first_group_2);

        assert_eq!(
            elem_next_group_2_target_recomputed,
            elem_next_group_2_target
        );
    }

    //This test is only for check the size of the CRS which is n + 3
    //it's g1, g2, s[g2] and s[g1],...,s^n[g1]
    fn _generation_of_crs<P: Pairing>() {
        let n = 1 << 5;
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let kzg_scheme = KZGCommitmentScheme::<P>::new(n, &mut prng);
        assert_eq!(kzg_scheme.public_parameter_group_1.len(), n + 1 );
        assert_eq!(kzg_scheme.public_parameter_group_2.len(), 2 );
    }

    #[test]
    pub fn test_homomorphic_poly_com_elem() {
        let mut prng = ChaChaRng::from_seed([0_u8; 32]);
        let pcs = KZGCommitmentSchemeBLS::new(20, &mut prng);
        type Field = BLSScalar;
        let one = Field::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = three.add(&one);
        let six = three.add(&three);
        let eight = six.add(&two);
        let poly1 = FpPolynomial::from_coefs(vec![two, three, six]);

        let (commitment1, poly1) = pcs.commit(poly1).unwrap();

        let poly2 = FpPolynomial::from_coefs(vec![one, eight, four]);

        let (commitment2, poly2) = pcs.commit(poly2).unwrap();

        // Add two polynomials
        let poly_sum = poly1.add(&poly2);
        let (commitment_sum, _) = pcs.commit(poly_sum).unwrap();
        let commitment_sum_computed = commitment1.op(&commitment2);
        assert_eq!(commitment_sum.value, commitment_sum_computed.value);

        let minus_two = two.neg();
        let minus_three = three.neg();
        let minus_six = six.neg();
        // Negating the coefficients of the polynomial
        let poly1_neg =
            FpPolynomial::from_coefs(vec![minus_two, minus_three, minus_six]);
        let (commitment_poly1_neg, _) = pcs.commit(poly1_neg).unwrap();
        let commitment_poly1_neg_hom = commitment1.inv();
        assert_eq!(commitment_poly1_neg_hom.value, commitment_poly1_neg.value);

        // Multiplying all the coefficients of a polynomial by some value
        let exponent = four.add(&one);
        let poly1_mult_5 = poly1.mul_scalar(&exponent);
        let (commitment_poly1_mult_5, _) = pcs.commit(poly1_mult_5).unwrap();
        let commitment_poly1_mult_5_hom = commitment1.exp(&exponent);
        assert_eq!(
            commitment_poly1_mult_5.value,
            commitment_poly1_mult_5_hom.value
        );
    }

    #[test]
    fn test_public_parameters() {
        _check_public_parameters_generation::<Bls12381>();
    }

    #[test]
    fn test_generation_of_crs() {
        _generation_of_crs::<Bls12381>();
    }

    #[test]
    fn test_commit() {
        let mut prng = ChaChaRng::from_seed([0_u8; 32]);
        let pcs = KZGCommitmentSchemeBLS::new(10, &mut prng);
        type Field = BLSScalar;
        let one = Field::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let six = three.add(&three);

        let fq_poly = FpPolynomial::from_coefs(vec![two, three, six]);
        let (commitment, open) = pcs.commit(fq_poly).unwrap();

        let coefs_poly_blsscalar = open.get_coefs_ref().iter().collect_vec();
        let mut expected_committed_value = BLSG1::get_identity();

        // Doing the multiexp by hand
        for (i, coef) in coefs_poly_blsscalar.iter().enumerate() {
            let g_i = pcs.public_parameter_group_1[i].clone();
            expected_committed_value = expected_committed_value.add(&g_i.mul(&coef));
        }
        assert_eq!(expected_committed_value, commitment.value);
    }

    #[test]
    fn test_eval() {
        let mut prng = ChaChaRng::from_seed([0_u8; 32]);
        let pcs = KZGCommitmentSchemeBLS::new(10, &mut prng);
        type Field = BLSScalar;
        let one = Field::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = three.add(&one);
        let six = three.add(&three);
        let seven = six.add(&one);
        let fq_poly = FpPolynomial::from_coefs(vec![one, two, four]);
        let point = one;
        let max_degree = fq_poly.degree();

        let mut not_needed_transcript = Transcript::new(b"transcript_not_needed");

        let degree = fq_poly.degree();
        let (commitment_value, opening) = pcs.commit(fq_poly).unwrap();

        // Check that an error is returned if the degree of the polynomial exceeds the maximum degree.
        let wrong_max_degree = 1;
        let res = pcs.prove_eval(
            &mut not_needed_transcript,
            &opening,
            &point,
            wrong_max_degree,
        );
        assert!(res.is_err());

        let (value, proof) = pcs
            .prove_eval(&mut not_needed_transcript, &opening, &point, max_degree)
            .unwrap();
        assert_eq!(value, seven);

        let res = pcs.verify_eval(
            &mut not_needed_transcript,
            &commitment_value,
            degree,
            &point,
            &value,
            &proof,
        );
        pnk!(res);

        let wrong_value_verif = one;
        let wrong_value_verif = pcs.verify_eval(
            &mut not_needed_transcript,
            &commitment_value,
            degree,
            &point,
            &wrong_value_verif,
            &proof,
        );
        assert!(wrong_value_verif.is_err());
    }
}
