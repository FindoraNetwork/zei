use algebra::groups::{One, Scalar, ScalarArithmetic, Zero};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use ruc::*;

use crate::commitments::pcs::{BatchProofEval, PolyComScheme};
use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    helpers::{build_group, compute_lagrange_constant},
};
use crate::polynomials::field_polynomial::{primitive_nth_root_of_unity, FpPolynomial};
use crate::utils::u8_lsf_slice_to_u64_lsf_le_vec;

/// A PlonkProof is generic on the polynomial commitment scheme, PCS.
/// PCS is generic in the commitment group C, the eval proof type E, and Field elements F.
#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct PlonkProof<C, E, F> {
    pub(crate) C_witness_polys: Vec<C>,
    pub(crate) C_q_polys: Vec<C>, // splitted quotient polynomials
    pub(crate) C_Sigma: C,
    pub(crate) witness_polys_eval_beta: Vec<F>,
    pub(crate) Sigma_eval_g_beta: F,
    pub(crate) perms_eval_beta: Vec<F>,
    pub(crate) L_eval_beta: F,
    pub(crate) batch_eval_proof: BatchProofEval<C, E>,
}

pub type PlonkPf<PCS> = PlonkProof<
    <PCS as PolyComScheme>::Commitment,
    <PCS as PolyComScheme>::EvalProof,
    <PCS as PolyComScheme>::Field,
>;

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
pub struct PlonkProverParams<O, C, F> {
    pub(crate) selectors: Vec<O>,
    // perm1, perm2, ..., perm_{n_wires_per_gate}
    pub(crate) extended_permutations: Vec<O>,
    pub(crate) verifier_params: PlonkVerifierParams<C, F>,
    pub(crate) group: Vec<F>,
    // The evaluation domain for computing the quotient polynomial
    pub(crate) coset_quot: Vec<F>,
    pub(crate) root_m: F,
    pub(crate) L1: FpPolynomial<F>, // first lagrange basis
    pub(crate) Z_H: FpPolynomial<F>,
    pub(crate) selectors_coset_evals: Vec<Vec<F>>,
    pub(crate) perms_coset_evals: Vec<Vec<F>>,
    pub(crate) L1_coset_evals: Vec<F>,
    pub(crate) Z_H_inv_coset_evals: Vec<F>,
}

impl<O, C, F> PlonkProverParams<O, C, F> {
    pub fn get_verifier_params(self) -> PlonkVerifierParams<C, F> {
        self.verifier_params
    }

    pub fn get_verifier_params_ref(&self) -> &PlonkVerifierParams<C, F> {
        &self.verifier_params
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlonkVerifierParams<C, F> {
    pub(crate) selectors: Vec<C>,
    pub(crate) extended_permutations: Vec<C>,
    pub(crate) k: Vec<F>,
    pub(crate) root: F,
    pub(crate) cs_size: usize,
    pub(crate) public_vars_constraint_indices: Vec<usize>,
    pub(crate) lagrange_constants: Vec<F>,
}

pub type VerifierParams<PCS> = PlonkVerifierParams<
    <PCS as PolyComScheme>::Commitment,
    <PCS as PolyComScheme>::Field,
>;

pub fn perm_values<F: Scalar>(group: &[F], perm: &[usize], k: &[F]) -> Vec<F> {
    let n = group.len();
    perm.iter()
        .map(|pi| {
            for (i, ki) in k.iter().enumerate().skip(1) {
                if *pi < (i + 1) * n && *pi >= i * n {
                    return ki.mul(&group[pi % n]);
                }
            }
            group[pi % n]
        })
        .collect()
}

// Compute `n_wires_per_gate` different quadratic non-residue in F_q-{0}.
pub fn choose_ks<R: CryptoRng + RngCore, F: Scalar>(
    prng: &mut R,
    n_wires_per_gate: usize,
) -> Vec<F> {
    let mut k = vec![F::one()];
    let q_minus_1_half_lsf = F::field_size_minus_one_half();
    let q_minus_1_half_u64_lims_le = u8_lsf_slice_to_u64_lsf_le_vec(&q_minus_1_half_lsf);

    for _ in 1..n_wires_per_gate {
        loop {
            let ki = F::random(prng);
            if ki == F::zero() {
                continue;
            }
            if k.iter().all(|x| x != &ki)
                && ki.pow(&q_minus_1_half_u64_lims_le) != F::one()
            {
                k.push(ki);
                break;
            }
        }
    }
    k
}

pub type ProverParams<PCS> = PlonkProverParams<
    <PCS as PolyComScheme>::Opening,
    <PCS as PolyComScheme>::Commitment,
    <PCS as PolyComScheme>::Field,
>;

/// Precompute the prover parameters.
/// Before invoking preprocess_prover(), the constraint system `cs` should pad the number of
/// constraints to a power of two.
/// # Example
/// See plonk::prover::prover
#[allow(non_snake_case)]
pub fn preprocess_prover<
    PCS: PolyComScheme,
    CS: ConstraintSystem<Field = PCS::Field>,
>(
    cs: &CS,
    pcs: &PCS,
    prg_seed: [u8; 32],
) -> Result<ProverParams<PCS>> {
    let mut prng = ChaChaRng::from_seed(prg_seed);
    let n_wires_per_gate = CS::n_wires_per_gate();
    let n = cs.size();
    let m = cs.quot_eval_dom_size();
    let factor = m / n;
    if n * factor != m {
        return Err(eg!(PlonkError::SetupError));
    }
    // Compute evaluation domains.
    let root_m = primitive_nth_root_of_unity::<PCS::Field>(m)
        .c(d!(PlonkError::GroupNotFound(m)))?;
    let group_m = build_group(&root_m, m)?;
    let root = group_m[factor % m];
    let group = build_group(&root, n)?;
    // TODO: we can fix the set k for different circuits.
    let k = choose_ks::<_, PCS::Field>(&mut prng, n_wires_per_gate);
    let coset_quot = group_m.iter().map(|x| k[1].mul(x)).collect();

    use std::time::Instant;

    let timer = Instant::now();

    // Compute the openings, commitments, and point evaluations of the permutation polynomials.
    let perm = cs.compute_permutation();
    let mut p_values = Vec::with_capacity(n_wires_per_gate * n);
    for i in 0..n_wires_per_gate {
        p_values.extend(perm_values(&group, &perm[i * n..(i + 1) * n], &k));
    }
    let mut perms_coset_evals = vec![vec![]; n_wires_per_gate];
    let mut prover_extended_perms = vec![];
    let mut verifier_extended_perms = vec![];
    for i in 0..n_wires_per_gate {
        let perm = FpPolynomial::ffti(&root, &p_values[i * n..(i + 1) * n]);
        perms_coset_evals[i].extend(perm.coset_fft_with_unity_root(&root_m, m, &k[1]));
        let (C_perm, O_perm) = pcs.commit(perm).c(d!(PlonkError::SetupError))?;
        prover_extended_perms.push(O_perm);
        verifier_extended_perms.push(C_perm);
    }

    println!("perms: {}", timer.elapsed().as_secs_f64());

    let timer = Instant::now();
    // Compute the openings, commitments, and point evaluations of the selector polynomials.
    let mut selectors_coset_evals = vec![vec![]; cs.num_selectors()];
    let mut prover_selectors = vec![];
    let mut verifier_selectors = vec![];
    for (i, selector_coset_evals) in selectors_coset_evals.iter_mut().enumerate() {
        let q = FpPolynomial::ffti(&root, cs.selector(i)?);
        let timer = Instant::now();
        selector_coset_evals.extend(q.coset_fft_with_unity_root(&root_m, m, &k[1]));
        println!("coset_fft_with_unity_root: {}", timer.elapsed().as_secs_f64());
        let timer = Instant::now();
        let (C_q, O_q) = pcs.commit(q).c(d!(PlonkError::SetupError))?;
        println!("msm: {}", timer.elapsed().as_secs_f64());
        prover_selectors.push(O_q);
        verifier_selectors.push(C_q);
    }
    println!("selectors: {}", timer.elapsed().as_secs_f64());

    // Compute polynomials L1, Z_H, and point evaluations of L1 and Z_H^{-1}.

    let timer = Instant::now();
    let L1 = FpPolynomial::from_zeroes(&group[1..]);
    println!("L1 from_zeroes: {}", timer.elapsed().as_secs_f64());
    let timer = Instant::now();
    let L1_coset_evals = L1.coset_fft_with_unity_root(&root_m, m, &k[1]);
    println!("L1_coset_evals: {}", timer.elapsed().as_secs_f64());

    let mut Z_H_coefs = vec![PCS::Field::zero(); n + 1];
    Z_H_coefs[0] = PCS::Field::one().neg();
    Z_H_coefs[n] = PCS::Field::one();
    let Z_H = FpPolynomial::from_coefs(Z_H_coefs);
    let timer = Instant::now();
    let Z_H_inv_coset_evals = Z_H
        .coset_fft_with_unity_root(&root_m, m, &k[1])
        .into_iter()
        .map(|x| x.inv().unwrap())
        .collect();
    println!("Z_H: {}", timer.elapsed().as_secs_f64());

    let timer = Instant::now();
    let mut lagrange_constants = vec![];
    for constraint_index in cs.public_vars_constraint_indices().iter() {
        lagrange_constants.push(compute_lagrange_constant(&group, *constraint_index));
    }
    println!("L: {}", timer.elapsed().as_secs_f64());

    let verifier_params = PlonkVerifierParams {
        selectors: verifier_selectors,
        extended_permutations: verifier_extended_perms,
        k,
        root,
        cs_size: n,
        public_vars_constraint_indices: cs.public_vars_constraint_indices().to_vec(),
        lagrange_constants,
    };

    Ok(PlonkProverParams {
        selectors: prover_selectors,
        extended_permutations: prover_extended_perms,
        verifier_params,
        group,
        coset_quot,
        root_m,
        L1,
        Z_H,
        selectors_coset_evals,
        perms_coset_evals,
        L1_coset_evals,
        Z_H_inv_coset_evals,
    })
}

/// Precompute the verifier parameters.
/// Before invoking preprocess_verifier(), the constraint system `cs` should pad the number of
/// constraints to a power of two.
/// # Example
/// See plonk::prover::prover
pub fn preprocess_verifier<
    PCS: PolyComScheme,
    CS: ConstraintSystem<Field = PCS::Field>,
>(
    cs: &CS,
    pcs: &PCS,
    prg_seed: [u8; 32],
) -> Result<VerifierParams<PCS>> {
    let prover_params = preprocess_prover(cs, pcs, prg_seed).c(d!())?;
    Ok(prover_params.verifier_params)
}

#[cfg(test)]
mod test {
    use algebra::{
        bls12_381::BLSScalar,
        groups::{One, Scalar, ScalarArithmetic, Zero},
    };
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::plonk::setup::choose_ks;
    use crate::utils::u8_lsf_slice_to_u64_lsf_le_vec;

    type F = BLSScalar;

    #[test]
    fn test_choose_ks() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let m = 8;
        let k = choose_ks::<_, F>(&mut prng, m);
        let q_minus_one_half = F::field_size_minus_one_half();
        let q_minus_one_half_u64 = u8_lsf_slice_to_u64_lsf_le_vec(&q_minus_one_half);
        assert_eq!(k[0], F::one());
        assert!(k.iter().skip(1).all(|x| *x != F::zero()));
        assert!(k
            .iter()
            .skip(1)
            .all(|x| x.pow(&q_minus_one_half_u64) != F::one()));
        for i in 1..m {
            for j in 0..i {
                assert_ne!(k[i], k[j]);
            }
        }
    }
}
