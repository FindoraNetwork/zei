use crate::plonk::{
    constraint_system::ConstraintSystem,
    errors::PlonkError,
    indexer::{PlonkPK, PlonkPf, PlonkVK},
};
use crate::poly_commit::{
    field_polynomial::FpPolynomial,
    pcs::{HomomorphicPolyComElem, PolyComScheme},
};
use std::cmp::min;
use zei_algebra::prelude::*;

/// Build the base group.
pub(super) fn build_group<F: Scalar>(generator: &F, max_elems: usize) -> Result<Vec<F>> {
    let mut elems = vec![F::one()];
    let mut current_root = *generator;
    let mut n = 1;
    while current_root != F::one() {
        if n == max_elems {
            return Err(eg!(PlonkError::GroupNotFound(max_elems)));
        }
        elems.push(current_root);
        current_root.mul_assign(&generator);
        n += 1;
    }
    Ok(elems)
}

/// The data structure for challenges in Plonk.
#[derive(Default)]
pub(super) struct PlonkChallenges<F> {
    challenges: Vec<F>,
}

impl<F: Scalar> PlonkChallenges<F> {
    /// Create a challenges with capacity 4.
    pub(super) fn new() -> PlonkChallenges<F> {
        PlonkChallenges {
            challenges: Vec::with_capacity(4),
        }
    }

    /// Insert beta and gamma.
    pub(super) fn insert_beta_gamma(&mut self, beta: F, gamma: F) -> Result<()> {
        if self.challenges.is_empty() {
            self.challenges.push(beta);
            self.challenges.push(gamma);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Insert alpha.
    pub(super) fn insert_alpha(&mut self, alpha: F) -> Result<()> {
        if self.challenges.len() == 2 {
            self.challenges.push(alpha);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Insert zeta.
    pub(super) fn insert_zeta(&mut self, zeta: F) -> Result<()> {
        if self.challenges.len() == 3 {
            self.challenges.push(zeta);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Insert u.
    pub(super) fn insert_u(&mut self, u: F) -> Result<()> {
        if self.challenges.len() == 4 {
            self.challenges.push(u);
            Ok(())
        } else {
            Err(eg!())
        }
    }

    /// Return beta and gamma.
    pub(super) fn get_beta_gamma(&self) -> Result<(&F, &F)> {
        if self.challenges.len() > 1 {
            Ok((&self.challenges[0], &self.challenges[1]))
        } else {
            Err(eg!())
        }
    }

    /// Return alpha.
    pub(super) fn get_alpha(&self) -> Result<&F> {
        if self.challenges.len() > 2 {
            Ok(&self.challenges[2])
        } else {
            Err(eg!())
        }
    }

    /// Return zeta.
    pub(super) fn get_zeta(&self) -> Result<&F> {
        if self.challenges.len() > 3 {
            Ok(&self.challenges[3])
        } else {
            Err(eg!())
        }
    }

    /// Return u.
    pub(super) fn get_u(&self) -> Result<&F> {
        if self.challenges.len() > 4 {
            Ok(&self.challenges[4])
        } else {
            Err(eg!())
        }
    }
}

/// Return the PI polynomial.
pub(super) fn pi_poly<PCS: PolyComScheme>(
    prover_params: &PlonkPK<PCS>,
    pi: &[PCS::Field],
) -> FpPolynomial<PCS::Field> {
    let mut evals = Vec::with_capacity(prover_params.verifier_params.cs_size);
    for (i, _) in prover_params.group.iter().enumerate() {
        if let Some((pos, _)) = prover_params
            .verifier_params
            .public_vars_constraint_indices
            .iter()
            .find_position(|&&x| x == i)
        {
            evals.push(pi[pos])
        } else {
            evals.push(PCS::Field::zero());
        }
    }

    FpPolynomial::ffti(
        &prover_params.verifier_params.root,
        &evals,
        prover_params.verifier_params.cs_size,
    )
}

/// Add a random degree `num_hide_points`+`zeroing_degree` polynomial
/// that vanishes on X^{zeroing_degree} -1. Goal is to randomize
/// `polynomial` maintaining output values for elements in a sub group
/// of order N. Eg, when num_hide_points is 1, then it adds
/// (r1 + r2*X) * (X^zeroing_degree - 1) to `polynomial.
pub(super) fn hide_polynomial<R: CryptoRng + RngCore, F: Scalar>(
    prng: &mut R,
    polynomial: &mut FpPolynomial<F>,
    num_hide_points: usize,
    zeroing_degree: usize,
) -> Vec<F> {
    let mut blinds = Vec::new();
    for i in 0..num_hide_points + 1 {
        let mut blind = F::random(prng);
        blinds.push(blind);
        polynomial.add_coef_assign(&blind, i);
        blind = blind.neg();
        polynomial.add_coef_assign(&blind, zeroing_degree + i);
    }
    blinds
}

/// Build the z polynomial, by interpolating
/// z(\omega^{i+1}) = z(\omega^i)\prod_{j=1}^{n_wires_per_gate}(fj(\omega^i)
/// + \beta * k_j * \omega^i +\gamma)/(fj(\omega^i) + \beta * perm_j(\omega^i) +\gamma)
/// and setting z(1) = 1 for the base case
pub(super) fn z_poly<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    prover_params: &PlonkPK<PCS>,
    w: &[PCS::Field],
    challenges: &PlonkChallenges<PCS::Field>,
) -> FpPolynomial<PCS::Field> {
    let n_wires_per_gate = CS::n_wires_per_gate();
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();
    let mut z_evals = vec![];
    let perm = cs.compute_permutation();
    let n_constraints = w.len() / n_wires_per_gate;
    let mut prev = PCS::Field::one();
    z_evals.push(PCS::Field::one());
    let group = &prover_params.group[..];

    // computes permutation values
    let p_of_x =
        |perm_value: usize, n: usize, group: &[PCS::Field], k: &[PCS::Field]| -> PCS::Field {
            for (i, ki) in k.iter().enumerate().skip(1) {
                if perm_value < (i + 1) * n && perm_value >= i * n {
                    return ki.mul(&group[perm_value % n]);
                }
            }
            k[0].mul(&group[perm_value])
        };

    let k = &prover_params.verifier_params.k;
    for i in 0..n_constraints - 1 {
        // 1. numerator = prod_{j=1..n_wires_per_gate}(fj(\omega^i) + \beta * k_j * \omega^i + \gamma)
        // 2. denominator = prod_{j=1..n_wires_per_gate}(fj(\omega^i) + \beta * permj(\omega^i) +\gamma)
        let mut numerator = PCS::Field::one();
        let mut denominator = PCS::Field::one();
        for j in 0..n_wires_per_gate {
            let k_x = k[j].mul(&group[i]);
            let f_x = &w[j * n_constraints + i];
            let f_plus_beta_id_plus_gamma = &f_x.add(gamma).add(&beta.mul(&k_x));
            numerator.mul_assign(&f_plus_beta_id_plus_gamma);

            let p_x = p_of_x(perm[j * n_constraints + i], n_constraints, group, k);
            let f_plus_beta_perm_plus_gamma = f_x.add(gamma).add(&beta.mul(&p_x));
            denominator.mul_assign(&f_plus_beta_perm_plus_gamma);
        }

        // save s(\omega^{i+1}) = s(\omega^i)* a / b
        let denominator_inv = denominator.inv().unwrap();
        prev.mul_assign(&numerator.mul(&denominator_inv));
        z_evals.push(prev);
    }

    // interpolate the polynomial
    FpPolynomial::from_coefs(z_evals)
}

/// Compute the t polynomial.
pub(super) fn t_poly<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    cs: &CS,
    prover_params: &PlonkPK<PCS>,
    w_polys: &[FpPolynomial<PCS::Field>],
    z: &FpPolynomial<PCS::Field>,
    challenges: &PlonkChallenges<PCS::Field>,
    pi: &FpPolynomial<PCS::Field>,
) -> Result<FpPolynomial<PCS::Field>> {
    let n = cs.size();
    let m = cs.quot_eval_dom_size();
    let factor = m / n;
    if n * factor != m {
        return Err(eg!(PlonkError::SetupError));
    }
    let root_m = &prover_params.root_m;
    let k = &prover_params.verifier_params.k;

    // Compute the evaluations of w/pi/z polynomials on the coset k[1] * <root_m>.
    let w_polys_coset_evals: Vec<Vec<PCS::Field>> = w_polys
        .iter()
        .map(|poly| poly.coset_fft_with_unity_root(root_m, m, &k[1]))
        .collect();
    let pi_coset_evals = pi.coset_fft_with_unity_root(root_m, m, &k[1]);
    let z_coset_evals = z.coset_fft_with_unity_root(root_m, m, &k[1]);

    // Compute the evaluations of the quotient polynomial on the coset.
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let alpha_pow_2 = alpha.mul(alpha);
    let alpha_pow_3 = alpha_pow_2.mul(alpha);
    let alpha_pow_4 = alpha_pow_3.mul(alpha);
    let alpha_pow_5 = alpha_pow_4.mul(alpha);
    let mut t_coset_evals = vec![];

    for point in 0..m {
        let w_vals: Vec<&PCS::Field> = w_polys_coset_evals
            .iter()
            .map(|poly_coset_evals| &poly_coset_evals[point])
            .collect();
        let q_vals: Vec<&PCS::Field> = prover_params
            .q_coset_evals
            .iter()
            .map(|poly_coset_evals| &poly_coset_evals[point])
            .collect();
        // q * w
        let term1 = CS::eval_gate_func(&w_vals, &q_vals, &pi_coset_evals[point])?;

        // alpha * [z(X)\prod_j (fj(X) + beta * kj * X + gamma)]
        let mut term2 = alpha.mul(&z_coset_evals[point]);
        for j in 0..CS::n_wires_per_gate() {
            let tmp = w_polys_coset_evals[j][point]
                .add(gamma)
                .add(&beta.mul(&k[j].mul(&prover_params.coset_quotient[point])));
            term2.mul_assign(&tmp);
        }

        // alpha * [z(\omega * X)\prod_j (fj(X) + beta * perm_j(X) + gamma)]
        let mut term3 = alpha.mul(&z_coset_evals[(point + factor) % m]);
        for (w_poly_coset_evals, s_coset_evals) in w_polys_coset_evals
            .iter()
            .zip(prover_params.s_coset_evals.iter())
        {
            let tmp = &w_poly_coset_evals[point]
                .add(gamma)
                .add(&beta.mul(&s_coset_evals[point]));
            term3.mul_assign(&tmp);
        }

        // alpha^2 * (z(X) - 1) * L_1(X)
        let term4 = alpha_pow_2
            .mul(&prover_params.l1_coset_evals[point])
            .mul(&z_coset_evals[point].sub(&PCS::Field::one()));

        let qb_eval_point = prover_params.qb_coset_eval[point];

        // alpha^3 * qb(X) (w[1] (1 - w[1]))
        let w1_eval_point = w_polys_coset_evals[1][point];
        let term5 = alpha_pow_3
            .mul(&qb_eval_point)
            .mul(&w1_eval_point)
            .mul(&w1_eval_point.sub(&PCS::Field::one()));

        // alpha^4 * qb(X) (w[2] (1 - w[2]))
        let w2_eval_point = w_polys_coset_evals[2][point];
        let term6 = alpha_pow_4
            .mul(&qb_eval_point)
            .mul(&w2_eval_point)
            .mul(&w2_eval_point.sub(&PCS::Field::one()));

        // alpha^5 * qb(X) (w[3] (1 - w[3]))
        let w3_eval_point = w_polys_coset_evals[3][point];
        let term7 = alpha_pow_5
            .mul(&qb_eval_point)
            .mul(&w3_eval_point)
            .mul(&w3_eval_point.sub(&PCS::Field::one()));

        let numerator = term1
            .add(&term2)
            .add(&term4.sub(&term3))
            .add(&term5)
            .add(&term6)
            .add(&term7);
        t_coset_evals.push(numerator.mul(&prover_params.z_h_inv_coset_evals[point]));
    }

    let k_inv = k[1].inv().c(d!(PlonkError::DivisionByZero))?;
    Ok(FpPolynomial::coset_ffti(root_m, &t_coset_evals, &k_inv, m))
}

/// Compute r polynomial or commitment.
fn r_poly_or_comm<F: Scalar, PCSType: HomomorphicPolyComElem<Scalar = F>>(
    w: &[F],
    n: usize,
    q_polys_or_comms: &[PCSType],
    qb_poly_or_comm: &PCSType,
    k: &[F],
    last_s_poly_or_comm: &PCSType,
    z_poly_or_comm: &PCSType,
    w_polys_eval_zeta: &[&F],
    s_polys_eval_zeta: &[&F],
    z_eval_zeta_omega: &F,
    challenges: &PlonkChallenges<F>,
    t_polys_or_comms: &[PCSType],
    n_t_polys: usize,
) -> PCSType {
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let zeta = challenges.get_zeta().unwrap();

    let alpha_pow_2 = alpha.mul(alpha);
    let alpha_pow_3 = alpha_pow_2.mul(alpha);
    let alpha_pow_4 = alpha_pow_3.mul(alpha);
    let alpha_pow_5 = alpha_pow_4.mul(alpha);

    // 1. sum_{i=1..n_selectors} wi * qi(X)
    let mut l = q_polys_or_comms[0].mul(&w[0]);
    for i in 1..q_polys_or_comms.len() {
        l.add_assign(&q_polys_or_comms[i].mul(&w[i]));
    }

    // 2. z(X) [ alpha * prod_{j=1..n_wires_per_gate} (fj(zeta) + beta * kj * zeta + gamma)
    //              + alpha^2 * L1(zeta)]
    let z_scalar = compute_z_scalar_in_r(n, w_polys_eval_zeta, k, challenges);
    l.add_assign(&z_poly_or_comm.mul(&z_scalar));

    // 3. - perm_{n_wires_per_gate}(X) [alpha * z(zeta * omega) * beta
    //    * prod_{j=1..n_wires_per_gate-1}(fj(zeta) + beta * perm_j(zeta) + gamma)]
    let mut s_last_poly_scalar = alpha.mul(&z_eval_zeta_omega.mul(beta));
    for i in 0..w_polys_eval_zeta.len() - 1 {
        let tmp = w_polys_eval_zeta[i]
            .add(&beta.mul(s_polys_eval_zeta[i]))
            .add(gamma);
        s_last_poly_scalar.mul_assign(&tmp);
    }
    l.sub_assign(&last_s_poly_or_comm.mul(&s_last_poly_scalar));

    // 4. subtract the combined t polynomial
    let mut z_h_eval_zeta = zeta.pow(&[n as u64]);
    z_h_eval_zeta.sub_assign(&F::one());

    // 5. + qb(X) * (w[1] (1 - w[1]) + w[2] (1 - w[2]) + w[3] (1 - w[3]))
    let w1_part = w[1].mul(&(w[1] - &F::one())).mul(&alpha_pow_3);
    let w2_part = w[2].mul(&(w[2] - &F::one())).mul(&alpha_pow_4);
    let w3_part = w[3].mul(&(w[3] - &F::one())).mul(&alpha_pow_5);
    l.add_assign(&qb_poly_or_comm.mul(&w1_part.add(w2_part).add(w3_part)));

    let factor = zeta.pow(&[n_t_polys as u64]);
    let mut exponent = z_h_eval_zeta * factor;
    let mut t_poly_combined = t_polys_or_comms[0].clone().mul(&z_h_eval_zeta);
    for t_poly in t_polys_or_comms.iter().skip(1) {
        t_poly_combined.add_assign(&t_poly.mul(&exponent));
        exponent.mul_assign(&factor);
    }
    l.sub_assign(&t_poly_combined);
    l
}

/// Compute the r polynomial.
pub(super) fn r_poly<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    prover_params: &PlonkPK<PCS>,
    z: &FpPolynomial<PCS::Field>,
    w_polys_eval_zeta: &[&PCS::Field],
    s_polys_eval_zeta: &[&PCS::Field],
    z_eval_zeta_omega: &PCS::Field,
    challenges: &PlonkChallenges<PCS::Field>,
    t_polys: &[FpPolynomial<PCS::Field>],
    n_t_polys: usize,
) -> FpPolynomial<PCS::Field> {
    let w = CS::eval_selector_multipliers(w_polys_eval_zeta).unwrap(); // safe unwrap
    r_poly_or_comm::<PCS::Field, FpPolynomial<PCS::Field>>(
        &w,
        prover_params.group.len(),
        &prover_params.q_polys,
        &prover_params.qb_poly,
        &prover_params.verifier_params.k,
        &prover_params.s_polys[CS::n_wires_per_gate() - 1],
        z,
        w_polys_eval_zeta,
        s_polys_eval_zeta,
        z_eval_zeta_omega,
        challenges,
        t_polys,
        n_t_polys,
    )
}

/// Commit the r commitment.
pub(super) fn r_commitment<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
    verifier_params: &PlonkVK<PCS>,
    cm_z: &PCS::Commitment,
    w_polys_eval_zeta: &[&PCS::Field],
    s_polys_eval_zeta: &[&PCS::Field],
    z_eval_zeta_omega: &PCS::Field,
    challenges: &PlonkChallenges<PCS::Field>,
    t_polys: &[PCS::Commitment],
    n_t_polys: usize,
) -> PCS::Commitment {
    let w = CS::eval_selector_multipliers(w_polys_eval_zeta).unwrap(); // safe unwrap
    r_poly_or_comm::<PCS::Field, PCS::Commitment>(
        &w,
        verifier_params.cs_size,
        &verifier_params.cm_q_vec,
        &verifier_params.cm_qb,
        &verifier_params.k,
        &verifier_params.cm_s_vec[CS::n_wires_per_gate() - 1],
        cm_z,
        w_polys_eval_zeta,
        s_polys_eval_zeta,
        z_eval_zeta_omega,
        challenges,
        t_polys,
        n_t_polys,
    )
}

/// Compute sum_{i=1}^\ell w_i L_j(X), where j is the constraint
/// index for the i-th public value. L_j(X) = (X^n-1) / (X - \omega^j) is
/// the j-th lagrange base (zero for every X = \omega^i, except when i == j)
pub(super) fn eval_pi_poly<PCS: PolyComScheme>(
    verifier_params: &PlonkVK<PCS>,
    public_inputs: &[PCS::Field],
    eval_point: &PCS::Field,
) -> PCS::Field {
    let mut eval = PCS::Field::zero();
    // compute X ^ n - 1
    let x_to_n = eval_point.pow(&[verifier_params.cs_size as u64]);
    let num = x_to_n.sub(&PCS::Field::one());

    for ((constraint_index, public_value), lagrange_constant) in verifier_params
        .public_vars_constraint_indices
        .iter()
        .zip(public_inputs)
        .zip(verifier_params.lagrange_constants.iter())
    {
        // X - \omega^j j-th Lagrange denominator
        let root_to_j = verifier_params.root.pow(&[*constraint_index as u64]);
        let denominator = eval_point.sub(&root_to_j);
        let denominator_inv = denominator.inv().unwrap();
        let lagrange_i = lagrange_constant.mul(&denominator_inv);
        eval.add_assign(&lagrange_i.mul(public_value));
    }
    eval.mul(&num)
}

/// Compute constant c_j such that 1 = c_j * prod_{i != j} (\omega^j - \omega^i).
/// In such case, j-th lagrange base can be represented
/// by L_j(X) = c_j (X^n-1) / (X- \omega^j)
pub(super) fn compute_lagrange_constant<F: Scalar>(group: &[F], base_index: usize) -> F {
    let mut constant_inv = F::one();
    for (i, elem) in group.iter().enumerate() {
        if i == base_index {
            continue;
        }
        constant_inv.mul_assign(&group[base_index].sub(elem));
    }
    constant_inv.inv().unwrap()
}

/// compute the scalar factor of z(X) in the r poly.
/// prod(fi(\zeta) + \beta * k_i * \zeta + \gamma) * \alpha
///       + (\zeta^n - 1) / (\zeta-1) * \alpha^2
fn compute_z_scalar_in_r<F: Scalar>(
    n: usize,
    w_polys_eval_zeta: &[&F],
    k: &[F],
    challenges: &PlonkChallenges<F>,
) -> F {
    let n_wires_per_gate = w_polys_eval_zeta.len();
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let zeta = challenges.get_zeta().unwrap();

    // 1. alpha * prod_{i=1..n_wires_per_gate}(fi(\zeta) + \beta * k_i * \zeta + \gamma)
    let beta_zeta = beta.mul(zeta);
    let mut z_scalar = *alpha;
    for i in 0..n_wires_per_gate {
        let tmp = w_polys_eval_zeta[i].add(&k[i].mul(&beta_zeta)).add(gamma);
        z_scalar.mul_assign(&tmp);
    }

    // 2. alpha^2 * (beta^n - 1) / (beta - 1)
    let alpha_sq = alpha.mul(alpha);
    let zeta_pow_n = zeta.pow(&[n as u64]);
    let l1_eval_zeta = zeta_pow_n
        .sub(&F::one())
        .mul(&zeta.sub(&F::one()).inv().unwrap());

    z_scalar.add_assign(&l1_eval_zeta.mul(&alpha_sq));
    z_scalar
}

/// Evaluate the r polynomial at point \zeta.
pub(super) fn r_eval_zeta<PCS: PolyComScheme>(
    verifier_params: &PlonkVK<PCS>,
    proof: &PlonkPf<PCS>,
    challenges: &PlonkChallenges<PCS::Field>,
    pi_eval_zeta: &PCS::Field,
) -> PCS::Field {
    let zeta = challenges.get_zeta().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();

    let term0 = pi_eval_zeta;
    let mut term1 = alpha.mul(&proof.z_eval_zeta_omega);
    let n_wires_per_gate = &proof.w_polys_eval_zeta.len();
    for i in 0..n_wires_per_gate - 1 {
        let b = proof.w_polys_eval_zeta[i]
            .add(&beta.mul(&proof.s_polys_eval_zeta[i]))
            .add(gamma);
        term1.mul_assign(&b);
    }
    term1.mul_assign(&proof.w_polys_eval_zeta[n_wires_per_gate - 1].add(gamma));

    let one = PCS::Field::one();
    let zeta_n = zeta.pow(&[verifier_params.cs_size as u64]);
    let z_h_eval_zeta = zeta_n.sub(&one);
    let zeta_minus_one = zeta.sub(&one);
    let first_lagrange_eval_zeta = z_h_eval_zeta.mul(zeta_minus_one.inv().unwrap());
    let term2 = first_lagrange_eval_zeta.mul(alpha.mul(alpha));

    let term1_plus_term2 = term1.add(&term2);
    term1_plus_term2.sub(&term0)
}

/// Split the t polynomial into `n_wires_per_gate` degree-`n` polynomials and commit.
pub(crate) fn split_t_and_commit<R: CryptoRng + RngCore, PCS: PolyComScheme>(
    prng: &mut R,
    pcs: &PCS,
    t: &FpPolynomial<PCS::Field>,
    n_wires_per_gate: usize,
    n: usize,
) -> Result<(Vec<PCS::Commitment>, Vec<FpPolynomial<PCS::Field>>)> {
    let mut cm_t_vec = vec![];
    let mut t_polys = vec![];
    let coefs_len = t.get_coefs_ref().len();

    let zero = PCS::Field::zero();
    let mut prev_coef = zero;

    for i in 0..n_wires_per_gate {
        let coefs_start = i * n;
        let coefs_end = if i == n_wires_per_gate - 1 {
            coefs_len
        } else {
            (i + 1) * n
        };
        let mut coefs = if coefs_start < coefs_len {
            t.get_coefs_ref()[coefs_start..min(coefs_len, coefs_end)].to_vec()
        } else {
            vec![]
        };

        let rand = PCS::Field::random(prng);
        if i != n_wires_per_gate - 1 {
            coefs.resize(n + 1, zero);
            coefs[n].add_assign(&rand);
            coefs[0].sub_assign(&prev_coef);
        } else {
            if coefs.len() == 0 {
                coefs = vec![prev_coef.neg()];
            } else {
                coefs[0].sub_assign(&prev_coef);
            }
        }
        prev_coef = rand;

        let t_poly = FpPolynomial::from_coefs(coefs);
        let cm_t = pcs.commit(&t_poly).c(d!(PlonkError::CommitmentError))?;
        cm_t_vec.push(cm_t);
        t_polys.push(t_poly);
    }

    Ok((cm_t_vec, t_polys))
}

#[cfg(test)]
mod test {
    use crate::plonk::{
        constraint_system::TurboCS,
        helpers::{z_poly, PlonkChallenges},
        indexer::indexer,
    };
    use crate::poly_commit::kzg_poly_com::{KZGCommitmentScheme, KZGCommitmentSchemeBLS};
    use rand_chacha::ChaChaRng;
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};

    type F = BLSScalar;

    #[test]
    fn test_z_polynomial() {
        let mut cs = TurboCS::new();

        let zero = F::zero();
        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = three.add(&one);
        let five = four.add(&one);
        let six = five.add(&one);
        let seven = six.add(&one);

        let witness = [one, three, five, four, two, two, seven, six];
        cs.add_variables(&witness);

        cs.insert_add_gate(0 + 2, 4 + 2, 1 + 2);
        cs.insert_add_gate(1 + 2, 4 + 2, 2 + 2);
        cs.insert_add_gate(2 + 2, 4 + 2, 6 + 2);
        cs.insert_add_gate(3 + 2, 5 + 2, 7 + 2);
        cs.pad();

        let mut prng = ChaChaRng::from_seed([0_u8; 32]);
        let pcs = KZGCommitmentScheme::new(20, &mut prng);
        let params = indexer(&cs, &pcs).unwrap();

        let mut challenges = PlonkChallenges::<F>::new();
        challenges.insert_beta_gamma(one, zero).unwrap();
        let q =
            z_poly::<KZGCommitmentSchemeBLS, TurboCS<F>>(&cs, &params, &witness[..], &challenges);

        let q0 = q.coefs[0];
        assert_eq!(q0, one);
    }
}
