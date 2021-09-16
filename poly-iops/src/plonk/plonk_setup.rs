use crate::commitments::pcs::PolyComScheme;
use crate::ioputils::u8_lsf_slice_to_u64_lsf_le_vec;
use crate::plonk::errors::PlonkError;
use crate::plonk::plonk_helpers::{build_group, compute_lagrange_constant};
use crate::polynomials::field_polynomial::{primitive_nth_root_of_unity, FpPolynomial};
use algebra::groups::{One, Scalar, ScalarArithmetic, Zero};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use ruc::*;

/// Trait for Turbo PLONK constraint systems.
pub trait ConstraintSystem {
    type Field: Scalar;
    /// Return the number of constraints in the system.
    /// `size should divide q-1 where q is the size of the prime field.
    /// This enables finding a multiplicative subgroup with order `size.
    fn size(&self) -> usize;

    /// Return number of variables in the constrain system
    fn num_vars(&self) -> usize;

    /// Return the wiring of the constrain system
    fn wiring(&self) -> &[Vec<usize>];

    /// Return the size of the evaluation domain for computing the quotient polynomial.
    /// `quot_eval_dom_size divides q-1 where q is the size of the prime field.
    /// `quot_eval_dom_size is larger than the degree of the quotient polynomial.
    /// `quot_eval_dom_size is a multiple of 'size'.
    fn quot_eval_dom_size(&self) -> usize;

    /// Return the number of wires in a single gate.
    fn n_wires_per_gate(&self) -> usize;

    /// Return the number of selectors.
    fn num_selectors(&self) -> usize;

    /// Compute the permutation implied by the copy constraints.
    fn compute_permutation(&self) -> Vec<usize> {
        let n = self.size();
        let n_wires_per_gate = self.n_wires_per_gate();
        let mut perm = vec![0usize; n_wires_per_gate * n];
        let mut marked = vec![false; self.num_vars()];
        let mut v = Vec::with_capacity(n_wires_per_gate * n);
        for wire_slice in self.wiring().iter() {
            v.extend_from_slice(wire_slice);
        }
        // form a cycle for each variable value
        // marked variables already processd
        // for each unmarked variable, find all position where this variable occurs to form a cycle.
        for (i, value) in v.iter().enumerate() {
            if marked[*value as usize] {
                continue;
            }
            let first = i;
            let mut prev = i;
            for (j, current_value) in v[i + 1..].iter().enumerate() {
                if current_value == value {
                    perm[prev] = i + 1 + j; //current index in v
                    prev = i + 1 + j;
                }
            }
            perm[prev] = first;
            marked[*value as usize] = true
        }
        perm
    }

    /// Compute the indices of the constraints related to public inputs.
    fn public_vars_constraint_indices(&self) -> &[usize];

    /// Compute the indices of the witnesses related to public inputs.
    fn public_vars_witness_indices(&self) -> &[usize];

    /// Map the witnesses into the wires of the circuit.
    /// The (i * size + j)-th output element is the value of the i-th wire on the j-th gate.
    fn extend_witness(&self, witness: &[Self::Field]) -> Vec<Self::Field> {
        let mut extended = Vec::with_capacity(self.n_wires_per_gate() * self.size());
        for wire_slice in self.wiring().iter() {
            for index in wire_slice.iter() {
                extended.push(witness[*index]);
            }
        }
        extended
    }

    /// Borrow the (index)-th selector vector.
    fn selector(&self, index: usize) -> Result<&[Self::Field]>;

    /// Evaluate the constraint equation given public input and the values of the wires and the selectors.
    fn eval_gate_func(
        &self,
        wire_vals: &[&Self::Field],
        sel_vals: &[&Self::Field],
        pub_input: &Self::Field,
    ) -> Result<Self::Field>;

    /// Given the wires values of a gate, evaluate the coefficients of the selectors in the
    /// constraint equation.
    fn eval_selector_multipliers(
        &self,
        wire_vals: &[&Self::Field],
    ) -> Result<Vec<Self::Field>>;
}

///
#[allow(non_snake_case)]
pub struct PlonkConstraintSystem<F> {
    pub selectors: Vec<Vec<F>>,
    pub wiring: [Vec<usize>; 3], // left, right, output, each of size `size
    pub num_vars: usize,
    pub size: usize,
    pub public_vars_constraint_indices: Vec<usize>,
    pub public_vars_witness_indices: Vec<usize>,
}

impl<F: Scalar> ConstraintSystem for PlonkConstraintSystem<F> {
    type Field = F;

    fn size(&self) -> usize {
        self.size
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn wiring(&self) -> &[Vec<usize>] {
        &self.wiring[..]
    }

    fn quot_eval_dom_size(&self) -> usize {
        if self.size > 4 {
            self.size * 4
        } else {
            self.size * 8
        }
    }

    fn n_wires_per_gate(&self) -> usize {
        3
    }

    fn num_selectors(&self) -> usize {
        self.selectors.len()
    }

    fn public_vars_constraint_indices(&self) -> &[usize] {
        &self.public_vars_constraint_indices
    }

    fn public_vars_witness_indices(&self) -> &[usize] {
        &self.public_vars_witness_indices
    }

    fn selector(&self, index: usize) -> Result<&[F]> {
        if index >= self.selectors.len() {
            return Err(eg!(PlonkError::FuncParamsError));
        }
        Ok(&self.selectors[index])
    }

    /// The equation is wl * ql + wr * qr + wl * wr * qm - wo * qo + qc + PI  = 0.
    fn eval_gate_func(
        &self,
        wire_vals: &[&Self::Field],
        sel_vals: &[&Self::Field],
        pub_input: &Self::Field,
    ) -> Result<Self::Field> {
        if wire_vals.len() < 3 || sel_vals.len() < 5 {
            return Err(eg!(PlonkError::FuncParamsError));
        }
        let left = sel_vals[0].mul(wire_vals[0]);
        let right = sel_vals[1].mul(wire_vals[1]);
        let mul = sel_vals[2].mul(&wire_vals[0].mul(wire_vals[1]));
        let out = sel_vals[3].mul(wire_vals[2]);
        let constant = sel_vals[4].add(pub_input);
        Ok(left.add(&right.add(&mul.add(&constant))).sub(&out))
    }

    /// The coefficients are (wl, wr, wl * wr, -wo, 1).
    fn eval_selector_multipliers(
        &self,
        wire_vals: &[&Self::Field],
    ) -> Result<Vec<Self::Field>> {
        if wire_vals.len() < 3 {
            return Err(eg!(PlonkError::FuncParamsError));
        }
        Ok(vec![
            *wire_vals[0],
            *wire_vals[1],
            wire_vals[0].mul(wire_vals[1]),
            wire_vals[2].neg(),
            F::one(),
        ])
    }
}

impl<F: Scalar> PlonkConstraintSystem<F> {
    pub fn new(num_vars: usize) -> PlonkConstraintSystem<F> {
        PlonkConstraintSystem {
            selectors: vec![vec![], vec![], vec![], vec![], vec![]], // q_L, q_R, q_M, q_O, q_C
            wiring: [vec![], vec![], vec![]],
            num_vars,
            size: 0,
            public_vars_constraint_indices: vec![],
            public_vars_witness_indices: vec![],
        }
    }

    pub fn insert_add_gate(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
    ) {
        self.insert_add_gate_with_inputs_multiplier(
            left_var_index,
            right_var_index,
            out_var_index,
            F::one(),
            F::one(),
        )
    }
    pub fn insert_add_gate_with_inputs_multiplier(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
        left_var_multiplier: F,
        right_var_multiplier: F,
    ) {
        assert!(
            left_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            right_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            out_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(left_var_multiplier);
        self.selectors[1].push(right_var_multiplier);
        self.selectors[2].push(F::zero());
        self.selectors[3].push(F::one());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(left_var_index);
        self.wiring[1].push(right_var_index);
        self.wiring[2].push(out_var_index);
        self.size += 1;
    }

    pub fn insert_mul_gate(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
    ) {
        self.insert_mul_gate_with_input_multiplier(
            left_var_index,
            right_var_index,
            out_var_index,
            F::one(),
        )
    }

    pub fn insert_mul_gate_with_input_multiplier(
        &mut self,
        left_var_index: usize,
        right_var_index: usize,
        out_var_index: usize,
        in_vars_multiplier: F,
    ) {
        assert!(
            left_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            right_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        assert!(
            out_var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(in_vars_multiplier);
        self.selectors[3].push(F::one());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(left_var_index);
        self.wiring[1].push(right_var_index);
        self.wiring[2].push(out_var_index);
        self.size += 1;
    }

    pub fn insert_boolean_gate(&mut self, var_index: usize) {
        assert!(
            var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(F::one());
        self.selectors[3].push(F::one());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(var_index);
        self.wiring[1].push(var_index);
        self.wiring[2].push(var_index);
        self.size += 1;
    }

    /// Insert a constant in the constraint system
    pub fn insert_constant(&mut self, var_index: usize, constant: F) {
        assert!(
            var_index < self.num_vars,
            "Variable index out of Constraint System bound"
        );
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(F::zero());
        self.selectors[3].push(F::one());
        self.selectors[4].push(constant);
        self.wiring[0].push(0);
        self.wiring[1].push(0);
        self.wiring[2].push(var_index);
        self.size += 1;
    }

    /// Insert constraint of a public IO value to be decided online
    pub fn prepare_io_variable(&mut self, var_index: usize) {
        self.public_vars_constraint_indices.push(self.size);
        self.public_vars_witness_indices.push(var_index);
        self.insert_constant(var_index, F::zero());
    }

    /// Insert a dummy constraint in the constraint system
    pub fn insert_dummy(&mut self) {
        self.selectors[0].push(F::zero());
        self.selectors[1].push(F::zero());
        self.selectors[2].push(F::zero());
        self.selectors[3].push(F::zero());
        self.selectors[4].push(F::zero());
        self.wiring[0].push(0);
        self.wiring[1].push(0);
        self.wiring[2].push(0);
        self.size += 1;
    }

    /// Pad the number of constraints to a power of two.
    pub fn pad(&mut self) {
        let n = self.size.next_power_of_two();
        let diff = n - self.size();
        let zeroes_scalar = vec![F::zero(); diff];
        let zeroes = vec![0; diff];
        self.selectors[0].extend(zeroes_scalar.clone());
        self.selectors[1].extend(zeroes_scalar.clone());
        self.selectors[2].extend(zeroes_scalar.clone());
        self.selectors[3].extend(zeroes_scalar.clone());
        self.selectors[4].extend(zeroes_scalar);
        self.wiring[0].extend(zeroes.clone());
        self.wiring[1].extend(zeroes.clone());
        self.wiring[2].extend(zeroes);
        self.size += diff;
    }

    fn get_left_witness_index(&self, cs_index: usize) -> usize {
        assert!(cs_index < self.size);
        self.wiring[0][cs_index] as usize
    }

    fn get_right_witness_index(&self, cs_index: usize) -> usize {
        assert!(cs_index < self.size);
        self.wiring[1][cs_index] as usize
    }

    fn get_out_witness_index(&self, cs_index: usize) -> usize {
        assert!(cs_index < self.size);
        self.wiring[2][cs_index] as usize
    }

    pub fn verify_witness(&self, witness: &[F], online_vars: &[F]) -> Result<()> {
        if witness.len() != self.num_vars {
            return Err(eg!());
        }
        if online_vars.len() != self.public_vars_witness_indices.len()
            || online_vars.len() != self.public_vars_constraint_indices.len()
        {
            return Err(eg!());
        }
        for cs_index in 0..self.size() {
            let mut public_online = F::zero();
            // check if constraint constrains a public variable
            // search constraint index in online vars
            for ((c_i, w_i), online_var) in self
                .public_vars_constraint_indices
                .iter()
                .zip(self.public_vars_witness_indices.iter())
                .zip(online_vars.iter())
            {
                if *c_i == cs_index {
                    // found
                    public_online = *online_var;
                    if witness[*w_i] != *online_var {
                        return Err(eg!());
                    }
                }
            }
            let left_wire_value = &witness[self.get_left_witness_index(cs_index)];
            let right_wire_value = &witness[self.get_right_witness_index(cs_index)];
            let out_wire_value = &witness[self.get_out_witness_index(cs_index)];
            let add = left_wire_value
                .mul(&self.selectors[0][cs_index])
                .add(&right_wire_value.mul(&self.selectors[1][cs_index]));
            let mul = right_wire_value
                .mul(left_wire_value)
                .mul(&self.selectors[2][cs_index]);
            let out = out_wire_value.mul(&self.selectors[3][cs_index]);
            let constant = &self.selectors[4][cs_index];
            let constant_add = constant.add(&public_online);
            if add.add(&mul.add(&constant_add)).sub(&out) != F::zero() {
                return Err(eg!());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
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
#[allow(non_snake_case)]
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
/// ```
/// // See plonk::prover::prover
/// ```
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
    let n_wires_per_gate = cs.n_wires_per_gate();
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

    // Compute the openings, commitments, and point evaluations of the selector polynomials.
    let mut selectors_coset_evals = vec![vec![]; cs.num_selectors()];
    let mut prover_selectors = vec![];
    let mut verifier_selectors = vec![];
    for (i, selector_coset_evals) in selectors_coset_evals.iter_mut().enumerate() {
        let q = FpPolynomial::ffti(&root, cs.selector(i)?);
        selector_coset_evals.extend(q.coset_fft_with_unity_root(&root_m, m, &k[1]));
        let (C_q, O_q) = pcs.commit(q).c(d!(PlonkError::SetupError))?;
        prover_selectors.push(O_q);
        verifier_selectors.push(C_q);
    }

    // Compute polynomials L1, Z_H, and point evaluations of L1 and Z_H^{-1}.
    let L1 = FpPolynomial::from_zeroes(&group[1..]);
    let L1_coset_evals = L1.coset_fft_with_unity_root(&root_m, m, &k[1]);
    let mut Z_H_coefs = vec![PCS::Field::zero(); n + 1];
    Z_H_coefs[0] = PCS::Field::one().neg();
    Z_H_coefs[n] = PCS::Field::one();
    let Z_H = FpPolynomial::from_coefs(Z_H_coefs);
    let Z_H_inv_coset_evals = Z_H
        .coset_fft_with_unity_root(&root_m, m, &k[1])
        .into_iter()
        .map(|x| x.inv().unwrap())
        .collect();

    let mut lagrange_constants = vec![];
    for constraint_index in cs.public_vars_constraint_indices().iter() {
        lagrange_constants.push(compute_lagrange_constant(&group, *constraint_index));
    }

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
/// ```
/// // See plonk::prover::prover
/// ```
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
    use crate::ioputils::u8_lsf_slice_to_u64_lsf_le_vec;
    use crate::plonk::plonk_setup::{
        choose_ks, ConstraintSystem, PlonkConstraintSystem,
    };
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{One, Scalar, ScalarArithmetic, Zero};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    type F = BLSScalar;

    #[test]
    fn test_permutation() {
        let cs = PlonkConstraintSystem::<F> {
            selectors: vec![vec![], vec![], vec![], vec![]],
            wiring: [vec![0, 1, 3], vec![3, 2, 2], vec![4, 3, 5]],
            num_vars: 6,
            size: 3,
            public_vars_constraint_indices: vec![],
            public_vars_witness_indices: vec![],
        };
        let perm = cs.compute_permutation();
        assert_eq!(perm, vec![0, 1, 3, 7, 5, 4, 6, 2, 8]);
    }

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

    #[test]
    fn test_circuit_cs() {
        let mut cs = PlonkConstraintSystem::<F>::new(3);
        let zero = F::zero();
        let one = F::one();
        // no constrains, every witness is valid
        assert!(cs.verify_witness(&[zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, zero, one], &[]).is_ok());

        cs.insert_add_gate(0, 1, 2);
        assert!(cs.verify_witness(&[zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, zero, one], &[]).is_err());
        assert!(cs.verify_witness(&[zero], &[]).is_err());

        cs.insert_mul_gate(2, 0, 1);
        assert!(cs.verify_witness(&[zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, one, one], &[]).is_err());

        let mut cs = PlonkConstraintSystem::<F>::new(4);
        // no constrains, every witness is valid
        assert!(cs.verify_witness(&[zero, zero, zero, zero], &[]).is_ok());
        // x + y = w
        // y * w = z
        cs.insert_add_gate(0, 1, 2);
        cs.insert_mul_gate(1, 2, 3);
        assert!(cs.verify_witness(&[zero, zero, zero, zero], &[]).is_ok());
        assert!(cs.verify_witness(&[zero, one, one, one], &[]).is_ok());
        let two = one.add(&one);
        assert!(cs.verify_witness(&[one, one, two, two], &[]).is_ok());
        let three = two.add(&one);
        assert!(cs.verify_witness(&[two, one, three, two], &[]).is_err());
        assert!(cs.verify_witness(&[two, one, three, three], &[]).is_ok());
    }
}
