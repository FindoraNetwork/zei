// This files implements PLONK/turbo PLONK SNARK for PLONK constraint systems
// The standard constraint system for m variables and n constraints is specified by selector vectors q_L, q_R, q_O, q_M, and
// input indices vectors a,b,c, such that an input x\in \FF^{m} satisfies the constraint system if for all i\in [n]
// x_{a_i} * q_L[i] + x_{b_i} * q_R[i] + x_{a_i} * x_{b_i} * q_M[i]  =  x_{c_i} * q_O[i]
// Note that this allows to specify arithmetic circuits gates by setting q_M[i] = 1 for MUL gates and
// q_L[i] = q_R[i] = 1 for ADD gates. But it is more general, as other combination can be added. Moreover,
// additional selector polynomials can be added with little cost to support more complex gates (Turbo PLONK).

// PLONK encodes the selector vectors as polynomials of degree n over field \FF. In addition, the input witness
// is expanded to 3 vectors of length n, representing left, right, and output values of each gate.
// This expansion must form a predefined permutation in [3*n] that correctly maps each value with the wiring of the circuit (
// for example, the output of i-th gate must be the left input j-th gate).
// The expanded witness vector is also represented by a polynomials f1(X), f2(X) and f3(X) of degree n.
// All polynomials are interpolated at points {g^i} for g a generator of an order n group H (<g> = H).
// Then, the constraint system is satisfiable if for all i in {0..n-1}
// f1(g^i) * q_L(g^i) + f2(g^i) * q_R(g^i) + f2(g^i) * f3(g^i) * q_M(g^i)  = f2(g^i) * q_O(g^i)
// AND the evaluation values of f1,f2,f3 define the permutation derived from vectors a, b, c.

// Let k_1, k_2 and k_3 such that k_i * H, are distinct cosets of H. That is, for all x \in k_iH
// x\not \in k_j*H for i!=j \in {1,2,3}. Let \pi be a permutation over [3n], define polynomials $\pi_1, \pi_2, \pi_3$ such that
// \pi_j(g^s) = k_l g^t if \pi[(j-1)*n + s] = (l-1)*n + t. That is, s-th element in group j, is mapped to t-th element in group l, for k, l \in {1,2,3},
// and s,t in {0..n-1}. Meaning, for example if j = 1 and l = 2, the left input of the s-th gate is the same wire as the right input of t-th gate.

// For random field elements gamma, delta, interpolate polynomial \Sigma such that
//  - \Sigma(g^{i+1}) = \Sigma(g^i) * prod_{j=1}^3[(f_j(g^i) + gamma * k_j g^i + delta)/ (f_j(g^i) + gamma * \pi_j(g^i) + delta)],
// for i in [n], and using \Sigma(0) = 1, for the base case.
// Hence, if f1, f2, f3 do not satisfy the permutation, then \Sigma(g^n)\neq 1 with overwhelming probability.
// This check is implemented as follows:
// - Verifier needs to check
//   + \Sigma(1) = 1,
//   + \Sigma(g^{i+1})* prod_{j=1}^3(f_j(g^i) + gamma * \pi_j(g^i) + delta) - \Sigma(g^i)* prod_{j=1}^3(f_j(g^i) + gamma * k_j*g^i + delta) = 0 for all i
// Or equivalently, that for all X in H:
//   + (\Sigma(X) -1)*(X^n -1)(X -1) = 0
//   + \Sigma(g*X)* prod_{j=1}^3(f_j(X) + gamma * \pi_j(X) + delta) - \Sigma(X)* prod_{j=1}^3(f_j(X) + gamma * k_j*X + delta) = 0

// For a random element alpha, them, the verifier checks the following equation over every element of X:

// P(X) = f1(X) * q_L(X) + f2(X) * q_R(X) + f2(X) * f3(X) * q_M(X)  - f2(X) * q_O(X) +
// alpha * (\Sigma(g*X)* prod_{j=1}^3(f_j(X) + gamma * \pi_j(X) + delta) - \Sigma(X)* prod_{j=1}^3(f_j(X) + gamma * k_j*X + delta)) +
// alpha^2*(\Sigma(X) -1)*(X^n -1)(X -1) = 0

// To check this equation, the prover computes the quotient polynomial Q(X) = P(X) / (X^n -1), and convinces the verifier that
// P(X) - Q(X)*(X^n-1) = 0 for all X in the **field**. For this purpose, a random challenge \beta is sampled uniformly random in the field,
// and the verifier checks that P(\beta) - Q(\beta)/(\beta^n -1) = 0.

// Preprocessing:
// Verifier and prover deterministically samples a group H of order n, k1,k2,k3, and compute polynomials q_L, q_R, q_M, q_O, \pi_1, \pi_2, \pi_3.
// The verifier store a commitment representation to each of them.

// Online:
// 1. Prover uses extended witness to interpolate polynomials f1,f2,f3, commit to them, and append the commitments to the proof.
// 2. The random challenges \gamma and \delta are sampled.
// 3. Prover interpolate polynomial \Sigma. Commit to it, and append the commitment to the proof.
// 4. The random challenge \alpha is sampled.
// 5. Prover computes polynomials P(X) and Q(X). It splits Q(X) into 3 degree-n polynomials Q0, Q1, Q2, commits, and append the commitment to the proof.
// 6. The random challenge \beta is sampled.
// 7. Prover computes linearization polynomial L(X):
//  - L(X): f1(\beta) * q_L(X) + f2(\beta) * q_R(X) + f1(\beta) * f2(\beta) * q_M(X) - f3(\beta) * q_O(X) +
//        \alpha * \Sigma(X)* prod_{j=1}^3(f_j(\beta) + gamma * k_j*\beta + delta)) -
//        \alpha * (\Sigma(g*\beta)* prod_{j=2}^3(f_j(\beta) + gamma * \pi_j(\beta) + delta)*gamma*\pi_3(X) +
//        \alpha^2 * Sigma(X) (\beta^n - 1)/(\beta - 1)
// 8. Prover appends f1(\beta), f2(\beta), f3(\beta), \pi_1(\beta), \pi_2(\beta), L(\beta), \Sigma(beta*g) to the proof, together with a batch
// proof of the correctness of these values, including a proof for Q(\beta) = Q0(\beta) + \beta^{n} * Q1(\beta) + \beta^{2*n} * Q2(\beta).
// 9. Verifier computes element Q(\beta) = P(\beta)/(\beta^n -1) =
//   (L(\beta) -  \alpha * (\Sigma(g*\beta)* prod_{j=2}^3(f_j(\beta) + gamma * \pi_j(\beta) + delta)*f3(\beta + delta) -
//   (\beta^n - 1)/(\beta - 1))/ (\beta^n -1).
// 10. Verifier homomorphically derives commitment to L(X).
// 11. Verifier batch verify the eval proofs for f1(\beta), f2(\beta), f3(\beta), \pi_1(\beta), \pi_2(\beta), L(\beta), \Sigma(beta*g),
// Q(\beta) =  = Q0(\beta) + \beta^{n} * Q1(\beta) + \beta^{2*n} * Q2(\beta).

// Adding Zero-Knowledge:
//  - each fi polynomial is randomized by adding a blinding polynomial of degree 1 that vanishes on H: fi(X) -> (bi1 + X bi2) * (X^n - 1) + fi(X)
//  - Since \Sigma(X) is opened in two points, we blind it with a degree 2 polynomial \Sigma(X) -> (b1 + X * b2 + X^2 * b3) * (X^n - 1) + \Sigma(X)
// Since, random polynomial vanishes on H, it does not affect correctness nor soundness of the protocol.

#[allow(non_snake_case)]
pub mod prover {
    use crate::commitments::pcs::{BatchProofEval, PolyComScheme};
    use crate::commitments::transcript::PolyComTranscript;
    use crate::plonk::errors::PlonkError;
    use crate::plonk::plonk_helpers::{
        combine_q_polys, derive_Q_eval_beta, eval_public_var_poly, hide_polynomial,
        linearization_commitment, linearization_polynomial_opening, split_Q_and_commit,
        PlonkChallenges, PublicVars_polynomial, Quotient_polynomial, Sigma_polynomial,
    };
    use crate::plonk::plonk_setup::{ConstraintSystem, ProverParams, VerifierParams};
    use crate::plonk::transcript::{
        transcript_get_plonk_challenge_alpha, transcript_get_plonk_challenge_beta,
        transcript_get_plonk_challenge_delta, transcript_get_plonk_challenge_gamma,
        transcript_init_plonk,
    };
    use crate::polynomials::field_polynomial::FpPolynomial;
    use algebra::groups::ScalarArithmetic;
    use merlin::Transcript;
    use rand_core::{CryptoRng, RngCore};
    use ruc::*;
    use std::time::SystemTime;

    /// A PlonkProof is generic on the polynomial commitment scheme, PCS.
    /// PCS is generic in the commitment group C, the eval proof type E, and Field elements F.
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

    /// PLONK Prover: it produces a proof that `witness` satisfies the constraint system `cs`
    /// Proof verifier must use a transcript with same state as prover and match the public parameters
    /// Returns PlonkErrorInvalidWitness if witness does not satisfy the the constraint system.
    /// It returns PlonkError if an error occurs in computing proof commitments, meaning parameters of the polynomial
    /// commitment scheme `pcs` do not match the constraint system parameters.
    /// # Example
    /// ```
    /// use poly_iops::plonk::protocol::prover::{prover, verifier};
    /// use poly_iops::plonk::plonk_setup::{preprocess_prover, preprocess_verifier, PlonkConstraintSystem};
    /// use poly_iops::commitments::kzg_poly_com::KZGCommitmentScheme;
    /// use poly_iops::commitments::pcs::PolyComScheme;
    /// use merlin::Transcript;
    /// use rand_chacha::ChaChaRng;
    /// use rand_core::{CryptoRng, RngCore, SeedableRng};
    /// use algebra::bls12_381::BLSScalar;
    /// use algebra::groups::{One, ScalarArithmetic};
    ///
    /// let mut prng = ChaChaRng::from_seed([1u8; 32]);
    /// let pcs = KZGCommitmentScheme::new(10, &mut prng);
    /// // circuit (x_0 + x_1);
    /// let mut cs = PlonkConstraintSystem::<BLSScalar>::new(3);
    /// cs.insert_add_gate(0, 1, 2);
    /// cs.pad();
    /// let one = BLSScalar::one();
    /// let two = one.add(&one);
    /// let three = two.add(&one);

    /// let common_seed = [0u8; 32];
    /// let proof = {
    /// // witness 1 + 2 = 3
    ///   let witness = [one,
    ///                 two,
    ///                 three];
    ///   let prover_params = preprocess_prover(&cs, &pcs, common_seed).unwrap();
    ///   let mut transcript = Transcript::new(b"Test");
    ///   prover(& mut prng, &mut transcript, &pcs, &cs, &prover_params, &witness).unwrap()
    /// };
    ///
    /// let verifier_params = preprocess_verifier(&cs, &pcs, common_seed).unwrap();
    /// let mut transcript = Transcript::new(b"Test");
    /// assert!(verifier(&mut transcript, &pcs, &cs, &verifier_params, &[], &proof).is_ok())
    /// ```
    pub fn prover<
        R: CryptoRng + RngCore,
        PCS: PolyComScheme,
        CS: ConstraintSystem<Field = PCS::Field>,
    >(
        prng: &mut R,
        transcript: &mut Transcript,
        pcs: &PCS,
        cs: &CS,
        params: &ProverParams<PCS>,
        witness: &[PCS::Field],
    ) -> Result<PlonkPf<PCS>> {
        println!(" In prover {:#?}", SystemTime::now());
        let online_values: Vec<PCS::Field> = cs
            .public_vars_witness_indices()
            .iter()
            .map(|index| witness[*index])
            .collect();
        println!(" Before Init transcript {:#?}", SystemTime::now());
        // Init transcript
        transcript_init_plonk::<_, PCS::Field>(
            transcript,
            &params.verifier_params,
            &online_values,
        );
        let mut challenges = PlonkChallenges::new();
        let n_constraints = cs.size();

        println!(" Before Prepare extended witness {:#?}", SystemTime::now());
        // Prepare extended witness
        let extended_witness = cs.extend_witness(witness);
        let IO = PublicVars_polynomial::<PCS>(&params, &online_values);

        println!(" Before 1 {:#?}", SystemTime::now());
        // 1. build witness polynomials, hide them and commit
        let root = &params.verifier_params.root;
        let n_wires_per_gate = cs.n_wires_per_gate();
        let mut witness_openings = vec![];
        let mut C_witness_polys = vec![];
        for i in 0..n_wires_per_gate {
            let mut f = FpPolynomial::ffti(
                root,
                &extended_witness[i * n_constraints..(i + 1) * n_constraints],
            );
            hide_polynomial(prng, &mut f, 1, n_constraints);
            let (C_f, O_f) = pcs.commit(f).c(d!(PlonkError::CommitmentError))?;
            transcript.append_commitment::<PCS::Commitment>(&C_f);
            witness_openings.push(O_f);
            C_witness_polys.push(C_f);
        }

        println!(" Before 2 {:#?}", SystemTime::now());
        // 2. get challenges gamma and delta
        let gamma = transcript_get_plonk_challenge_gamma(transcript, n_constraints);
        let delta = transcript_get_plonk_challenge_delta(transcript, n_constraints);
        challenges.insert_gamma_delta(gamma, delta).unwrap(); // safe unwrap

        println!(" Before 3 {:#?}", SystemTime::now());
        // 3. build sigma, hide it and commit
        let mut Sigma =
            Sigma_polynomial::<PCS, CS>(cs, params, &extended_witness, &challenges);
        hide_polynomial(prng, &mut Sigma, 2, n_constraints);
        let (C_Sigma, O_Sigma) = pcs.commit(Sigma).c(d!(PlonkError::CommitmentError))?;
        transcript.append_commitment::<PCS::Commitment>(&C_Sigma);

        println!(" Before 4 {:#?}", SystemTime::now());
        // 4. get challenge alpha
        let alpha = transcript_get_plonk_challenge_alpha(transcript, n_constraints);
        challenges.insert_alpha(alpha).unwrap();

        println!(" Before 5 {:#?}", SystemTime::now());
        // 5. build Q, split into `n_wires_per_gate` degree-(N+2) polynomials and commit
        // TODO: avoid the cloning when computing witness_polys and Sigma
        let witness_polys: Vec<FpPolynomial<PCS::Field>> = witness_openings
            .iter()
            .map(|open| pcs.polynomial_from_opening_ref(open))
            .collect();
        println!(" Before 5 a {:#?}", SystemTime::now());
        let Sigma = pcs.polynomial_from_opening_ref(&O_Sigma);
        println!(" Before 5 b {:#?}", SystemTime::now());
        let Q = Quotient_polynomial::<PCS, CS>(
            cs,
            params,
            &witness_polys,
            &Sigma,
            &challenges,
            &IO,
        )
        .c(d!())?;
        println!(" Before 5 c {:#?}", SystemTime::now());
        let (C_q_polys, O_q_polys) =
            split_Q_and_commit(pcs, &Q, n_wires_per_gate, n_constraints + 2).c(d!())?;
        println!(" Before 5 d {:#?}", SystemTime::now());
        for C_q in C_q_polys.iter() {
            transcript.append_commitment::<PCS::Commitment>(C_q);
        }

        println!(" After 8 {:#?}", SystemTime::now());

        println!(" Before 6 {:#?}", SystemTime::now());
        // 6. get challenge beta
        let beta = transcript_get_plonk_challenge_beta(transcript, n_constraints);

        println!(" Before 7 {:#?}", SystemTime::now());
        // 7. a) Evaluate the openings of witness/permutation polynomials at beta, and
        // evaluate the opening of Sigma(X) at point g * beta.
        let witness_polys_eval_beta: Vec<PCS::Field> = witness_openings
            .iter()
            .map(|open| pcs.eval_opening(open, &beta))
            .collect();
        let perms_eval_beta: Vec<PCS::Field> = params
            .extended_permutations
            .iter()
            .take(n_wires_per_gate - 1)
            .map(|open| pcs.eval_opening(open, &beta))
            .collect();

        let g_beta = root.mul(&beta);
        let Sigma_eval_g_beta = pcs.eval_opening(&O_Sigma, &g_beta);

        challenges.insert_beta(beta).unwrap();
        //  b). build linearization polynomial r_beta(X), and eval at beta
        let witness_polys_eval_beta_as_ref: Vec<&PCS::Field> =
            witness_polys_eval_beta.iter().collect();
        let perms_eval_beta_as_ref: Vec<&PCS::Field> = perms_eval_beta.iter().collect();
        let O_L = linearization_polynomial_opening::<PCS, CS>(
            cs,
            params,
            &O_Sigma,
            &witness_polys_eval_beta_as_ref[..],
            &perms_eval_beta_as_ref[..],
            &Sigma_eval_g_beta,
            &challenges,
        );
        for eval_beta in witness_polys_eval_beta.iter().chain(perms_eval_beta.iter()) {
            transcript.append_field_elem(eval_beta);
        }
        let beta = challenges.get_beta().unwrap();
        let L_eval_beta = pcs.eval_opening(&O_L, &beta);
        transcript.append_field_elem(&Sigma_eval_g_beta);
        transcript.append_field_elem(&L_eval_beta);

        println!(" Before 8 {:#?}", SystemTime::now());
        // 8. batch eval proofs
        let mut openings: Vec<&PCS::Opening> = witness_openings
            .iter()
            .chain(
                params
                    .extended_permutations
                    .iter()
                    .take(cs.n_wires_per_gate() - 1),
            )
            .collect();

        println!(" Before 8 a {:#?}", SystemTime::now());
        let O_q_combined = combine_q_polys(&O_q_polys, &beta, n_constraints + 2);
        openings.push(&O_q_combined);
        openings.push(&O_L);
        openings.push(&O_Sigma);

        println!(" Before 8 b {:#?}", SystemTime::now());
        // n_wires_per_gate opening proofs for witness polynomials; n_wires_per_gate-1 opening proofs
        // for the first n_wires_per_gate-1 extended permutations; 1 opening proof for each of [Q(X), L(X)]
        let mut points = vec![*beta; 2 * n_wires_per_gate + 1];
        // One opening proof for Sigma(X) at point g * beta
        points.push(g_beta);

        println!(" Before 8 c {:#?}", SystemTime::now());
        let (_, batch_eval_proof) = pcs
            .batch_prove_eval(
                transcript,
                &openings[..],
                &points[..],
                n_constraints + 2,
                None,
            )
            .c(d!(PlonkError::ProofError))?;

        println!(" After 8 {:#?}", SystemTime::now());

        println!(" Before return {:#?}", SystemTime::now());

        let proof = PlonkProof {
            C_witness_polys,
            C_q_polys,
            C_Sigma,
            witness_polys_eval_beta,
            Sigma_eval_g_beta,
            perms_eval_beta,
            L_eval_beta,
            batch_eval_proof,
        };
        println!("Proof {:#?}", proof);
        // return proof
        Ok(proof)
    }

    /// Verify a proof for a constraint system previously preprocessed into `cs_params`
    /// State of the transcript must match prover state of the transcript
    /// Polynomial Commitement parameters must be shared between prover and verifier.
    /// # Example
    /// ```
    /// // See plonk::prover::prover
    /// ```
    pub fn verifier<PCS: PolyComScheme, CS: ConstraintSystem<Field = PCS::Field>>(
        transcript: &mut Transcript,
        pcs: &PCS,
        cs: &CS,
        cs_params: &VerifierParams<PCS>,
        public_values: &[PCS::Field],
        proof: &PlonkPf<PCS>,
    ) -> Result<()> {
        transcript_init_plonk(transcript, cs_params, public_values);

        let mut challenges = PlonkChallenges::new();

        // 1. compute gamma and delta challenges
        for C in proof.C_witness_polys.iter() {
            transcript.append_commitment::<PCS::Commitment>(C);
        }
        let gamma = transcript_get_plonk_challenge_gamma(transcript, cs.size());
        let delta = transcript_get_plonk_challenge_delta(transcript, cs.size());
        challenges.insert_gamma_delta(gamma, delta).unwrap();

        // 2. compute alpha challenge
        transcript.append_commitment::<PCS::Commitment>(&proof.C_Sigma);
        let alpha = transcript_get_plonk_challenge_alpha(transcript, cs.size());
        challenges.insert_alpha(alpha).unwrap();
        for C_q in &proof.C_q_polys {
            transcript.append_commitment::<PCS::Commitment>(&C_q);
        }

        // 3. compute beta challenge
        let beta = transcript_get_plonk_challenge_beta(transcript, cs.size());
        challenges.insert_beta(beta).unwrap();
        for eval_beta in proof
            .witness_polys_eval_beta
            .iter()
            .chain(proof.perms_eval_beta.iter())
        {
            transcript.append_field_elem(eval_beta);
        }
        transcript.append_field_elem(&proof.Sigma_eval_g_beta);
        transcript.append_field_elem(&proof.L_eval_beta);

        let public_vars_eval_beta = eval_public_var_poly::<PCS>(
            cs_params,
            public_values,
            challenges.get_beta().unwrap(),
        );

        // 4. derive linearization polynomial commitment
        let witness_polys_eval_beta_as_ref: Vec<&PCS::Field> =
            proof.witness_polys_eval_beta.iter().collect();
        let perms_eval_beta_as_ref: Vec<&PCS::Field> =
            proof.perms_eval_beta.iter().collect();
        let C_L = linearization_commitment::<PCS, CS>(
            cs,
            cs_params,
            &proof.C_Sigma,
            &witness_polys_eval_beta_as_ref[..],
            &perms_eval_beta_as_ref[..],
            &proof.Sigma_eval_g_beta,
            &challenges,
        );
        // Note: for completeness steps 5 and 6 is analogous to getting Q(beta) in the proof, verify it, and then
        // check that P(\beta) - Q(\beta) * Z_H(\beta) (plus checking all eval proofs)

        // 5. derive value of Q(\beta) such that P(\beta) - Q(\beta) * Z_H(\beta) = 0
        let beta = challenges.get_beta().unwrap();
        let derived_q_eval_beta = derive_Q_eval_beta::<PCS>(
            cs_params,
            proof,
            &challenges,
            &public_vars_eval_beta,
        );
        let g_beta = beta.mul(&cs_params.root);

        // 6. verify batch eval proofs for witness/permutation polynomials evaluations at point beta, and Q(beta), L(beta), \Sigma(g*beta)
        let mut commitments: Vec<&PCS::Commitment> = proof
            .C_witness_polys
            .iter()
            .chain(
                cs_params
                    .extended_permutations
                    .iter()
                    .take(cs.n_wires_per_gate() - 1),
            )
            .collect();
        let C_q_combined =
            combine_q_polys(&proof.C_q_polys[..], &beta, cs_params.cs_size + 2);
        commitments.push(&C_q_combined);
        commitments.push(&C_L);
        commitments.push(&proof.C_Sigma);
        let mut points = vec![*beta; 2 * cs.n_wires_per_gate() + 1];
        points.push(g_beta);
        let mut values: Vec<PCS::Field> = proof
            .witness_polys_eval_beta
            .iter()
            .chain(proof.perms_eval_beta.iter())
            .cloned()
            .collect();
        values.push(derived_q_eval_beta);
        values.push(proof.L_eval_beta);
        values.push(proof.Sigma_eval_g_beta);
        pcs.batch_verify_eval(
            transcript,
            &commitments[..],
            cs_params.cs_size + 2,
            &points[..],
            &values[..],
            &proof.batch_eval_proof,
            None,
        )
        .c(d!(PlonkError::VerificationError))
    }
}

#[cfg(test)]
mod test {
    use crate::commitments::kzg_poly_com::KZGCommitmentScheme;
    use crate::commitments::pcs::PolyComScheme;
    use crate::plonk::plonk_setup::{
        preprocess_prover, preprocess_verifier, PlonkConstraintSystem,
    };
    use crate::plonk::protocol::prover::{prover, verifier, PlonkPf};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{One, ScalarArithmetic};
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    #[test]
    fn test_plonk_kzg() {
        let mut prng = ChaChaRng::from_seed([1u8; 32]);
        let pcs = KZGCommitmentScheme::new(30, &mut prng);
        test_plonk(&pcs, &mut prng);
    }

    fn test_plonk<PCS: PolyComScheme, R: CryptoRng + RngCore>(pcs: &PCS, prng: &mut R) {
        // circuit (x_0 + x_1) * (x_2 + x_3) + x_0;
        let mut cs = PlonkConstraintSystem::<PCS::Field>::new(8);
        cs.insert_add_gate(0, 1, 4);
        cs.insert_add_gate(2, 3, 5);
        cs.insert_mul_gate(4, 5, 6);
        cs.insert_add_gate(0, 6, 7);
        cs.pad();
        let one = PCS::Field::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);
        let seven = four.add(&three);
        let twenty_one = seven.mul(&three);
        let twenty_two = twenty_one.add(&one);

        let common_seed = [0u8; 32];
        let proof = {
            // witness (1+2) * (3+4) + 1= 22
            let witness = [one, two, three, four, three, seven, twenty_one, twenty_two];
            assert!(cs.verify_witness(&witness, &[]).is_ok());
            let prover_params = preprocess_prover(&cs, pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            prover(prng, &mut transcript, pcs, &cs, &prover_params, &witness).unwrap()
        };
        // test serialization
        let proof_json = serde_json::to_string(&proof).unwrap();
        let proof_de: PlonkPf<PCS> = serde_json::from_str(&proof_json).unwrap();
        assert_eq!(proof, proof_de);
        {
            let verifier_params = preprocess_verifier(&cs, pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            assert!(
                verifier(&mut transcript, pcs, &cs, &verifier_params, &[], &proof)
                    .is_ok()
            )
        }
    }

    #[test]
    fn test_plonk_with_constants_wires() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pcs = KZGCommitmentScheme::new(64, &mut prng);
        type F = BLSScalar;

        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);
        let seven = four.add(&three);
        let twenty_one = seven.mul(&three);
        let twenty_five = twenty_one.add(&four);

        // circuit (x_0 + 2) * (x_2 + x_3) + x_0*4;
        let mut cs = PlonkConstraintSystem::new(10);
        cs.insert_add_gate(0, 1, 4);
        cs.insert_add_gate(2, 3, 5);
        cs.insert_mul_gate(4, 5, 6);
        cs.insert_mul_gate(0, 7, 8);
        cs.insert_add_gate(6, 8, 9);
        cs.insert_constant(1, two);
        cs.insert_constant(7, four);
        cs.insert_dummy();
        cs.pad();

        let common_seed = [0u8; 32];
        let proof = {
            // witness (1+2) * (3+4) + 1*4= 25
            let witness = [
                one,
                two,
                three,
                four,
                three,
                seven,
                twenty_one,
                four,
                four,
                twenty_five,
            ];
            assert!(cs.verify_witness(&witness, &[]).is_ok());
            let prover_params = preprocess_prover(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            prover(
                &mut prng,
                &mut transcript,
                &pcs,
                &cs,
                &prover_params,
                &witness,
            )
            .unwrap()
        };

        {
            let verifier_params = preprocess_verifier(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            assert!(
                verifier(&mut transcript, &pcs, &cs, &verifier_params, &[], &proof)
                    .is_ok()
            )
        }
    }

    #[test]
    fn test_plonk_with_public_online_values() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pcs = KZGCommitmentScheme::new(64, &mut prng);
        type F = BLSScalar;
        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = two.add(&two);
        let seven = four.add(&three);
        let twenty_one = seven.mul(&three);
        let twenty_five = twenty_one.add(&four);

        // circuit (x_0 + y0) * (x_2 + 4) + x_0*y1;
        let mut cs = PlonkConstraintSystem::<F>::new(10);
        cs.insert_add_gate(0, 1, 4);
        cs.insert_add_gate(2, 3, 5);
        cs.insert_mul_gate(4, 5, 6);
        cs.insert_mul_gate(0, 7, 8);
        cs.insert_add_gate(6, 8, 9);
        cs.insert_constant(3, four);
        cs.prepare_io_variable(1);
        cs.prepare_io_variable(7);
        cs.pad();

        let online_vars = [two, four];

        let common_seed = [0u8; 32];
        let proof = {
            // witness (1+2) * (3+4) + 1*4= 25
            let witness = [
                one,
                two,
                three,
                four,
                three,
                seven,
                twenty_one,
                four,
                four,
                twenty_five,
            ];
            assert!(cs.verify_witness(&witness, &online_vars).is_ok());
            let prover_params = preprocess_prover(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            prover(
                &mut prng,
                &mut transcript,
                &pcs,
                &cs,
                &prover_params,
                &witness,
            )
            .unwrap()
        };
        {
            let verifier_params = preprocess_verifier(&cs, &pcs, common_seed).unwrap();
            let mut transcript = Transcript::new(b"TestPlonk");
            assert!(verifier(
                &mut transcript,
                &pcs,
                &cs,
                &verifier_params,
                &online_vars,
                &proof
            )
            .is_ok())
        }
    }
}
