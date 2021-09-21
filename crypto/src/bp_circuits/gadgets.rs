use crate::bp_circuits::cloak::CloakVariable;
use algebra::groups::{Scalar as _, ScalarArithmetic};
use algebra::ristretto::RistrettoScalar as Scalar;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, R1CSError, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};
use ruc::*;
use std::iter;

pub(crate) fn cloak_merge_gadget<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    sorted: &[CloakVariable],
    intermediate: &[CloakVariable],
    merged: &[CloakVariable],
) -> Result<usize> {
    let in1 = sorted[0];
    let out1 = merged[0];
    let mut n_gates = 0;
    let l = sorted.len();
    if l == 0 {
        return Ok(0);
    }
    if l == 1 {
        // sorted and merges should be the same
        cs.constrain(in1.amount - out1.amount);
        cs.constrain(in1.asset_type - out1.asset_type);
        return Ok(0);
    }
    assert_eq!(l, merged.len());
    assert_eq!(l, intermediate.len() + 2);
    let first_in = sorted[0];
    let in1iter = iter::once(&first_in).chain(intermediate.iter());
    let in2iter = sorted[1..l].iter();
    let out1iter = merged[0..l - 1].iter();
    let out2iter = intermediate.iter().chain(iter::once(&merged[l - 1]));

    for (((in1, in2), out1), out2) in in1iter.zip(in2iter).zip(out1iter).zip(out2iter) {
        n_gates += gate_mix(cs, *in1, *in2, *out1, *out2).c(d!())?;
    }

    Ok(n_gates)
}

/// I implement the mix gate gadget, proving that either
/// in1 = out1 and in2 = out2  if in1 and in2 have different types or
/// out1 = 0 and out2 = in1 + in2 if in1 and in2 have same type
/// I return the number of left wires created
pub(super) fn gate_mix<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    in1: CloakVariable,
    in2: CloakVariable,
    out1: CloakVariable,
    out2: CloakVariable,
) -> Result<usize> {
    cs.specify_randomized_constraints(move |cs| {
        let w1 = cs.challenge_scalar(b"mix challenge1");
        let w2 = cs.challenge_scalar(b"mix challenge2");
        let w3 = cs.challenge_scalar(b"mix challenge3");
        let (_, _, out) = cs.multiply(
            (in1.amount - out1.amount) +          // quantity maintains
                (in1.asset_type - out1.asset_type) * w1 + // asset type maintains in first input
                (in2.amount - out2.amount) * w2 + // quantity maintains
                (in2.asset_type - out2.asset_type) * w3, // asset type maintains in second input
            out1.amount + // or out1 is 0
                (in1.asset_type - in2.asset_type) * w1 + // or in flavors are equal
                (out2.amount - in1.amount - in2.amount) * w2 // or out2 is the sum of the inputs
                + (out2.asset_type - in1.asset_type) * w3, // in 1 and out2 have same asset type
        );
        cs.constrain(out.into());
        Ok(())
    })
    .c(d!())?;
    Ok(1usize)
}

/// Prove shuffling of a list of CloakValues
/// Return the number of gates created
pub(super) fn cloak_shuffle_gadget<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    input: Vec<CloakVariable>,
    permuted: Vec<CloakVariable>,
) -> Result<usize> {
    let l = input.len();
    if l != permuted.len() {
        return Err(eg!(R1CSError::GadgetError {
            description: "list shuffle error, input and output list differ in length"
                .to_string(),
        }));
    }
    if l == 0 {
        return Ok(0usize);
    }
    if l == 1 {
        cs.constrain(permuted[0].amount - input[0].amount);
        cs.constrain(permuted[0].asset_type - input[0].asset_type);
        return Ok(0usize);
    }

    cs.specify_randomized_constraints(move |cs| {
        let challenge = cs.challenge_scalar(b"k-value shuffle challenge");
        let mut single_input = Vec::with_capacity(l);
        let mut single_perm = Vec::with_capacity(l);

        for (in_var, perm_var) in input.iter().zip(permuted.iter()) {
            //compute a single representative for the pair
            let (single_in, single_pe, _) = cs.multiply(
                in_var.amount + challenge * in_var.asset_type,
                perm_var.amount + challenge * perm_var.asset_type,
            );
            single_input.push(single_in);
            single_perm.push(single_pe);
        }

        list_shuffle(cs, &single_input[..], &single_perm[..])
            .c(d!())
            .map_err(|e| {
                e.print(None);
                R1CSError::GadgetError {
                    description: e.to_string(),
                }
            })
            .map(|_| ())
    })
    .c(d!())?;

    // list_shuffle does 2*(l-1) multiplications
    Ok(l + 2 * (l - 1))
}

/// Prove shuffling of a list of values
/// Return the number of left wires created
pub(super) fn list_shuffle<CS: RandomizedConstraintSystem>(
    cs: &mut CS,
    input: &[Variable],
    permuted: &[Variable],
) -> Result<usize> {
    let l = input.len();
    if l != permuted.len() {
        return Err(eg!(R1CSError::GadgetError {
            description: "list shuffle error, input and output list differ in length"
                .to_string(),
        }));
    }
    if l == 0 {
        return Ok(0usize);
    }
    if l == 1 {
        cs.constrain(permuted[0] - input[0]);
        return Ok(0usize);
    }

    let challenge = cs.challenge_scalar(b"shuffle challenge");

    // Make last x multiplier for i = l-1 and l-2
    let (_, _, last_mulx_out) =
        cs.multiply(input[l - 1] - challenge, input[l - 2] - challenge);

    // Make multipliers for x from i == [0, l-3]
    let first_mulx_out = (0..l - 2).rev().fold(last_mulx_out, |prev_out, i| {
        let (_, _, o) = cs.multiply(prev_out.into(), input[i] - challenge);
        o
    });

    // Make last y multiplier for i = l-1 and l-2
    let (_, _, last_muly_out) =
        cs.multiply(permuted[l - 1] - challenge, permuted[l - 2] - challenge);

    // Make multipliers for y from i == [0, l-3]
    let first_muly_out = (0..l - 2).rev().fold(last_muly_out, |prev_out, i| {
        let (_, _, o) = cs.multiply(prev_out.into(), permuted[i] - challenge);
        o
    });

    // Constrain last x mul output and last y mul output to be equal
    cs.constrain(first_mulx_out - first_muly_out);

    // l-1 multiplications for input + l-1 multiplication for permuted
    Ok(2 * (l - 1))
}

/// I prove that value is in [0..2^64-1]
pub fn range_proof_64<CS: ConstraintSystem>(
    cs: &mut CS,
    mut var: LinearCombination,
    value: Option<Scalar>,
) -> Result<usize> {
    let mut exp_2 = Scalar::from_u32(1);
    let n_usize = 64usize;
    let value_bytes = value.as_ref().map(|v| v.to_bytes());
    for i in 0..n_usize {
        // Create low-level variables and add them to constraints
        let (a, b, o) = match value_bytes.as_ref() {
            Some(bytes) => {
                let index = i >> 3;
                if index > bytes.len() {
                    // This could happen due to the scalar's representation
                    return Err(eg!(R1CSError::FormatError));
                }
                let bit = ((bytes[index] >> (i & 7)) & 1u8) as i8;
                let assignment = (
                    Scalar::from_u32(1 - bit as u32),
                    Scalar::from_u32(bit as u32),
                );
                cs.allocate_multiplier(Some(assignment).map(|(a, b)| (a.0, b.0)))
            }
            None => cs.allocate_multiplier(None),
        }
        .c(d!())?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        cs.constrain(a + (b - 1u64));

        // Add `-b_i*2^i` to the linear combination
        // in order to form the following constraint by the end of the loop:
        // v = Sum(b_i * 2^i, i = 0..n-1)
        var = var - b * exp_2.0;
        exp_2 = exp_2.add(&exp_2);
    }
    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
    cs.constrain(var);

    // one multiplication gate per bit
    Ok(n_usize)
}

#[cfg(test)]
mod test {
    use crate::bp_circuits::cloak::{
        allocate_cloak_vector, CloakCommitment, CloakValue, CloakVariable,
    };
    use algebra::groups::Scalar;
    use algebra::ristretto::RistrettoScalar;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn test_cloak_merge() {
        let pc_gens = PedersenGens::default();

        let sorted_values = vec![
            CloakValue::new(RistrettoScalar::from_u32(1), RistrettoScalar::from_u32(10)),
            CloakValue::new(RistrettoScalar::from_u32(3), RistrettoScalar::from_u32(10)),
            CloakValue::new(RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(11)),
            CloakValue::new(RistrettoScalar::from_u32(5), RistrettoScalar::from_u32(11)),
            CloakValue::new(RistrettoScalar::from_u32(4), RistrettoScalar::from_u32(12)),
        ];

        let mid_values = vec![
            CloakValue::new(RistrettoScalar::from_u32(4), RistrettoScalar::from_u32(10)),
            CloakValue::new(RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(11)),
            CloakValue::new(RistrettoScalar::from_u32(7), RistrettoScalar::from_u32(11)),
        ];
        let out_values = vec![
            CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(10)),
            CloakValue::new(RistrettoScalar::from_u32(4), RistrettoScalar::from_u32(10)),
            CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(11)),
            CloakValue::new(RistrettoScalar::from_u32(7), RistrettoScalar::from_u32(11)),
            CloakValue::new(RistrettoScalar::from_u32(4), RistrettoScalar::from_u32(12)),
        ];

        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let sorted = allocate_cloak_vector(
            &mut prover,
            Some(&sorted_values),
            sorted_values.len(),
        )
        .unwrap();
        let mid =
            allocate_cloak_vector(&mut prover, Some(&mid_values), mid_values.len())
                .unwrap();
        let added =
            allocate_cloak_vector(&mut prover, Some(&out_values), out_values.len())
                .unwrap();
        let num_wires =
            super::cloak_merge_gadget(&mut prover, &sorted[..], &mid[..], &added[..])
                .unwrap();
        let bp_gens = BulletproofGens::new(
            (num_wires + 2 * (sorted.len() + mid.len() + added.len()))
                .next_power_of_two(),
            1,
        );
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let sorted =
            allocate_cloak_vector(&mut verifier, None, sorted_values.len()).unwrap();
        let mid = allocate_cloak_vector(&mut verifier, None, mid_values.len()).unwrap();
        let added =
            allocate_cloak_vector(&mut verifier, None, out_values.len()).unwrap();
        let num_wires =
            super::cloak_merge_gadget(&mut verifier, &sorted[..], &mid[..], &added[..])
                .unwrap();
        let bp_gens = BulletproofGens::new(
            (num_wires + 2 * (sorted.len() + mid.len() + added.len()))
                .next_power_of_two(),
            1,
        );
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

        // test the same using commitments
        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let sorted_coms_vars: Vec<(CloakCommitment, CloakVariable)> = sorted_values
            .iter()
            .map(|value| {
                value.commit_prover(
                    &mut prover,
                    &CloakValue::new(
                        RistrettoScalar::from_u32(1),
                        RistrettoScalar::from_u32(2),
                    ),
                )
            })
            .collect();
        let mid =
            allocate_cloak_vector(&mut prover, Some(&mid_values), mid_values.len())
                .unwrap();
        let added =
            allocate_cloak_vector(&mut prover, Some(&out_values), out_values.len())
                .unwrap();
        let sorted_vars: Vec<CloakVariable> =
            sorted_coms_vars.iter().map(|(_, var)| *var).collect();
        let num_wires = super::cloak_merge_gadget(
            &mut prover,
            &sorted_vars[..],
            &mid[..],
            &added[..],
        )
        .unwrap();
        let num_wires = num_wires + added.len() + mid.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let sorted_coms: Vec<CloakCommitment> =
            sorted_coms_vars.iter().map(|(com, _)| (*com)).collect();
        let sorted_vars: Vec<CloakVariable> = sorted_coms
            .iter()
            .map(|com| com.commit_verifier(&mut verifier))
            .collect();
        let mid = allocate_cloak_vector(&mut verifier, None, mid_values.len()).unwrap();
        let added =
            allocate_cloak_vector(&mut verifier, None, out_values.len()).unwrap();
        let num_wires = super::cloak_merge_gadget(
            &mut verifier,
            &sorted_vars[..],
            &mid[..],
            &added[..],
        )
        .unwrap();
        let num_wires = num_wires + added.len() + mid.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
    }

    #[test]
    fn test_shuffle() {
        let pc_gens = PedersenGens::default();
        let input_values = vec![
            CloakValue::new(
                RistrettoScalar::from_u32(10),
                RistrettoScalar::from_u32(10),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(20),
                RistrettoScalar::from_u32(20),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(30),
                RistrettoScalar::from_u32(30),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(40),
                RistrettoScalar::from_u32(40),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(50),
                RistrettoScalar::from_u32(50),
            ),
        ];

        let shuffled_values = vec![
            CloakValue::new(
                RistrettoScalar::from_u32(20),
                RistrettoScalar::from_u32(20),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(40),
                RistrettoScalar::from_u32(40),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(10),
                RistrettoScalar::from_u32(10),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(50),
                RistrettoScalar::from_u32(50),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(30),
                RistrettoScalar::from_u32(30),
            ),
        ];

        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let input =
            allocate_cloak_vector(&mut prover, Some(&input_values), input_values.len())
                .unwrap();
        let shuffled = allocate_cloak_vector(
            &mut prover,
            Some(&shuffled_values),
            shuffled_values.len(),
        )
        .unwrap();
        let num_wires =
            super::cloak_shuffle_gadget(&mut prover, input.to_vec(), shuffled.to_vec())
                .unwrap();
        let num_wires = num_wires + input.len() + shuffled.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let input =
            allocate_cloak_vector(&mut verifier, None, input_values.len()).unwrap();
        let shuffled =
            allocate_cloak_vector(&mut verifier, None, shuffled_values.len()).unwrap();
        super::cloak_shuffle_gadget(&mut verifier, input.to_vec(), shuffled.to_vec())
            .unwrap();
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

        let bad_shuffle_values = vec![
            CloakValue::new(RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(0)),
            CloakValue::new(
                RistrettoScalar::from_u32(40),
                RistrettoScalar::from_u32(40),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(10),
                RistrettoScalar::from_u32(10),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(50),
                RistrettoScalar::from_u32(50),
            ),
            CloakValue::new(
                RistrettoScalar::from_u32(30),
                RistrettoScalar::from_u32(30),
            ),
        ];

        let mut prover_transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let input = allocate_cloak_vector(&mut prover, Some(&input_values), 0).unwrap();
        let bad_shuffle =
            allocate_cloak_vector(&mut prover, Some(&bad_shuffle_values), 0).unwrap();
        let num_wires =
            super::cloak_shuffle_gadget(&mut prover, input.to_vec(), bad_shuffle)
                .unwrap();
        let num_wires = num_wires + input.len() + shuffled.len();
        let bp_gens = BulletproofGens::new(num_wires.next_power_of_two(), 1);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let input =
            allocate_cloak_vector(&mut verifier, None, input_values.len()).unwrap();
        let bad_shuffle =
            allocate_cloak_vector(&mut verifier, None, bad_shuffle_values.len())
                .unwrap();
        super::cloak_shuffle_gadget(&mut verifier, input.to_vec(), bad_shuffle.to_vec())
            .unwrap();
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_err());
    }
}
