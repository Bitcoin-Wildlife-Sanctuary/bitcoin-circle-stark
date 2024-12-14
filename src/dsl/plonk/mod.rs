pub mod hints;

pub mod covenant;

pub mod part1_fiat_shamir1;
pub mod part2_fiat_shamir2_and_constraint_num;
pub mod part3_constraint_denom;
pub mod part4_pair_vanishing_and_alphas;
pub mod part5_column_line_coeffs1;
pub mod part6_column_line_coeffs2;
pub mod part7_column_line_coeffs3;

pub mod per_query_part1_folding;
pub mod per_query_part2_num_trace;
pub mod per_query_part3_num_constant;
pub mod per_query_part4_num_composition;
pub mod per_query_part5_num_interaction_shifted;
pub mod per_query_part6_num_interaction1;
pub mod per_query_part7_num_interaction2;
pub mod per_query_part8_last_step;

pub mod part8_cleanup;

#[cfg(test)]
mod test {
    use crate::dsl::plonk::hints::Hints;
    use crate::treepp::*;
    use bitcoin_script_dsl::ldm::LDM;
    use bitcoin_script_dsl::test_program;
    use stwo_prover::core::prover::N_QUERIES;

    #[test]
    fn test_generate_dsl() {
        let hints = Hints::instance();
        let mut ldm = LDM::new();

        let cs = super::part1_fiat_shamir1::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs =
            super::part2_fiat_shamir2_and_constraint_num::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = super::part3_constraint_denom::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = super::part4_pair_vanishing_and_alphas::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = super::part5_column_line_coeffs1::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = super::part6_column_line_coeffs2::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        let cs = super::part7_column_line_coeffs3::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();

        for i in 0..N_QUERIES {
            let cs = super::per_query_part1_folding::generate_cs(&hints, &mut ldm, i).unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            let cs = super::per_query_part2_num_trace::generate_cs(&hints, &mut ldm, i).unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            let cs = super::per_query_part3_num_constant::generate_cs(&hints, &mut ldm, i).unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            let cs =
                super::per_query_part4_num_composition::generate_cs(&hints, &mut ldm, i).unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            let cs =
                super::per_query_part5_num_interaction_shifted::generate_cs(&hints, &mut ldm, i)
                    .unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            let cs =
                super::per_query_part6_num_interaction1::generate_cs(&hints, &mut ldm, i).unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            let cs =
                super::per_query_part7_num_interaction2::generate_cs(&hints, &mut ldm, i).unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();

            let cs = super::per_query_part8_last_step::generate_cs(&hints, &mut ldm, i).unwrap();
            test_program(
                cs,
                script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                },
            )
            .unwrap();
        }

        let cs = super::part8_cleanup::generate_cs(&hints, &mut ldm).unwrap();
        test_program(
            cs,
            script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            },
        )
        .unwrap();
    }
}
