use crate::dsl::primitives::cm31_limbs::CM31LimbsVar;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use anyhow::Result;
use bitcoin_script_dsl::bvar::BVar;
use bitcoin_script_dsl::constraint_system::ConstraintSystemRef;
use std::ops::Mul;

#[derive(Clone)]
pub struct QM31LimbsVar {
    pub first: CM31LimbsVar,
    pub second: CM31LimbsVar,
}

impl BVar for QM31LimbsVar {
    type Value = (([u32; 4], [u32; 4]), ([u32; 4], [u32; 4]));

    fn cs(&self) -> ConstraintSystemRef {
        self.first.cs().and(&self.second.cs())
    }

    fn variables(&self) -> Vec<usize> {
        let mut variables = self.first.variables();
        variables.extend(self.second.variables());
        variables
    }

    fn length() -> usize {
        16
    }

    fn value(&self) -> Result<Self::Value> {
        Ok((self.first.value()?, self.second.value()?))
    }
}

impl From<&QM31Var> for QM31LimbsVar {
    fn from(var: &QM31Var) -> Self {
        let first = CM31LimbsVar::from(&var.first);
        let second = CM31LimbsVar::from(&var.second);

        Self { first, second }
    }
}

impl Mul<(&TableVar, &QM31LimbsVar)> for &QM31LimbsVar {
    type Output = QM31Var;

    fn mul(self, rhs: (&TableVar, &QM31LimbsVar)) -> Self::Output {
        let table = rhs.0;
        let rhs = rhs.1;

        let self_sum = &self.first + &self.second;
        let rhs_sum = &rhs.first + &rhs.second;

        let sum_product = &self_sum * (table, &rhs_sum);
        let first_product = &self.first * (table, &rhs.first);
        let second_product = &self.second * (table, &rhs.second);

        let mut first = &first_product + &second_product;
        first = &first + &second_product;
        let second_product_shifted_by_i = second_product.shift_by_i();
        first = &first + &second_product_shifted_by_i;

        let mut second = &sum_product - &first_product;
        second = &second - &second_product;

        QM31Var { first, second }
    }
}

#[cfg(test)]
mod test {
    use crate::dsl::primitives::qm31::QM31Var;
    use crate::dsl::primitives::qm31_limbs::QM31LimbsVar;
    use crate::dsl::primitives::table::utils::rand_qm31;
    use crate::dsl::primitives::table::TableVar;
    use crate::treepp::*;
    use bitcoin_script_dsl::bvar::AllocVar;
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_qm31_limbs_table_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_val = rand_qm31(&mut prng);
        let b_val = rand_qm31(&mut prng);
        let expected = a_val * b_val;

        let cs = ConstraintSystem::new_ref();

        let a = QM31Var::new_constant(&cs, a_val).unwrap();
        let a_limbs = QM31LimbsVar::from(&a);

        let b = QM31Var::new_constant(&cs, b_val).unwrap();
        let b_limbs = QM31LimbsVar::from(&b);

        let table = TableVar::new_constant(&cs, ()).unwrap();
        let res = &a_limbs * (&table, &b_limbs);

        cs.set_program_output(&res).unwrap();

        test_program(
            cs,
            script! {
                { expected.1.1 } { expected.1.0 } { expected.0.1 } { expected.0.0 }
            },
        )
        .unwrap();
    }
}
