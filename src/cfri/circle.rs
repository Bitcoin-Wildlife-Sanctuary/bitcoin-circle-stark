#![allow(unused)]

use std::ops::{Add, Neg, Sub};

use crate::cfri::fields::M31;

/// A point on the complex circle. Treaed as an additive group.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CirclePoint {
    pub x: M31,
    pub y: M31,
}

impl CirclePoint {
    pub fn zero() -> Self {
        Self {
            x: 1.into(),
            y: 0.into(),
        }
    }

    pub fn double(&self) -> Self {
        *self + *self
    }

    pub fn mul(&self, mut scalar: u128) -> CirclePoint {
        let mut res = Self::zero();
        let mut cur = *self;
        while scalar > 0 {
            if scalar & 1 == 1 {
                res = res + cur;
            }
            cur = cur.double();
            scalar >>= 1;
        }
        res
    }

    pub fn repeated_double(&self, n: usize) -> Self {
        let mut res = *self;
        for _ in 0..n {
            res = res.double();
        }
        res
    }

    pub fn conjugate(&self) -> CirclePoint {
        Self {
            x: self.x,
            y: -self.y,
        }
    }

    pub fn subgroup_gen(logn: usize) -> Self {
        M31_CIRCLE_GEN.repeated_double(M31_CIRCLE_LOG_ORDER - logn)
    }
}
impl Add for CirclePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let x = self.x * rhs.x - self.y * rhs.y;
        let y = self.x * rhs.y + self.y * rhs.x;
        Self { x, y }
    }
}
impl Neg for CirclePoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.conjugate()
    }
}
impl Sub for CirclePoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

pub const M31_CIRCLE_LOG_ORDER: usize = 31;
pub const M31_CIRCLE_GEN: CirclePoint = CirclePoint {
    x: M31(2),
    y: M31(1268011823),
};
