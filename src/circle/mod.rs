mod bitcoin_script;
pub use bitcoin_script::*;

use std::ops::{Add, Neg, Sub};

use crate::math::M31;

/// A point on the complex circle. Treated as an additive group.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CirclePoint {
    /// x coordinate.
    pub x: M31,
    /// y coordinate.
    pub y: M31,
}

impl CirclePoint {
    /// Push the zero point.
    pub fn zero() -> Self {
        Self {
            x: 1.into(),
            y: 0.into(),
        }
    }

    /// Double a point.
    pub fn double(&self) -> Self {
        *self + *self
    }

    /// Multiply a point with a scalar.
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

    /// Double a point repeatedly for n times.
    pub fn repeated_double(&self, n: usize) -> Self {
        let mut res = *self;
        for _ in 0..n {
            res = res.double();
        }
        res
    }

    /// Negate a point.
    pub fn conjugate(&self) -> CirclePoint {
        Self {
            x: self.x,
            y: -self.y,
        }
    }

    /// Compute a subgroup generator for points on the circle curve over the m31 field.
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

/// The group order of the points on the circle curve over the m31 field.
pub const M31_CIRCLE_LOG_ORDER: usize = 31;
/// A generator of the circle curve over the m31 field.
pub const M31_CIRCLE_GEN: CirclePoint = CirclePoint {
    x: M31(2),
    y: M31(1268011823),
};
