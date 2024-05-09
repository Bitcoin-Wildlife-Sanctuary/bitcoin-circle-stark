use std::fmt::Display;
use std::ops::{Add, Mul, Neg, Sub};

pub mod fft;

const MODULUS_BITS: u32 = 31;
pub const P: u32 = 2147483647;

pub trait Field:
    Neg<Output = Self>
    + Copy
    + Display
    + PartialOrd
    + Ord
    + Send
    + Sync
    + Sized
    + Mul<Output = Self>
    + Add<Output = Self>
{
    fn one() -> Self;
    fn zero() -> Self;

    fn square(&self) -> Self {
        (*self) * (*self)
    }

    fn double(&self) -> Self {
        (*self) + (*self)
    }

    fn pow(&self, exp: u128) -> Self {
        let mut res = Self::one();
        let mut base = *self;
        let mut exp = exp;
        while exp > 0 {
            if exp & 1 == 1 {
                res = res * base;
            }
            base = base.square();
            exp >>= 1;
        }
        res
    }

    fn inverse(&self) -> Self;
}

// M31
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct M31(pub u32);

impl M31 {
    pub fn reduce(val: u64) -> Self {
        Self((((((val >> MODULUS_BITS) + val + 1) >> MODULUS_BITS) + val) & (P as u64)) as u32)
    }
}

impl Display for M31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for M31 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::reduce((self.0 as u64) + (rhs.0 as u64))
    }
}

impl Neg for M31 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::reduce(P as u64 - (self.0 as u64))
    }
}

impl Sub for M31 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::reduce((self.0 as u64) + (P as u64) - (rhs.0 as u64))
    }
}

impl Mul for M31 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::reduce((self.0 as u64) * (rhs.0 as u64))
    }
}

impl From<u32> for M31 {
    fn from(value: u32) -> Self {
        M31::reduce(value.into())
    }
}

impl Field for M31 {
    fn zero() -> Self {
        M31::from(0)
    }
    fn one() -> Self {
        M31::from(1)
    }
    fn inverse(&self) -> Self {
        self.pow(P as u128 - 2)
    }
}

// CM31
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CM31(pub M31, pub M31);

impl Display for CM31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} + {}i", self.0, self.1)
    }
}

impl Mul for CM31 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // (a + bi) * (c + di) = (ac - bd) + (ad + bc)i.
        Self(
            self.0 * rhs.0 - self.1 * rhs.1,
            self.0 * rhs.1 + self.1 * rhs.0,
        )
    }
}

impl Add for CM31 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl Neg for CM31 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl Field for CM31 {
    fn zero() -> Self {
        Self(M31::zero(), M31::zero())
    }
    fn one() -> Self {
        Self(M31::one(), M31::zero())
    }
    fn inverse(&self) -> Self {
        assert!(*self != Self::zero(), "0 has no inverse");
        self.pow((P as u128) * (P as u128) - 2)
    }
}

// QM31
pub const R: CM31 = CM31(M31(1), M31(2));

#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QM31(pub CM31, pub CM31);

impl QM31 {
    pub const fn from_u32(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self(CM31(M31(a), M31(b)), CM31(M31(c), M31(d)))
    }

    pub fn from_m31(a: M31, b: M31, c: M31, d: M31) -> Self {
        Self(CM31(a, b), CM31(c, d))
    }

    pub fn from_m31_array(array: [M31; 4]) -> Self {
        Self::from_m31(array[0], array[1], array[2], array[3])
    }
}

impl Display for QM31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}) + ({})u", self.0, self.1)
    }
}

impl std::fmt::Debug for QM31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.1 == CM31::zero() && self.0 .1 == M31::zero() {
            write!(f, "{}", self.0 .0)
        } else {
            write!(f, "({}) + ({})u", self.0, self.1)
        }
    }
}

impl Mul for QM31 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // (a + bu) * (c + du) = (ac + rbd) + (ad + bc)u.
        Self(
            self.0 * rhs.0 + R * self.1 * rhs.1,
            self.0 * rhs.1 + self.1 * rhs.0,
        )
    }
}

impl Add for QM31 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl Neg for QM31 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl Field for QM31 {
    fn zero() -> Self {
        Self(CM31::zero(), CM31::zero())
    }
    fn one() -> Self {
        Self(CM31::one(), CM31::zero())
    }
    fn inverse(&self) -> Self {
        assert!(*self != Self::zero(), "0 has no inverse");
        self.pow((P as u128) * (P as u128) * (P as u128) * (P as u128) - 2)
    }
}

impl From<M31> for QM31 {
    fn from(value: M31) -> Self {
        QM31::from_m31(value, M31::zero(), M31::zero(), M31::zero())
    }
}
