/// Given a monoid, implement some arithmetic facilities that can be implemented
/// with a fold.
#[macro_export]
macro_rules! implement_monoid_arithmetic {
    ($type: ty) => {
        mod monoid_arithmetic {
            use super::*;
            use core::iter::Sum;

            impl Sum for $type {
                fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                    iter.fold(<Self as Monoid>::id(), |acc, e| {
                        <Self as Monoid>::op(&acc, &e)
                    })
                }
            }

            impl<'a> Sum<&'a $type> for $type {
                fn sum<I: Iterator<Item = &'a $type>>(iter: I) -> Self {
                    iter.fold(<Self as Monoid>::id(), |acc, e| {
                        <Self as Monoid>::op(&acc, e)
                    })
                }
            }
        }
    };
}

/// Given a group, implements an Abelian group.
#[macro_export]
macro_rules! implement_abelian_group {
    ($type: ty) => {
        mod abelian_group_arithmetic {
            use super::*;
            use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

            impl Add for $type {
                type Output = Self;

                fn add(self, rhs: Self) -> Self::Output {
                    <$type as Monoid>::op(&self, &rhs)
                }
            }

            impl Add<&$type> for $type {
                type Output = $type;

                fn add(self, rhs: &$type) -> Self::Output {
                    <$type as Monoid>::op(&self, &rhs)
                }
            }

            impl Add<&$type> for &$type {
                type Output = $type;

                fn add(self, rhs: &$type) -> Self::Output {
                    <$type as Monoid>::op(&self, &rhs)
                }
            }

            impl AddAssign for $type {
                fn add_assign(&mut self, rhs: Self) {
                    *self = <$type as Monoid>::op(&self, &rhs)
                }
            }

            impl Neg for $type {
                type Output = Self;

                fn neg(self) -> Self::Output {
                    <$type as Group>::invert(&self)
                }
            }

            impl Neg for &$type {
                type Output = $type;

                fn neg(self) -> Self::Output {
                    <$type as Group>::invert(self)
                }
            }

            impl Sub for $type {
                type Output = Self;

                fn sub(self, rhs: Self) -> Self::Output {
                    <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                }
            }

            impl Sub<&$type> for $type {
                type Output = Self;

                fn sub(self, rhs: &$type) -> Self::Output {
                    <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                }
            }

            impl Sub<&$type> for &$type {
                type Output = $type;

                fn sub(self, rhs: &$type) -> Self::Output {
                    <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                }
            }

            impl SubAssign for $type {
                fn sub_assign(&mut self, rhs: Self) {
                    *self = <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                }
            }

            impl AbelianGroup for $type {}
        }
    };
}

/// Given a ring, implements a commutative ring (the ring operation is *).
#[macro_export]
macro_rules! implement_commutative_ring {
    ($type: ty) => {
        mod commutative_ring {
            use super::*;
            use std::ops::{Mul, MulAssign};

            impl Mul for $type {
                type Output = Self;

                fn mul(self, rhs: Self) -> Self::Output {
                    <$type as Ring>::op(&self, &rhs)
                }
            }

            impl Mul<&$type> for $type {
                type Output = $type;

                fn mul(self, rhs: &$type) -> Self::Output {
                    <$type as Ring>::op(&self, &rhs)
                }
            }

            impl Mul<&$type> for &$type {
                type Output = $type;

                fn mul(self, rhs: &$type) -> Self::Output {
                    <$type as Ring>::op(&self, &rhs)
                }
            }

            impl MulAssign for $type {
                fn mul_assign(&mut self, rhs: Self) {
                    *self = <$type as Ring>::op(&self, &rhs)
                }
            }
        }
    };
}
