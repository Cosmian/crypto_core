use crate::CryptoCoreError;
use cosmian_crypto_base::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::{rand_core::CryptoRngCore, zeroize::ZeroizeOnDrop},
    traits::{Field, FixedSizeCBytes, One, Sampling, Zero},
    Secret,
};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    num::NonZeroUsize,
    ops::{Add, Div, Mul, Neg, Sub},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShamirShare<const SIZE: usize> {
    /// Shamir index start at one (since the evaluation in zero is the secret).
    index: NonZeroUsize,

    /// Minimum number of shares needed to reconstruct the secret.
    thres: NonZeroUsize,

    /// Actual value of the share.
    point: Secret<SIZE>,
}

impl<const SIZE: usize> ShamirShare<SIZE> {
    pub fn index(&self) -> NonZeroUsize {
        self.index
    }

    pub fn threshold(&self) -> NonZeroUsize {
        self.thres
    }
}

impl<const SIZE: usize> Serializable for ShamirShare<SIZE> {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        SIZE
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        Ok(ser.write(&self.index)? + ser.write(&self.thres)? + ser.write(&*self.point)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self {
            index: de.read()?,
            thres: de.read()?,
            point: de.read()?,
        })
    }
}

/// This type is a module that implements Shamir secret sharing based on an
/// abstract scalar type which serialized byte size is given at compile time.
pub struct ShamirSecretSharing<const SIZE: usize, Scalar: Field + FixedSizeCBytes<SIZE>>(
    PhantomData<Scalar>,
)
where
    for<'a> &'a Scalar: Neg<Output = Scalar>,
    for<'a, 'b> &'a Scalar: Add<&'b Scalar, Output = Scalar>,
    for<'a, 'b> &'a Scalar: Sub<&'b Scalar, Output = Scalar>,
    for<'a, 'b> &'a Scalar: Mul<&'b Scalar, Output = Scalar>,
    for<'a, 'b> &'a Scalar: Div<&'b Scalar, Output = Result<Scalar, Scalar::InvError>>;

impl<const SIZE: usize, Scalar: ZeroizeOnDrop + Sampling + Field + FixedSizeCBytes<SIZE>>
    ShamirSecretSharing<SIZE, Scalar>
where
    for<'a> &'a Scalar: Neg<Output = Scalar>,
    for<'a, 'b> &'a Scalar: Add<&'b Scalar, Output = Scalar>,
    for<'a, 'b> &'a Scalar: Sub<&'b Scalar, Output = Scalar>,
    for<'a, 'b> &'a Scalar: Mul<&'b Scalar, Output = Scalar>,
    for<'a, 'b> &'a Scalar: Div<&'b Scalar, Output = Result<Scalar, <Scalar as Field>::InvError>>,
{
    fn scalar_to_secret(s: &Scalar) -> Result<Secret<SIZE>, CryptoCoreError> {
        let mut res = Secret::<SIZE>::new();
        Scalar::write(s, &mut res)
            .map_err(|e| CryptoCoreError::GenericSerializationError(e.to_string()))?;
        Ok(res)
    }

    fn ith_scalar(i: usize) -> Scalar {
        (0..i).fold(<Scalar as Zero>::zero(), |s, _| s + <Scalar as One>::one())
    }

    /// Evaluates the polynomial with coefficients `coeffs` (constant term
    /// first) at `x`, using Horner's method.
    fn poly_eval(coeffs: &[Scalar], x: &Scalar) -> Scalar {
        coeffs
            .iter()
            .rev()
            .fold(<Scalar as Zero>::zero(), |acc, c| acc * x + c)
    }

    /// Splits a freshly generated `SKSeed` into `share_count` shares such that any
    /// `threshold` of them suffice to reconstruct it, using a random polynomial of
    /// degree `threshold - 1` over the P-256 scalar field. `threshold` is the
    /// caller-facing knob; the polynomial's degree is an implementation detail
    /// derived from it.
    pub fn split(
        rng: &mut impl CryptoRngCore,
        thres: NonZeroUsize,
        count: NonZeroUsize,
    ) -> Result<(Secret<SIZE>, Vec<ShamirShare<SIZE>>), CryptoCoreError> {
        // A threshold equal to one makes no sense since it enables any party to
        // reconstruct the shared secret, while a threshold greater than the
        // number of party makes no sense since it prevents any coalition of
        // parties from reconstructing the shared secret.
        if !(NonZeroUsize::MIN < thres && thres < count) {
            return Err(CryptoCoreError::Shamir(format!(
                "The threshold {thres} must be greater than one, \
                 but less that the total number or parties {count}."
            )));
        }

        let coeffs = {
            // For Shamir secret sharing, the number of shares required to
            // reconstruct the secret is degree + 1.
            let degree = thres.get() - 1;
            (0..=degree)
                .map(|_| Scalar::random(&mut *rng))
                .collect::<Vec<_>>()
        };

        let secret = Self::scalar_to_secret(
            coeffs
                .first()
                .expect("(1 < threshold) && (threshold = degree + 1) => 0 < degree"),
        )?;

        let shares =
            (1..=count.get()).try_fold(Vec::with_capacity(count.get()), |mut acc, index| {
                let point = Self::poly_eval(&coeffs, &Self::ith_scalar(index));
                let share = ShamirShare {
                    index: NonZeroUsize::new(index).expect("1 <= index <= count"),
                    thres,
                    point: Self::scalar_to_secret(&point)?,
                };
                acc.push(share);
                Ok::<_, CryptoCoreError>(acc)
            })?;

        Ok((secret, shares))
    }

    /// Evaluates the Lagrange basis polynomial at zero for the given share
    /// index in the context of the given shares.
    ///
    /// The computation ignores all shares which index is equal to the given one
    /// in order to guarantee a successful computation, which implies that
    /// incorrect or malicious inputs (e.g. which index has been forged)
    /// silenciously get an incorrect result.
    fn lagrange_eval(index: &NonZeroUsize, shares: &[&ShamirShare<SIZE>]) -> Scalar {
        let (num, den) = {
            let xi = Self::ith_scalar(index.get());
            shares.iter().fold(
                (<Scalar as One>::one(), <Scalar as One>::one()),
                |(num, den), share_j| {
                    // Ignore all shares with the same index as they lead to a
                    // null denominator which cannot be inversed.
                    if &share_j.index == index {
                        (num, den)
                    } else {
                        let xj = Self::ith_scalar(share_j.index.get());
                        (num * (-&xj), den * (&xi - &xj))
                    }
                },
            )
        };

        num * <Scalar as Field>::invert(&den)
            .expect("the index equality test guarantees the denominator is not null")
    }

    /// Reconstructs the shared secret from a the given shares.
    ///
    /// At least `threshold` shares are required to reconstruct the secret. In
    /// case more shares were given, the first `threshold` ones are used and the
    /// rest is ignored.
    ///
    /// Malicious inputs are not guared against, but return a random value.
    pub fn merge(
        shares: &BTreeMap<NonZeroUsize, ShamirShare<SIZE>>,
    ) -> Result<Secret<SIZE>, CryptoCoreError> {
        let Some(first) = shares.values().next() else {
            return Err(CryptoCoreError::Shamir("no share were given".to_owned()));
        };

        let shares = shares.values().take(first.thres.get()).collect::<Vec<_>>();

        if shares.len() < first.thres.get() {
            return Err(CryptoCoreError::Shamir(format!(
                "at least {} shares are required to reconstruct the secret, \
                     but {} were given",
                first.thres.get(),
                shares.len()
            )));
        }

        let acc = shares
            .iter()
            .try_fold(<Scalar as Zero>::zero(), |acc, share| {
                let point = Scalar::read(&share.point)
                    .map_err(|e| CryptoCoreError::Shamir(e.to_string()))?;
                Ok::<_, CryptoCoreError>(acc + point * Self::lagrange_eval(&share.index, &shares))
            })?;

        Self::scalar_to_secret(&acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, num::NonZeroUsize};

    use cosmian_crypto_base::{
        reexport::rand_core::SeedableRng,
        shuffle_in_place,
        traits::{Field, FixedSizeCBytes, Sampling},
        CsRng,
    };
    use cosmian_openssl_provider::p256::P256Scalar;
    use cosmian_rust_curve25519_provider::R25519Scalar;
    use zeroize::ZeroizeOnDrop;

    use crate::shamir::{ShamirSecretSharing, ShamirShare};

    #[test]
    fn test_openssl_sss() {
        test_shamir_secret_sharing::<{ P256Scalar::LENGTH }, P256Scalar>()
    }

    #[test]
    fn test_dalek_sss() {
        test_shamir_secret_sharing::<{ R25519Scalar::LENGTH }, R25519Scalar>()
    }

    fn test_shamir_secret_sharing<
        const SIZE: usize,
        Scalar: ZeroizeOnDrop + Sampling + Field + FixedSizeCBytes<SIZE>,
    >()
    where
        for<'a> &'a Scalar: Neg<Output = Scalar>,
        for<'a, 'b> &'a Scalar: Add<&'b Scalar, Output = Scalar>,
        for<'a, 'b> &'a Scalar: Sub<&'b Scalar, Output = Scalar>,
        for<'a, 'b> &'a Scalar: Mul<&'b Scalar, Output = Scalar>,
        for<'a, 'b> &'a Scalar: Div<&'b Scalar, Output = Result<Scalar, Scalar::InvError>>,
    {
        const THRES: usize = 3;
        const COUNT: usize = 5;

        let mut rng = CsRng::from_entropy();
        let (secret, shares) = ShamirSecretSharing::<SIZE, Scalar>::split(
            &mut rng,
            NonZeroUsize::try_from(THRES).unwrap(),
            NonZeroUsize::try_from(COUNT).unwrap(),
        )
        .unwrap();

        assert_eq!(COUNT, shares.len());

        {
            // Reconstruction from all the shares is possible.
            let shares = shares
                .iter()
                .cloned()
                .map(|share| (share.index, share))
                .collect::<BTreeMap<NonZeroUsize, ShamirShare<SIZE>>>();

            let reconstructed_secret = ShamirSecretSharing::<SIZE, Scalar>::merge(&shares).unwrap();

            assert_eq!(secret, reconstructed_secret);
        }

        {
            // Reconstruction from `threshold` shares is possible.
            let shares = shares
                .iter()
                .take(THRES)
                .cloned()
                .map(|share| (share.index, share))
                .collect::<BTreeMap<NonZeroUsize, ShamirShare<SIZE>>>();

            let reconstructed_secret = ShamirSecretSharing::<SIZE, Scalar>::merge(&shares).unwrap();

            assert_eq!(secret, reconstructed_secret);
        }

        {
            // Reconstruction from `threshold - 1` shares is impossible.
            let shares = shares
                .iter()
                .take(THRES - 1)
                .cloned()
                .map(|share| (share.index, share))
                .collect::<BTreeMap<NonZeroUsize, ShamirShare<SIZE>>>();

            assert!(ShamirSecretSharing::<SIZE, Scalar>::merge(&shares).is_err());
        }

        {
            let (_, new_shares) = ShamirSecretSharing::<SIZE, Scalar>::split(
                &mut rng,
                NonZeroUsize::try_from(THRES).unwrap(),
                NonZeroUsize::try_from(COUNT).unwrap(),
            )
            .unwrap();

            // Mix shares, making sure there isn't enough shares from a single
            // split to allow reconstructing the secret.
            let mut shares = shares
                .iter()
                .take(THRES - 1)
                .cloned()
                .chain(new_shares.iter().rev().take(THRES - 1).cloned())
                .collect::<Vec<_>>();

            // Shuffle for good measure.
            shuffle_in_place(&mut shares, &mut rng);

            // Reconstruction from a mix of shares from different splits is
            // impossible.
            let shares = shares
                .into_iter()
                .map(|share| (share.index, share))
                .collect::<BTreeMap<NonZeroUsize, ShamirShare<SIZE>>>();

            let reconstructed_secret = ShamirSecretSharing::<SIZE, Scalar>::merge(&shares).unwrap();

            assert_ne!(secret, reconstructed_secret);
        }
    }
}
