//! This module contains generic tests all implementations of the traits
//! defined in the parent module must pass.

use std::{
    fmt::Debug,
    ops::{Add, Div, Mul, Neg, Sub},
};

use crate::{
    reexport::rand_core::SeedableRng,
    traits::{AbelianGroup, CyclicGroup, Field, Group, Monoid, Ring, Sampling, Zero, KEM, NIKE},
    CsRng,
};

pub fn test_monoid<M: Debug + Sampling + Monoid>() {
    let mut rng = CsRng::from_entropy();

    // Neutral element.
    let id = M::id();
    assert_eq!(id, M::op(&id, &id));

    // Associativity.
    let a = M::random(&mut rng);
    let b = M::random(&mut rng);
    let c = M::random(&mut rng);
    assert_eq!(M::op(&a, &M::op(&b, &c)), M::op(&M::op(&a, &b), &c),);
}

pub fn test_group<G: Debug + Sampling + Group>() {
    test_monoid::<G>();

    let mut rng = CsRng::from_entropy();

    // Inversion.
    let a = G::random(&mut rng);
    assert_eq!(G::id(), a.op(&a.invert()));
}

pub fn test_abelian_group<G: Debug + Sampling + AbelianGroup>()
where
    for<'a> &'a G: Neg<Output = G>,
    for<'a, 'b> &'a G: Add<&'b G, Output = G>,
    for<'a, 'b> &'a G: Sub<&'b G, Output = G>,
{
    test_group::<G>();

    let mut rng = CsRng::from_entropy();

    // Commutativity.
    let a = G::random(&mut rng);
    let b = G::random(&mut rng);
    assert_eq!(a.op(&b), a.op(&b));
}

pub fn test_ring<R: Debug + Sampling + Ring>()
where
    for<'a> &'a R: Neg<Output = R>,
    for<'a, 'b> &'a R: Add<&'b R, Output = R>,
    for<'a, 'b> &'a R: Sub<&'b R, Output = R>,
{
    test_abelian_group::<R>();

    let mut rng = CsRng::from_entropy();

    // Neutral element.
    let id = <R as Ring>::id();
    assert_eq!(id, <R as Ring>::op(&id, &id));

    // Associativity.
    let a = R::random(&mut rng);
    let b = R::random(&mut rng);
    let c = R::random(&mut rng);
    assert_eq!(
        <R as Ring>::op(&a, &<R as Ring>::op(&b, &c)),
        <R as Ring>::op(&<R as Ring>::op(&a, &b), &c),
    );

    // Distributivity.
    assert_eq!(
        <R as Ring>::op(&a, &<R as Monoid>::op(&b, &c)),
        <R as Monoid>::op(&<R as Ring>::op(&a, &b), &<R as Ring>::op(&a, &c)),
    )
}

pub fn test_field<F: Debug + Sampling + Field>()
where
    for<'a> &'a F: Neg<Output = F>,
    for<'a, 'b> &'a F: Add<&'b F, Output = F>,
    for<'a, 'b> &'a F: Sub<&'b F, Output = F>,
    for<'a, 'b> &'a F: Mul<&'b F, Output = F>,
    for<'a, 'b> &'a F: Div<&'b F, Output = Result<F, F::InvError>>,
{
    // Used not to throw a warning upon `&a / &a`.
    #![allow(clippy::eq_op)]

    test_ring::<F>();

    let mut rng = CsRng::from_entropy();

    // Inversion.
    for _ in 0..10 {
        let a = F::random(&mut rng);
        if !a.is_zero() {
            assert_eq!(&a * &<F as Field>::invert(&a).unwrap(), <F as Ring>::id());
            assert_eq!((&a / &a).unwrap(), <F as Ring>::id());
            assert!((&a / &F::zero()).is_err());
            return;
        }
    }
    panic!("could not generate a non-null field element after 10 attempts")
}

pub fn test_cyclic_group<G: CyclicGroup>()
where
    G::Element: Debug + Sampling,
    G::Multiplicity: Debug + Sampling,
    for<'a> &'a G::Element: Neg<Output = G::Element>,
    for<'a, 'b> &'a G::Element: Add<&'b G::Element, Output = G::Element>,
    for<'a, 'b> &'a G::Element: Sub<&'b G::Element, Output = G::Element>,
    for<'a, 'b> &'a G::Element: Mul<G::Multiplicity, Output = G::Element>,
    for<'a, 'b> &'a G::Element: Mul<&'b G::Multiplicity, Output = G::Element>,
    for<'a> &'a G::Multiplicity: Neg<Output = G::Multiplicity>,
    for<'a, 'b> &'a G::Multiplicity: Add<&'b G::Multiplicity, Output = G::Multiplicity>,
    for<'a, 'b> &'a G::Multiplicity: Sub<&'b G::Multiplicity, Output = G::Multiplicity>,
    for<'a, 'b> &'a G::Multiplicity: Mul<&'b G::Multiplicity, Output = G::Multiplicity>,
    for<'a, 'b> &'a G::Multiplicity: Div<
        &'b G::Multiplicity,
        Output = Result<G::Multiplicity, <G::Multiplicity as Field>::InvError>,
    >,
{
    test_abelian_group::<G::Element>();
    test_field::<G::Multiplicity>();

    let mut rng = CsRng::from_entropy();

    let a = G::Element::random(&mut rng);
    let b = G::Element::random(&mut rng);
    let x = G::Multiplicity::random(&mut rng);
    let y = G::Multiplicity::random(&mut rng);

    // Neutral element.
    assert_eq!(G::Element::zero(), G::Element::zero() * &x);
    assert_eq!(G::Element::zero(), G::Element::zero() * &y);

    // Generator.
    assert_eq!(G::Element::zero(), &a * G::Multiplicity::zero());
    assert_eq!(G::Element::zero(), &b * G::Multiplicity::zero());

    // Bilinearity.
    assert_eq!(&a * &x + &a * &y, &a * (&x + &y));
    assert_eq!(&a * &x + &b * &x, (&a + &b) * &x);
}

/// A non-interactive key exchange must allow generating the same session key on
/// both sides.
pub fn test_nike<Scheme: NIKE>()
where
    Scheme::SharedSecret: Debug + Eq,
{
    let mut rng = CsRng::from_entropy();

    let keypair_1 = Scheme::keygen(&mut rng).unwrap();
    let keypair_2 = Scheme::keygen(&mut rng).unwrap();

    let session_key_1 = Scheme::shared_secret(&keypair_1.0, &keypair_2.1).unwrap();
    let session_key_2 = Scheme::shared_secret(&keypair_2.0, &keypair_1.1).unwrap();

    assert_eq!(session_key_1, session_key_2);
}

pub fn test_kem<const KEY_LENGTH: usize, Scheme: KEM<KEY_LENGTH>>() {
    let mut rng = CsRng::from_entropy();

    let (dk_1, ek_1) = Scheme::keygen(&mut rng).unwrap();
    let (dk_2, ek_2) = Scheme::keygen(&mut rng).unwrap();

    let (ss_1, enc_1) = Scheme::enc(&ek_1, &mut rng).unwrap();
    let (ss_2, enc_2) = Scheme::enc(&ek_2, &mut rng).unwrap();

    let ss_1_ = Scheme::dec(&dk_1, &enc_1).unwrap();
    let ss_2_ = Scheme::dec(&dk_2, &enc_2).unwrap();

    assert_eq!(ss_1, ss_1_);
    assert_eq!(ss_2, ss_2_);
}
