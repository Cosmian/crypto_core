use super::*;
use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

pub use error::{PkeError, SealBoxError};

#[derive(Clone, Copy, Default)]
pub struct GenericPKE<
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const TAG_LENGTH: usize,
    Kem: KEM<KEY_LENGTH>,
    E: AE<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
>(PhantomData<(Kem, E)>);

impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        Kem: Debug + KEM<KEY_LENGTH>,
        E: Debug + AE<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > PKE for GenericPKE<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, E>
{
    type Plaintext = E::Plaintext;
    type Ciphertext = (Kem::Encapsulation, E::Ciphertext);
    type PublicKey = Kem::EncapsulationKey;
    type SecretKey = Kem::DecapsulationKey;
    type Error = PkeError<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, E>;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error> {
        Kem::keygen(rng).map_err(Self::Error::Kem)
    }

    fn encrypt(
        pk: &Self::PublicKey,
        ptx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Ciphertext, Self::Error> {
        let (key, enc) = Kem::enc(pk, rng).map_err(Self::Error::Kem)?;
        let mut nonce = [0; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);
        let ctx = E::encrypt(&key, ptx, &nonce).map_err(Self::Error::Ae)?;
        Ok((enc, ctx))
    }

    fn decrypt(
        sk: &Self::SecretKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Self::Error> {
        let key = Kem::dec(sk, &ctx.0).map_err(Self::Error::Kem)?;
        let ptx = E::decrypt(&key, ctx.1.as_ref()).map_err(Self::Error::Ae)?;
        Ok(ptx)
    }
}

#[derive(Clone, Copy, Default)]
pub struct SealBox<
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const TAG_LENGTH: usize,
    Kem: KEM<KEY_LENGTH>,
    H: XOF,
    E: AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
>(PhantomData<(Kem, H, E)>);

impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        Kem: KEM<KEY_LENGTH>,
        H: XOF,
        E: AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > SealBox<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, H, E>
{
    fn get_nonce(
        ek: &Kem::EncapsulationKey,
        enc: &Kem::Encapsulation,
    ) -> Result<[u8; NONCE_LENGTH], SealBoxError<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, H, E>>
    {
        let mut nonce = [0; NONCE_LENGTH];
        H::hash(
            vec![
                &enc.serialize().map_err(SealBoxError::KemEncSerialization)?,
                &ek.serialize().map_err(SealBoxError::KemPkSerialization)?,
            ],
            &mut nonce,
        )
        .map_err(SealBoxError::Xof)?;
        Ok(nonce)
    }
}

impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        Kem: Debug + KEM<KEY_LENGTH>,
        H: Debug + XOF,
        E: Debug + AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > PKE for SealBox<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, H, E>
where
    Kem::Encapsulation: Debug,
    Kem::EncapsulationKey: Debug,
{
    type Plaintext = Zeroizing<Vec<u8>>;
    // CIPHERTEXT = ENCAPSULATION + TAG || ENCRYPTED PLAINTEXT
    type Ciphertext = (Kem::Encapsulation, Vec<u8>);
    type PublicKey = Kem::EncapsulationKey;
    type SecretKey = Kem::DecapsulationKey;
    type Error = SealBoxError<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, H, E>;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error> {
        Kem::keygen(rng).map_err(Self::Error::Kem)
    }

    fn encrypt(
        pk: &Self::PublicKey,
        ptx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Ciphertext, Self::Error> {
        let (key, enc) = Kem::enc(pk, rng).map_err(Self::Error::Kem)?;
        let nonce = Self::get_nonce(pk, &enc)?;
        let mut ctx = vec![0; TAG_LENGTH + ptx.len()];
        ctx[TAG_LENGTH..].copy_from_slice(ptx);
        let tag =
            E::encrypt_in_place(&key, &mut ctx[TAG_LENGTH..], &nonce).map_err(Self::Error::Ae)?;
        ctx[..TAG_LENGTH].copy_from_slice(&tag);
        Ok((enc, ctx))
    }

    fn decrypt(
        sk: &Self::SecretKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Self::Error> {
        if ctx.1.len() < TAG_LENGTH {
            return Err(Self::Error::AeCtxLength(ctx.1.len()));
        }
        let key = Kem::dec(sk, &ctx.0).map_err(Self::Error::Kem)?;
        let nonce = Self::get_nonce(&Kem::EncapsulationKey::from(sk), &ctx.0)?;
        let mut ptx = Zeroizing::new(vec![0; ctx.1.len() - TAG_LENGTH]);
        ptx.copy_from_slice(&ctx.1[TAG_LENGTH..]);
        E::decrypt_in_place(
            &key,
            &mut ptx,
            &nonce,
            &<[u8; TAG_LENGTH]>::try_from(&ctx.1[..TAG_LENGTH]).unwrap(),
        )
        .map_err(Self::Error::Ae)?;
        Ok(ptx)
    }
}

mod error {
    use super::*;

    #[derive(Debug)]
    pub enum PkeError<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        Kem: KEM<KEY_LENGTH>,
        Ae: AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > {
        Kem(Kem::Error),
        Ae(Ae::Error),
        AeCtxLength(usize),
    }

    impl<
            const KEY_LENGTH: usize,
            const NONCE_LENGTH: usize,
            const TAG_LENGTH: usize,
            Kem: KEM<KEY_LENGTH>,
            E: AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
        > Display for PkeError<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, E>
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Kem(e) => write!(f, "KEM error in PKE: {e}"),
                Self::Ae(e) => write!(f, "AE error in PKE: {e}"),
                Self::AeCtxLength(l) => write!(
                    f,
                    "AE ciphertext length error in PKE: {l} given, should be more than {TAG_LENGTH}"
                ),
            }
        }
    }

    impl<
            const KEY_LENGTH: usize,
            const NONCE_LENGTH: usize,
            const TAG_LENGTH: usize,
            Kem: Debug + KEM<KEY_LENGTH>,
            E: Debug + AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
        > std::error::Error for PkeError<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, E>
    {
    }

    #[derive(Debug)]
    pub enum SealBoxError<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        Kem: KEM<KEY_LENGTH>,
        H: XOF,
        Ae: AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > {
        Kem(Kem::Error),
        KemEncSerialization(<Kem::Encapsulation as Serializable>::Error),
        KemPkSerialization(<Kem::EncapsulationKey as Serializable>::Error),
        Xof(H::Error),
        Ae(Ae::Error),
        AeCtxLength(usize),
    }

    impl<
            const KEY_LENGTH: usize,
            const NONCE_LENGTH: usize,
            const TAG_LENGTH: usize,
            Kem: KEM<KEY_LENGTH>,
            H: XOF,
            E: AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
        > Display for SealBoxError<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, H, E>
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Kem(e) => write!(f, "KEM error in PKE: {e}"),
                Self::KemEncSerialization(e) => {
                    write!(f, "serialization error for KEM encapsulation: {e}")
                }
                Self::KemPkSerialization(e) => {
                    write!(f, "serialization error for KEM encapsulation key: {e}")
                }
                Self::Xof(e) => write!(f, "XOF error in PKE: {e}"),
                Self::Ae(e) => write!(f, "AE error in PKE: {e}"),
                Self::AeCtxLength(l) => write!(
                    f,
                    "AE ciphertext length error in PKE: {l} given, should be more than {TAG_LENGTH}"
                ),
            }
        }
    }

    impl<
            const KEY_LENGTH: usize,
            const NONCE_LENGTH: usize,
            const TAG_LENGTH: usize,
            Kem: Debug + KEM<KEY_LENGTH>,
            H: Debug + XOF,
            E: Debug + AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
        > std::error::Error for SealBoxError<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kem, H, E>
    where
        Kem::Encapsulation: Debug,
        Kem::EncapsulationKey: Debug,
    {
    }
}
