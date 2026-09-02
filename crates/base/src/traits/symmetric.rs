use crate::{bytes_ser_de::Serializable, reexport::zeroize::Zeroizing, Error, SymmetricKey};

/// Authenticated Encryption scheme.
///
/// Implementations of this trait shall guarantee the absence of allocation.
#[allow(non_camel_case_types)]
pub trait AE_InPlace<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const TAG_LENGTH: usize> {
    type Error: std::error::Error;

    /// The length of the key.
    const KEY_LENGTH: usize = KEY_LENGTH;

    /// The length of the nonce.
    const NONCE_LENGTH: usize = NONCE_LENGTH;

    /// The length of the authentication tag.
    const TAG_LENGTH: usize = TAG_LENGTH;

    /// Encrypts the given plaintext using the given nonce and key.
    fn encrypt_in_place(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &mut [u8],
        nonce: &[u8; NONCE_LENGTH],
    ) -> Result<[u8; TAG_LENGTH], Self::Error>;

    /// Decrypts the given ciphertext using the given nonce and key.
    ///
    /// # Error
    ///
    /// Returns an error if the integrity of the ciphertext could not be
    /// verified.
    fn decrypt_in_place(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &mut [u8],
        nonce: &[u8; NONCE_LENGTH],
        tag: &[u8; TAG_LENGTH],
    ) -> Result<(), Self::Error>;
}

/// Authenticated Encryption scheme.
///
/// This trait provides a more convenient API than `AE_InPlace` but performs
/// allocation.
pub trait AE<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const TAG_LENGTH: usize>:
    AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>
{
    type Plaintext: AsRef<[u8]>;
    type Ciphertext: AsRef<[u8]> + PartialEq + Eq + Serializable;

    /// Encrypts the given plaintext using the given nonce and key.
    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
        nonce: &[u8; NONCE_LENGTH],
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Decrypts the given ciphertext using the given nonce and key.
    ///
    /// # Error
    ///
    /// Returns an error if the length of the ciphertext is smaller than
    /// NONCE_LENGTH + TAG_LENGTH or if the integrity of the ciphertext could
    /// not be verified.
    fn decrypt(key: &SymmetricKey<KEY_LENGTH>, ptx: &[u8]) -> Result<Self::Plaintext, Self::Error>;
}

// An AE in place trivially implements an AEAD.
impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        E: AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > AE<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH> for E
where
    E::Error: From<Error>,
{
    type Plaintext = Zeroizing<Vec<u8>>;

    // CIPHERTEXT = NONCE || TAG || ENCRYPTED PLAINTEXT
    type Ciphertext = Vec<u8>;

    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
        nonce: &[u8; NONCE_LENGTH],
    ) -> Result<Self::Ciphertext, Self::Error> {
        let mut ctx = vec![0; NONCE_LENGTH + TAG_LENGTH + ptx.len()];
        ctx[..NONCE_LENGTH].copy_from_slice(nonce);
        ctx[NONCE_LENGTH + TAG_LENGTH..].copy_from_slice(ptx);
        let tag = Self::encrypt_in_place(key, &mut ctx[NONCE_LENGTH + TAG_LENGTH..], nonce)?;
        ctx[NONCE_LENGTH..NONCE_LENGTH + TAG_LENGTH].copy_from_slice(&tag);
        Ok(ctx)
    }

    fn decrypt(key: &SymmetricKey<KEY_LENGTH>, ctx: &[u8]) -> Result<Self::Plaintext, Self::Error> {
        if ctx.len() < TAG_LENGTH + NONCE_LENGTH {
            return Err(Error::DecryptionError.into());
        }
        let mut ptx = Zeroizing::new(vec![0; ctx.len() - TAG_LENGTH - NONCE_LENGTH]);
        ptx.copy_from_slice(&ctx[NONCE_LENGTH + TAG_LENGTH..]);
        Self::decrypt_in_place(
            key,
            &mut ptx,
            &<[u8; NONCE_LENGTH]>::try_from(&ctx[..NONCE_LENGTH]).unwrap(),
            &<[u8; TAG_LENGTH]>::try_from(&ctx[NONCE_LENGTH..NONCE_LENGTH + TAG_LENGTH]).unwrap(),
        )?;
        Ok(ptx)
    }
}

/// Authenticated Encryption scheme with Associated Data.
///
/// Implementations of this trait shall guarantee the absence of allocation.
#[allow(non_camel_case_types)]
pub trait AEAD_InPlace<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const TAG_LENGTH: usize>
{
    type Error: std::error::Error;

    /// The length of the key.
    const KEY_LENGTH: usize = KEY_LENGTH;

    /// The length of the nonce.
    const NONCE_LENGTH: usize = NONCE_LENGTH;

    /// The length of the authentication tag.
    const TAG_LENGTH: usize = TAG_LENGTH;

    /// Encrypts the given plaintext using the given key and associated data.
    fn encrypt_in_place(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &mut [u8],
        nonce: &[u8; NONCE_LENGTH],
        ad: &[u8],
    ) -> Result<[u8; TAG_LENGTH], Self::Error>;

    /// Decrypts the given ciphertext using the given key and associated data.
    ///
    /// # Error
    ///
    /// Returns an error if the integrity of the ciphertext could not be
    /// verified.
    fn decrypt_in_place(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &mut [u8],
        nonce: &[u8; NONCE_LENGTH],
        tag: &[u8; TAG_LENGTH],
        ad: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Authenticated Encryption scheme with Associated Data.
///
/// This trait provides a more convenient API than `AEAD_InPlace` but performs
/// allocation.
pub trait AEAD<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const TAG_LENGTH: usize>:
    AEAD_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>
{
    type Plaintext;

    type Ciphertext;

    /// Encrypts the given plaintext using the given key, nonce and associated data.
    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        ad: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Decrypts the given ciphertext using the given key and associated data.
    ///
    /// # Error
    ///
    /// Returns an error if the length of the ciphertext is smaller than
    /// NONCE_LENGTH + TAG_LENGTH or if the integrity of the ciphertext could
    /// not be verified.
    fn decrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &[u8],
        ad: &[u8],
    ) -> Result<Self::Plaintext, Self::Error>;
}

// An AEAD in place trivially implements an AEAD.
impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        E: AEAD_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > AEAD<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH> for E
where
    E::Error: From<Error>,
{
    type Plaintext = Zeroizing<Vec<u8>>;

    // CIPHERTEXT = NONCE || TAG || ENCRYPTED PLAINTEXT
    type Ciphertext = Vec<u8>;

    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        ad: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error> {
        let mut ctx = vec![0; NONCE_LENGTH + TAG_LENGTH + ptx.len()];
        ctx[..NONCE_LENGTH].copy_from_slice(nonce);
        ctx[NONCE_LENGTH + TAG_LENGTH..].copy_from_slice(ptx);
        let tag = Self::encrypt_in_place(key, &mut ctx[NONCE_LENGTH + TAG_LENGTH..], nonce, ad)?;
        ctx[NONCE_LENGTH..NONCE_LENGTH + TAG_LENGTH].copy_from_slice(&tag);
        Ok(ctx)
    }

    fn decrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &[u8],
        ad: &[u8],
    ) -> Result<Self::Plaintext, Self::Error> {
        if ctx.len() < TAG_LENGTH + NONCE_LENGTH {
            return Err(Error::DecryptionError.into());
        }
        let mut ptx = Zeroizing::new(vec![0; ctx.len() - NONCE_LENGTH - TAG_LENGTH]);
        ptx.copy_from_slice(&ctx[NONCE_LENGTH + TAG_LENGTH..]);
        Self::decrypt_in_place(
            key,
            &mut ptx,
            &<[u8; NONCE_LENGTH]>::try_from(&ctx[..NONCE_LENGTH]).unwrap(),
            &<[u8; TAG_LENGTH]>::try_from(&ctx[NONCE_LENGTH..NONCE_LENGTH + TAG_LENGTH]).unwrap(),
            ad,
        )?;
        Ok(ptx)
    }
}

// An AEAD trivially implements an AE.
impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const TAG_LENGTH: usize,
        Aead: AEAD_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
    > AE_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH> for Aead
{
    type Error = Aead::Error;

    fn encrypt_in_place(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &mut [u8],
        nonce: &[u8; NONCE_LENGTH],
    ) -> Result<[u8; TAG_LENGTH], Self::Error> {
        <Self as AEAD_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>>::encrypt_in_place(
            key,
            ptx,
            nonce,
            &[],
        )
    }

    fn decrypt_in_place(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &mut [u8],
        nonce: &[u8; NONCE_LENGTH],
        tag: &[u8; TAG_LENGTH],
    ) -> Result<(), Self::Error> {
        <Self as AEAD_InPlace<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>>::decrypt_in_place(
            key,
            ctx,
            nonce,
            tag,
            &[],
        )
    }
}

/// Hash algorithm.
pub trait HASH<const LENGTH: usize> {
    type State;
    type Error: std::error::Error;

    const LENGTH: usize = LENGTH;

    /// Initialize the hasher.
    fn initialize() -> Result<Self::State, Self::Error>;

    /// Hash the given bytes.
    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Fills the given buffer with pseudo-random bytes.
    fn finalize(state: Self::State, bytes: &mut [u8; LENGTH]) -> Result<(), Self::Error>;

    /// Hash the given bytes into the given buffer.
    fn hash(bytes: Vec<&[u8]>, buffer: &mut [u8; LENGTH]) -> Result<(), Self::Error> {
        let mut h = Self::initialize()?;
        for bytes in bytes {
            Self::update(&mut h, bytes)?;
        }
        Self::finalize(h, buffer)
    }
}

/// Extendable Output Function.
pub trait XOF {
    type State;
    type Error: std::error::Error;

    /// Initialize the hasher.
    fn initialize() -> Result<Self::State, Self::Error>;

    /// Hash the given bytes.
    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Fills the given buffer with pseudo-random bytes.
    fn finalize(state: Self::State, buffer: &mut [u8]) -> Result<(), Self::Error>;

    /// Hash the given bytes into the given buffer.
    fn hash(bytes: Vec<&[u8]>, buffer: &mut [u8]) -> Result<(), Self::Error> {
        let mut h = Self::initialize()?;
        for bytes in bytes {
            Self::update(&mut h, bytes)?;
        }
        Self::finalize(h, buffer)
    }
}

// A XOF trivially implements a HASH of any length.
impl<const LENGTH: usize, H: XOF> HASH<LENGTH> for H {
    type State = H::State;

    type Error = H::Error;

    fn initialize() -> Result<Self::State, Self::Error> {
        H::initialize()
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        H::update(state, bytes)
    }

    fn finalize(state: Self::State, bytes: &mut [u8; LENGTH]) -> Result<(), Self::Error> {
        H::finalize(state, bytes)
    }
}

/// Key Derivation Function.
pub trait KDF<const KEY_LENGTH: usize> {
    type Error: std::error::Error;

    fn derive(seed: &[u8], info: Vec<&[u8]>) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error>;
}

impl<const LENGTH: usize, H: HASH<LENGTH>> KDF<LENGTH> for H {
    type Error = H::Error;

    fn derive(seed: &[u8], info: Vec<&[u8]>) -> Result<SymmetricKey<LENGTH>, Self::Error> {
        let mut key = SymmetricKey::default();
        H::hash([vec![seed], info].concat(), &mut key)?;
        Ok(key)
    }
}
