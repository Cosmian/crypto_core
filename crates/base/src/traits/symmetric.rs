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
pub trait AEAD<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const TAG_LENGTH: usize> {
    /// The length of the key.
    const KEY_LENGTH: usize = KEY_LENGTH;

    /// The length of the nonce.
    const NONCE_LENGTH: usize = NONCE_LENGTH;

    /// The length of the authentication tag.
    const TAG_LENGTH: usize = TAG_LENGTH;

    type Error: std::error::Error;

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
    type Error = E::Error;

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

#[allow(non_camel_case_types)]
pub trait KDF_InPlace<const KEY_LENGTH: usize> {
    type Error: std::error::Error;

    fn derive(key: &mut [u8; KEY_LENGTH], seed: &[u8], info: Vec<&[u8]>)
        -> Result<(), Self::Error>;
}

impl<const LENGTH: usize, H: HASH<LENGTH>> KDF_InPlace<LENGTH> for H {
    type Error = H::Error;

    fn derive(key: &mut [u8; LENGTH], seed: &[u8], info: Vec<&[u8]>) -> Result<(), Self::Error> {
        let mut state = <H as HASH<LENGTH>>::initialize()?;
        H::update(&mut state, seed)?;
        H::update(&mut state, &info.concat())?;
        H::finalize(state, key)?;
        // TODO: we would like to be able to enforce having a zeroizable state, but
        // sadly not enough dependency provide it.
        //
        // state.zeroize();
        Ok(())
    }
}

/// Key Derivation Function.
pub trait KDF<const KEY_LENGTH: usize> {
    type Error: std::error::Error;

    fn derive(seed: &[u8], info: Vec<&[u8]>) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error>;
}

impl<const KEY_LENGTH: usize, T: KDF_InPlace<KEY_LENGTH>> KDF<KEY_LENGTH> for T {
    type Error = T::Error;

    fn derive(seed: &[u8], info: Vec<&[u8]>) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error> {
        let mut key = SymmetricKey::default();
        T::derive(&mut key, seed, info)?;
        Ok(key)
    }
}

pub trait SHA256: HASH<32> {}
pub trait SHA512: HASH<64> {}

pub trait SHA3_256: HASH<32> {}
pub trait SHA3_512: HASH<64> {}

pub trait Shake128: XOF {}
pub trait Shake256: XOF {}

pub fn test_sha256<Sha256: SHA256>() {
    // Source: https://www.dlitz.net/crypto/shad256-test-vectors/SHAd256_Test_Vectors.txt

    // test vector NIST.1
    {
        let mut res = [0; 32];
        Sha256::hash(vec![&[0x61, 0x62, 0x63]], &mut res).unwrap();
        assert_eq!(
            res,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        )
    }

    // test vector NIST.2
    {
        let mut res = [0; 32];
        Sha256::hash(
            vec![&[
                0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 0x65, 0x66, 0x64, 0x65,
                0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69, 0x67, 0x68, 0x69, 0x6a,
                0x68, 0x69, 0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c,
                0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f, 0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71,
            ]],
            &mut res,
        )
        .unwrap();
        assert_eq!(
            res,
            [
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
                0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
                0x19, 0xdb, 0x06, 0xc1,
            ]
        )
    }
}
