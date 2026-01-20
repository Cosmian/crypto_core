mod examples;

/// Run all examples.
fn main() {
    #[cfg(feature = "chacha")]
    self::examples::dem_vector_combined();
    #[cfg(feature = "chacha")]
    self::examples::dem_vector_detached();
    #[cfg(feature = "chacha")]
    self::examples::dem_stream_be32();

    #[cfg(all(
        feature = "ecies",
        feature = "chacha",
        feature = "blake",
        feature = "curve25519"
    ))]
    self::examples::ecies_x25519_xchacha20_combined();

    #[cfg(all(
        feature = "ecies",
        feature = "chacha",
        feature = "blake",
        feature = "curve25519"
    ))]
    self::examples::ecies_x25519_xchacha20_stream();

    #[cfg(all(
        feature = "ecies",
        feature = "aes",
        feature = "sha3",
        feature = "nist_curves"
    ))]
    self::examples::ecies_p256_aes128_combined();

    #[cfg(all(
        feature = "ecies",
        feature = "aes",
        feature = "sha3",
        feature = "nist_curves",
        feature = "chacha"
    ))]
    self::examples::ecies_p256_aes128_stream();

    #[cfg(feature = "curve25519")]
    self::examples::ed25519_static();
    #[cfg(feature = "curve25519")]
    self::examples::ed25519_cached();
    #[cfg(feature = "curve25519")]
    self::examples::ed25519_keypair();

    #[cfg(feature = "rsa")]
    self::examples::rsa_key_wrapping();
}
