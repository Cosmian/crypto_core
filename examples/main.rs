mod examples;

/// Run all examples.
fn main() {
    #[cfg(all(feature = "chacha"))]
    self::examples::dem_vector_combined();
    #[cfg(all(feature = "chacha"))]
    self::examples::dem_vector_detached();
    #[cfg(all(feature = "chacha"))]
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

    #[cfg(feature = "curve25519")]
    self::examples::ed25519_static();
    #[cfg(feature = "curve25519")]
    self::examples::ed25519_cached();
    #[cfg(feature = "curve25519")]
    self::examples::ed25519_keypair();
}
