mod examples;
use examples::*;

/// Run all examples.
fn main() {
    dem_vector_combined();
    dem_vector_detached();
    dem_stream_be32();
    ecies_x25519_xchacha20_combined();
    ecies_x25519_xchacha20_stream();
    ed25519_static();
    ed25519_cached();
    ed25519_keypair();
}
