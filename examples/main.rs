mod examples;
use examples::{
    dem_stream_be32, dem_vector_combined, dem_vector_detached, ecies_x25519_xchacha20_combined,
    ecies_x25519_xchacha20_stream, ed25519_cached, ed25519_keypair, ed25519_static,
};

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
