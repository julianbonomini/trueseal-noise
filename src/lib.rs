/// trueseal-noise — Noise_XX_25519_ChaChaPoly_BLAKE2s and Noise_NK_25519_ChaChaPoly_BLAKE2s
///
/// Implements the Noise Protocol Framework using the snow crate.
///
/// The `ffi` module exposes the public API to Swift and Kotlin via UniFFI.
pub mod ffi;
pub(crate) mod framing;
pub mod keypair;
pub(crate) mod session; // SessionInner + RetryConn — shared internals
pub mod session_nk;
pub mod session_xx;

#[cfg(test)]
mod prologue_vectors;
#[cfg(test)]
pub(crate) mod test_helpers;

// Re-export all FFI symbols at the crate root so the UniFFI-generated
// scaffolding (which calls crate::generate_keypair, crate::dial, etc.) can
// find them without qualification.
pub use ffi::*;

uniffi::include_scaffolding!("trueseal_noise");
