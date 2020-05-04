mod traits;
pub use self::traits::*;

#[cfg(feature = "signature-pgp")]
pub mod pgp;

/// test helper to print signatures
pub fn echo_signature(scope: &str, signature: &[u8]) {
    log::debug!(
        "{}: [len={}] [{:#04X?}, {:#04X?}, {:#04X?}, {:#04X?}, {:#04X?}, ...]",
        scope,
        signature.len(),
        signature[0],
        signature[1],
        signature[2],
        signature[3],
        signature[4]
    );
}
