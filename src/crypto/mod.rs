mod traits;
pub use self::traits::*;

use log;

#[cfg(feature = "signing-pgp")]
pub mod pgp;

/// test helper to print signatures
pub(crate) fn echo_signature(scope: &str, signature: &[u8]) {
    log::debug!("{}: [len={}] [{:#04X?}, {:#04X?}, {:#04X?}, {:#04X?}, {:#04X?}, ...]", scope, signature.len(), signature[0], signature[1], signature[2], signature[3], signature[4]);
    log::trace!("{}: {:#04X?}", scope, signature);
}
