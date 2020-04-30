// re-export
#[cfg(feature = "signing-pgp")]
pub use crate::crypto::{
    self,
    pgp::{Signer as SignerPGP, Verifier as VerifierPGP},
};
