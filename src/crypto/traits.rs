//! Trait abstractions of cryptographic operations.
//!
//! Does not contain hashing! Hashes are fixed by the rpm
//! "spec" to sha1, md5 (yes, that is correct), sha2_256.

#[allow(unused)]
use crate::errors::*;
use std::fmt::Debug;

pub mod algorithm {

    pub trait Algorithm: super::Debug {}
    /// currently only RSA is required
    ///
    /// Farsight for future algorithm extensions of rpm
    /// without breaking the API
    #[derive(Debug, Clone, Copy)]
    #[allow(non_camel_case_types)]

    pub struct RSA;

    impl Algorithm for RSA {}
}

use pem;

/// Signing trait to be implement for RPM signing.
pub trait Signing<A>: Debug
where
    A: algorithm::Algorithm,
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn sign(&self, data: &[u8]) -> Result<Self::Signature, RPMError>;
}

/// Verification trait to be implement for RPM signature verification.
pub trait Verifying<A>: Debug
where
    A: algorithm::Algorithm,
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), RPMError>;
}

pub mod key {

    /// Marker trait for key types.
    pub trait KeyType: super::Debug + Copy {}

    /// A secret key that should not be shared with any other party
    /// under any circumstance.
    #[derive(Debug, Clone, Copy)]
    pub struct Secret;

    /// A key publishable to the public.
    #[derive(Debug, Clone, Copy)]
    pub struct Public;

    impl KeyType for Secret {}
    impl KeyType for Public {}
}

/// Public and secret key loading trait.
///
/// Supposed to load application specific formatted keys with
/// `fn load_from` in whatever format is desired or used by the
/// [`Signer`](Self::Signing) or [`Verifier`](Self::Verifying) itself.
pub trait KeyLoader<T>: Sized
where
    T: key::KeyType,
{
    /// An application specific key loader.
    ///
    /// Should be implemented as a combination of the particular ones.
    fn load_from(bytes: &[u8]) -> Result<Self, RPMError>;

    /// Load a key from ascii armored key string.
    fn load_from_asc(_asc: &str) -> Result<Self, RPMError> {
        unimplemented!("ASCII ARMORED is not implemented")
    }

    /// Load a key from DER ASN.1 formatted bytes in PKCS#1 format.
    ///
    /// Its preamble is `-----BEGIN RSA (PRIVATE|PUBLIC) KEY-----`
    fn load_from_pkcs1_der(_pkcs1_der: &[u8]) -> Result<Self, RPMError> {
        unimplemented!("PKCS#1 der loading is not implemented")
    }

    /// Load a key from DER ASN.1 formatted bytes in PKCS#8 format.
    ///
    /// Its preamble is `-----BEGIN (ENCRYPTED)? (PRIVATE|PUBLIC) KEY-----`
    fn load_from_pkcs8_der(_pkcs8_der: &[u8]) -> Result<Self, RPMError> {
        unimplemented!("PKCS#8 der loading is not implemented")
    }

    /// Load a key from PEM formatted string in PKCS#8 or PKCS#1 internal format.
    fn load_from_pem(pem: &str) -> Result<Self, RPMError> {
        let pem = pem::parse(pem).map_err(|e| format!("Failed to parse pem format: {:?}", e))?;
        // PEM may containe any kind of key format, so at least support
        // well know PKCS#1 and PKCS#8 formats
        match pem.tag.as_str() {
            "RSA PRIVATE KEY" | "RSA PUBLIC KEY" => {
                Self::load_from_pkcs1_der(pem.contents.as_slice())
            }
            "PRIVATE KEY" | "PUBLIC KEY" => Self::load_from_pkcs8_der(pem.contents.as_slice()),
            _ => Err(RPMError::from(
                "Unknown key delimiter, only supporting PKCS#8 or PKCS#1 PRIVATE/PUBLIC keys"
                    .to_owned(),
            )),
        }
    }

    /// Load a key from the openssh specific format.
    fn load_from_openssh(_openssh: &[u8]) -> Result<Self, RPMError> {
        unimplemented!("OpenSSH loading is not implemented")
    }
}

/// Implement unreachable signer for empty tuple `()`
impl<A> Signing<A> for std::marker::PhantomData<A>
where
    A: algorithm::Algorithm,
{
    type Signature = Vec<u8>;
    fn sign(&self, _data: &[u8]) -> Result<Self::Signature, RPMError> {
        unreachable!("if you want to verify, you need to implement `sign` of the `Signing` trait")
    }
}

/// Implement unreachable verifier for the empty tuple`()`
impl<A> Verifying<A> for std::marker::PhantomData<A>
where
    A: algorithm::Algorithm,
{
    type Signature = Vec<u8>;
    fn verify(&self, _data: &[u8], _x: &[u8]) -> Result<(), RPMError> {
        unreachable!(
            "if you want to verify, you need to implement `verify` of the `Verifying` trait"
        )
    }
}

#[cfg(test)]
pub(crate) mod test {


    use super::*;
    use crate::crypto::{
        algorithm::Algorithm, echo_signature, KeyLoader, Signing, Verifying,
    };
    use crate::errors::RPMError;
    use env_logger;

    #[allow(unused)]
    pub(crate) fn sign_verify_roundtrip_blueprint<S, V, A>(
        data: &[u8],
        signing_key: &[u8],
        verification_key: &[u8],
    ) -> Result<(), RPMError>
    where
        S: Signing<A, Signature = Vec<u8>> + KeyLoader<key::Secret>,
        V: Verifying<A, Signature = Vec<u8>> + KeyLoader<key::Public>,
        A: Algorithm,
    {
        let _ = env_logger::try_init();
        let signer = S::load_from(signing_key).expect("Failed to load signer from secret key");
        let verifier =
            V::load_from(verification_key).expect("Failed to load verifier from public key");
        let signature = signer.sign(data)?;
        echo_signature("test/roundtrip", signature.as_slice());
        verifier.verify(data, signature.as_slice())?;

        Ok(())
    }

	#[allow(unused)]
    pub(crate) fn load_der_keys() -> (Vec<u8>, Vec<u8>) {
        let signing_key = include_bytes!("../../test_assets/id_rsa.der");
        let verification_key = include_bytes!("../../test_assets/id_rsa.pub.der");
        (signing_key.to_vec(), verification_key.to_vec())
    }

	#[allow(unused)]
    pub(crate) fn load_pem_keys() -> (Vec<u8>, Vec<u8>) {
        let signing_key = include_bytes!("../../test_assets/id_rsa.pem");
        let verification_key = include_bytes!("../../test_assets/id_rsa.pub.pem");
        (signing_key.to_vec(), verification_key.to_vec())
    }

    pub(crate) fn load_asc_keys() -> (Vec<u8>, Vec<u8>) {
        let signing_key = include_bytes!("../../test_assets/id_rsa.asc");
        let verification_key = include_bytes!("../../test_assets/id_rsa.pub.asc");
        (signing_key.to_vec(), verification_key.to_vec())
    }
}
