//! Trait abstractions of signing operations.
//!
//! Does not contain hashing! Hashes are fixed by the rpm
//! "spec" to sha1, md5 (yes, that is correct), sha2_256.

use crate::errors::*;
use crate::Timestamp;
use std::fmt::Debug;
use std::io;

#[derive(Clone, Copy, Debug)]
pub enum AlgorithmType {
    RSA,
    ECDSA,
    EdDSA,
}

/// Signing trait to be implement for RPM signing.
pub trait Signing: Debug
where
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn sign(&self, data: impl io::Read, t: Timestamp) -> Result<Self::Signature, Error>;
    fn algorithm(&self) -> AlgorithmType;
}

impl<T, S> Signing for &T
where
    T: Signing<Signature = S>,
    S: AsRef<[u8]>,
{
    type Signature = S;
    fn sign(&self, data: impl io::Read, t: Timestamp) -> Result<Self::Signature, Error> {
        T::sign(self, data, t)
    }

    fn algorithm(&self) -> AlgorithmType {
        T::algorithm(self)
    }
}

/// Verification trait to be implement for RPM signature verification.
pub trait Verifying: Debug
where
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn verify(&self, data: impl io::Read, signature: &[u8]) -> Result<(), Error>;
    fn algorithm(&self) -> AlgorithmType;
}

impl<T, S> Verifying for &T
where
    T: Verifying<Signature = S>,
    S: AsRef<[u8]>,
{
    type Signature = S;
    fn verify(&self, data: impl io::Read, signature: &[u8]) -> Result<(), Error> {
        T::verify(self, data, signature)
    }

    fn algorithm(&self) -> AlgorithmType {
        T::algorithm(self)
    }
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

/// Implement unreachable signer for empty tuple `()`
impl<T> Signing for std::marker::PhantomData<T> {
    type Signature = Vec<u8>;
    fn sign(&self, _data: impl io::Read, _t: Timestamp) -> Result<Self::Signature, Error> {
        unreachable!("you need to implement `sign` of the `Signing` trait")
    }

    fn algorithm(&self) -> AlgorithmType {
        unreachable!("you need to implement `algorithm` of the `Signing` trait")
    }
}

/// Implement unreachable verifier for the empty tuple`()`
impl<T> Verifying for std::marker::PhantomData<T> {
    type Signature = Vec<u8>;
    fn verify(&self, _data: impl io::Read, _x: &[u8]) -> Result<(), Error> {
        unreachable!("you need to implement `verify` of the `Verifying` trait")
    }

    fn algorithm(&self) -> AlgorithmType {
        unreachable!("you need to implement `algorithm` of the `Verifying` trait")
    }
}
