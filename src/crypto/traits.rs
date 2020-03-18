
use crate::errors::*;

pub trait Algorithm : Debug {}

/// currently only RSA is required
/// 
/// Farsight for future algorithm extensions of rpm
/// without breaking the API
#[derive(Debug,Clone,Copy)]
pub struct RSA_SHA256;

impl Algorithm for RSA_SHA256 {}

use std::fmt::Debug;

pub trait Signing<A> : Debug where A: Algorithm, Self::Signature : AsRef<[u8]> {
    type Signature;
    fn sign(&self,  data : &[u8]) -> Result<Self::Signature, RPMError>;
}


pub trait Verifying<A> : Debug where A: Algorithm, Self::Signature : AsRef<[u8]> {
    type Signature;
    fn verify(&self, data : &[u8], expected_digest : Self::Signature) -> Result<(), RPMError>;
}

pub trait LoaderPkcs8 : Sized {
    fn load_from_pkcs8(bytes : &[u8]) -> Result<Self, RPMError>;
}


// implement unreachable signer and verifyer for ()
impl<A> Signing<A> for std::marker::PhantomData<A> where A: Algorithm {
    type Signature = Vec<u8>;
    fn sign(&self,  _data : &[u8]) -> Result<Self::Signature, RPMError> {
        unreachable!("if you want to sign, use a frickin proper signer")
    }
}

impl<A> Verifying<A> for std::marker::PhantomData<A> where A: Algorithm {
    type Signature = Vec<u8>;
    fn verify(&self, _data : &[u8], expected_digest : Self::Signature) -> Result<(), RPMError> {
        unreachable!("if you want to verify, use a frickin proper signer")
    }
}