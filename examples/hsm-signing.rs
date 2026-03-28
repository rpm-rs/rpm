use clap::Parser;
use pgp::{
    adapter::RsaSigner,
    types::{KeyVersion, Timestamp},
};
use rpm::{Package, signature::pgp::HsmSigner};
use rsa::{RsaPrivateKey, pkcs1v15};
use std::path::PathBuf;

/// Sign an RPM with a random RPM key
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// RPM to sign
    #[arg(short, long)]
    input: PathBuf,

    /// RPM output after the signature
    #[arg(short, long)]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    let rsa_key =
        RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("failed to generate a key");
    let rsa_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key);

    // pgp::adapter::RsaSigner accept any key that implements [`signature::Keypair`] and
    // [`signature::PrehashSigner`].
    let rsa_signer =
        RsaSigner::new(rsa_key, KeyVersion::V4, Timestamp::now()).expect("create a PGP signer");

    let pgp_signer = HsmSigner::new(rsa_signer);

    let mut pkg = Package::open(args.input).expect("open source rpm");
    pkg.sign(pgp_signer)
        .expect("Sign the package with the private key");
    pkg.write_file(args.output).expect("write signed RPM");
}
