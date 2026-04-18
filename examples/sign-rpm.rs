use clap::Parser;
use rpm::{Package, signature::pgp::Signer};
use std::path::PathBuf;

/// Sign an RPM with a PGP private key.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the RPM file
    rpm: PathBuf,

    /// Path to the private key file (ASCII-armored)
    #[arg(short, long)]
    key: PathBuf,

    /// Output path (defaults to overwriting the input file)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Key passphrase (if the key is protected)
    #[arg(short, long)]
    passphrase: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut signer = Signer::from_asc_file(&args.key)?;
    if let Some(passphrase) = args.passphrase {
        signer = signer.with_key_passphrase(passphrase);
    }

    let output = args.output.as_ref().unwrap_or(&args.rpm);

    if output == &args.rpm {
        if Package::resign_in_place(&args.rpm, signer.clone()).is_err() {
            let mut pkg = Package::open(&args.rpm)?;
            pkg.sign(signer)?;
            pkg.write_file(output)?;
        }
    } else {
        let mut pkg = Package::open(&args.rpm)?;
        pkg.sign(signer)?;
        pkg.write_file(output)?;
    }

    println!("Signed: {}", output.display());

    Ok(())
}
