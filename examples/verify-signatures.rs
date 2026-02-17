use clap::Parser;
use rpm::{Package, signature::pgp::Verifier};
use std::path::PathBuf;

/// Verify the signatures and digests of an RPM package.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the RPM file
    rpm: PathBuf,

    /// Path to a public key file (ASCII-armored)
    #[arg(short, long)]
    key: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let pkg = Package::open(&args.rpm)?;

    let verifier = match &args.key {
        Some(path) => Verifier::from_asc_file(path)?,
        None => Verifier::new(),
    };

    let report = pkg.check_signatures(verifier)?;

    println!("Digest verification:");
    println!("  Header SHA1      : {:?}", report.digests.header_sha1);
    println!("  Header SHA256    : {:?}", report.digests.header_sha256);
    println!("  Header SHA3-256  : {:?}", report.digests.header_sha3_256);
    println!("  Payload SHA256   : {:?}", report.digests.payload_sha256);
    println!("  Payload SHA512   : {:?}", report.digests.payload_sha512);
    println!("  Payload SHA3-256 : {:?}", report.digests.payload_sha3_256);

    if report.signatures.is_empty() {
        println!("\nNo signatures found.");
    } else {
        println!("\nSignatures:");
        for sig in &report.signatures {
            let info = &sig.info;
            let algo = info
                .algorithm()
                .map_or("unknown".to_string(), |a| format!("{a:?}"));
            let hash = info
                .hash_algorithm()
                .map_or("unknown".to_string(), |h| format!("{h:?}"));
            print!("  {algo} / {hash}");
            if let Some(fp) = info.fingerprint() {
                print!(" [{fp}]");
            }
            if sig.is_verified() {
                println!(" — OK");
            } else if let Some(err) = &sig.error {
                println!(" — FAILED: {err}");
            }
        }
    }

    let ok = if args.key.is_some() {
        report.is_ok()
    } else {
        report.digests.is_ok()
    };

    if ok {
        println!("\nResult: OK");
    } else {
        println!("\nResult: FAILED");
        std::process::exit(1);
    }

    Ok(())
}
