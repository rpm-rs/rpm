use clap::Parser;
use rpm::Package;
use std::path::PathBuf;

/// Demonstrate the remote/split signing workflow.
///
/// This example shows how to:
/// 1. Extract header bytes from an RPM
/// 2. Sign them externally (simulated here with a local key)
/// 3. Apply the resulting signature back to the package
///
/// In a real deployment, step 2 would happen on a remote signing service
/// (e.g. an HSM, Sigstore, or a signing server behind an API).
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the input RPM file
    rpm: PathBuf,

    /// Path to the private key (used here to simulate remote signing)
    #[arg(short, long)]
    key: PathBuf,

    /// Output path for the signed RPM
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut pkg = Package::open(&args.rpm)?;

    // Step 1: Extract the header bytes that need to be signed.
    let header_bytes = pkg.header_bytes()?;
    println!("Extracted {} header bytes for signing", header_bytes.len());

    // Step 2: Sign the header bytes.
    // In a real workflow, you would send `header_bytes` to a remote service
    // and receive `signature_bytes` back. Here we simulate it locally.
    let signature_bytes = simulate_remote_sign(&args.key, &header_bytes)?;
    println!("Received {} signature bytes", signature_bytes.len());

    // Step 3: Apply the signature to the package.
    pkg.apply_signature(signature_bytes)?;
    pkg.write_file(&args.output)?;
    println!("Wrote signed package to {}", args.output.display());

    Ok(())
}

/// Simulate a remote signing service by signing locally with a PGP key.
fn simulate_remote_sign(
    key_path: &std::path::Path,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rpm::Timestamp;
    use rpm::signature::Signing;
    use rpm::signature::pgp::Signer;

    let signer = Signer::from_asc_file(key_path)?;
    let signature = signer.sign(std::io::Cursor::new(data), Timestamp::now())?;
    Ok(signature)
}
