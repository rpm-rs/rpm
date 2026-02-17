use rpm::{Dependency, FileOptions, PackageBuilder, Scriptlet};
use std::path::PathBuf;

use clap::Parser;

/// Build a simple RPM package from scratch.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Output path for the built RPM
    #[arg(short, long, default_value = "example.rpm")]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut builder = PackageBuilder::new(
        "example-package",
        "1.0.0",
        "MIT",
        "noarch",
        "An example RPM built with rpm-rs",
    );

    builder
        .epoch(0)
        .release("1.el9")
        .description("This is a demonstration package built using the rpm-rs library.")
        .url("https://github.com/rpm-rs/rpm")
        .vendor("rpm-rs")
        .requires(Dependency::any("bash"))
        .requires(Dependency::greater_eq("glibc", "2.17"))
        .provides(Dependency::eq("example-package", "1.0.0-1.el9"))
        .pre_install_script(Scriptlet::new("echo 'Installing example-package...'"))
        .post_install_script(Scriptlet::new("echo 'Installation complete.'"))
        .with_file_contents(
            "#!/bin/bash\necho 'Hello from example-package!'\n",
            FileOptions::new("/usr/bin/example-hello").permissions(0o755),
        )?
        .with_file_contents(
            "# Example configuration\nkey = value\n",
            FileOptions::new("/etc/example-package.conf")
                .config()
                .permissions(0o644),
        )?;

    let pkg = builder.build()?;
    pkg.write_file(&args.output)?;
    println!("Built: {}", args.output.display());

    Ok(())
}
