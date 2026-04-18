use clap::Parser;
use rpm::Nevra;
use std::cmp::Ordering;

/// Compare two NEVRA strings and print which is newer.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// First NEVRA (e.g. "bash-0:5.2.15-5.el9.x86_64")
    a: String,

    /// Second NEVRA (e.g. "bash-0:5.2.21-1.el9.x86_64")
    b: String,
}

fn main() {
    let args = Args::parse();

    let a = Nevra::parse(&args.a);
    let b = Nevra::parse(&args.b);

    match a.cmp(&b) {
        Ordering::Less => println!("{a} < {b}"),
        Ordering::Equal => println!("{a} == {b}"),
        Ordering::Greater => println!("{a} > {b}"),
    }
}
