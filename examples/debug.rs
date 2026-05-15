use std::env;

use rpm::*;

fn main() -> Result<(), rpm::Error> {
    let pkg_path = env::args().nth(1).expect("Expected a path");

    let pkg = Package::open(pkg_path)?;

    println!("{}", pkg.metadata.signature);
    println!("{:?}", pkg.metadata.header);

    Ok(())
}

// TODO: better formatting

// tag 1000 (NAME): length 1
//     string: tree
// tag 1001 (VERSION): length 1
//     string: 1.7.0
// tag 1002 (RELEASE): length 1
//     string: 7.fc26
// tag 1004 (SUMMARY): length 1
//     translatable string: File system tree viewer
// tag 1005 (DESCRIPTION): length 1
//     translatable string: The tree utility recursively displays the contents of directories in a
//     tree-like format.  Tree is basically a UNIX port of the DOS tree
//     utility.
// tag 1009 (SIZE): length 1
//     int32: 99355
// tag 1014 (LICENSE): length 1
//     string: GPLv2+
// tag 1021 (OS): length 1
//     string: linux
// tag 1022 (ARCH): length 1
//     string: x86_64
