use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Parser;
use rpm::{IndexData, PackageMetadata, display_tag_id};

/// Compare the headers of two RPM packages and report differences.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the first RPM file
    a: PathBuf,

    /// Path to the second RPM file
    b: PathBuf,
}

fn format_value(data: &IndexData) -> String {
    match data {
        IndexData::Null => "Null".to_string(),
        IndexData::StringTag(s) => format!("{s:?}"),
        IndexData::StringArray(v) | IndexData::I18NString(v) => {
            if v.len() == 1 {
                format!("{:?}", v[0])
            } else {
                format!("[{} strings]", v.len())
            }
        }
        IndexData::Bin(v) | IndexData::Char(v) | IndexData::Int8(v) => {
            if v.len() <= 16 {
                format!("{v:02x?}")
            } else {
                format!("[{} bytes]", v.len())
            }
        }
        IndexData::Int16(v) => format!("{v:?}"),
        IndexData::Int32(v) => format!("{v:?}"),
        IndexData::Int64(v) => format!("{v:?}"),
    }
}

fn diff_headers(label: &str, a_entries: Vec<(u32, IndexData)>, b_entries: Vec<(u32, IndexData)>) {
    let a_map: BTreeMap<u32, IndexData> = a_entries.into_iter().collect();
    let b_map: BTreeMap<u32, IndexData> = b_entries.into_iter().collect();

    let mut all_tags: Vec<u32> = a_map.keys().chain(b_map.keys()).copied().collect();
    all_tags.sort();
    all_tags.dedup();

    let mut diffs = 0;

    for tag in &all_tags {
        match (a_map.get(tag), b_map.get(tag)) {
            (Some(_), None) => {
                if diffs == 0 {
                    println!("\n{label}:");
                }
                diffs += 1;
                println!("  - {} (only in first)", display_tag_id(*tag));
            }
            (None, Some(_)) => {
                if diffs == 0 {
                    println!("\n{label}:");
                }
                diffs += 1;
                println!("  + {} (only in second)", display_tag_id(*tag));
            }
            (Some(a_val), Some(b_val)) if a_val != b_val => {
                if diffs == 0 {
                    println!("\n{label}:");
                }
                diffs += 1;
                println!("  ~ {}:", display_tag_id(*tag));
                println!("    < {}", format_value(a_val));
                println!("    > {}", format_value(b_val));
            }
            _ => {}
        }
    }

    if diffs == 0 {
        println!("\n{label}: identical");
    } else {
        println!("\n  {diffs} difference(s)");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let a = PackageMetadata::open(&args.a)?;
    let b = PackageMetadata::open(&args.b)?;

    let a_nevra = a.get_nevra()?;
    let b_nevra = b.get_nevra()?;
    println!("Comparing:");
    println!("  A: {a_nevra}");
    println!("  B: {b_nevra}");

    diff_headers(
        "Signature header",
        a.signature.get_all_entries()?,
        b.signature.get_all_entries()?,
    );

    diff_headers(
        "Main header",
        a.header.get_all_entries()?,
        b.header.get_all_entries()?,
    );

    Ok(())
}
