use std::path::Path;
use std::time::Instant;

fn visit_dir(
    dir: &Path,
    total: &mut u64,
    errors: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            visit_dir(&path, total, errors)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rpm") {
            *total += 1;
            match rpm::PackageMetadata::open(&path) {
                Ok(meta) => {
                    let nevra = meta.get_nevra()?;
                    let files = meta.get_file_entries()?;
                    println!("{nevra} ({} files)", files.len());
                    for f in &files {
                        println!("  {}", f.path.display());
                    }
                }
                Err(e) => {
                    *errors += 1;
                    eprintln!("ERROR {}: {e}", path.display());
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_dir = std::env::args_os().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: parse_repo <directory>");
        std::process::exit(1);
    });

    let mut total = 0u64;
    let mut errors = 0u64;

    let start = Instant::now();
    visit_dir(Path::new(&repo_dir), &mut total, &mut errors)?;
    let elapsed = start.elapsed();

    println!("\nParsed {total} packages ({errors} errors) in {elapsed:.2?}");

    Ok(())
}
