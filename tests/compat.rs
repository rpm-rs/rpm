use std::io::BufReader;
use std::io::prelude::*;
use std::path::Path;
use std::process::Stdio;

use rpm::*;

mod common;

#[cfg(target_os = "linux")]
mod pgp {
    use super::*;
    use rpm::signature::pgp::{Signer, Verifier};

    /// Signature algorithms that a distro's RPM may or may not support.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Algorithm {
        Rsa,
        Ecdsa,
        Eddsa,
        // Mldsa,  TODO: add to matrix once support exists somewhere
    }

    /// RPM format versions.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum RpmFormat {
        V4,
        V6,
    }

    struct Distro {
        image: &'static str,
        algorithms: &'static [Algorithm],
        formats: &'static [RpmFormat],
    }

    impl Distro {
        fn supports(&self, alg: Algorithm, fmt: RpmFormat) -> bool {
            self.algorithms.contains(&alg) && self.formats.contains(&fmt)
        }
    }

    // NOTE: If a distro gains support for an algorithm or format, update the relevant entry.
    const DISTROS: &[Distro] = &[
        Distro {
            image: "quay.io/almalinuxorg/8-base",
            algorithms: &[Algorithm::Rsa],
            formats: &[RpmFormat::V4],
        },
        Distro {
            image: "quay.io/centos/centos:stream9",
            algorithms: &[Algorithm::Rsa, Algorithm::Eddsa],
            formats: &[RpmFormat::V4],
        },
        Distro {
            image: "quay.io/centos/centos:stream10",
            algorithms: &[Algorithm::Rsa, Algorithm::Ecdsa, Algorithm::Eddsa],
            formats: &[RpmFormat::V4, RpmFormat::V6],
        },
        Distro {
            image: "quay.io/fedora/fedora:latest",
            algorithms: &[Algorithm::Rsa, Algorithm::Ecdsa, Algorithm::Eddsa],
            formats: &[RpmFormat::V4, RpmFormat::V6],
        },
    ];

    /// Install and checksig a package on distros that support the given
    /// algorithm and format. Pass `None` for unsigned packages (all distros).
    #[track_caller]
    fn try_installation_and_verify_signatures(
        required: Option<(Algorithm, RpmFormat)>,
        path: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cmd = format!(
            r#"
dnf ${{REPOS}} install -y {pkg_path};
rpm -vv --checksig {pkg_path} 2>&1;"#,
            pkg_path = path.as_ref().display()
        );

        for distro in DISTROS {
            let should_run = match required {
                Some((alg, fmt)) => distro.supports(alg, fmt),
                None => true,
            };
            if should_run {
                podman_container_launcher(&cmd, distro.image, vec![])?;
            }
        }
        Ok(())
    }

    fn build_full_rpm() -> Result<PackageBuilder, Box<dyn std::error::Error>> {
        let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");
        let config = BuildConfig::default().compression(CompressionType::Gzip);

        let bldr = PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some package")
            .using_config(config)
            .with_file(
                cargo_file.to_str().unwrap(),
                FileOptions::new("/etc/foobar/foo.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                FileOptions::new("/etc/foobar/zazz.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                FileOptions::new("/etc/foobar/hugo/bazz.toml")
                    .permissions(0o777)
                    .config()
                    .noreplace(),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                FileOptions::new("/etc/foobar/bazz.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                FileOptions::new("/etc/foobar/hugo/aa.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                FileOptions::new("/var/honollulu/bazz.toml"),
            )?
            .with_file(
                cargo_file.to_str().unwrap(),
                FileOptions::new("/etc/Cargo.toml"),
            )?
            .with_symlink(FileOptions::symlink(
                "/usr/bin/awesome_link",
                "/usr/bin/awesome",
            ))?
            .with_dir_entry(
                FileOptions::dir("/var/log/foobar")
                    .user("root")
                    .permissions(0o750),
            )?
            .with_ghost(FileOptions::ghost("/var/log/foobar/app.log"))?
            .with_ghost(FileOptions::ghost_dir("/var/run/foobar"))?
            .epoch(1)
            .pre_install_script("echo preinst")
            .add_changelog_entry(
                "me",
                "was awesome, eh?",
                chrono::DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").unwrap(),
            )
            .add_changelog_entry(
                "you",
                "yeah, it was",
                chrono::DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").unwrap(),
            )
            .requires(Dependency::any("rpm-sign".to_string()))
            .vendor("dummy vendor")
            .url("dummy url")
            .vcs("dummy vcs");

        Ok(bldr)
    }

    /// Verify fixture packages against both rpm-rs and rpm (with --checksig),
    /// only running each package on distros that support its algorithm and format.
    #[test]
    fn test_verify_externally_signed_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();

        let fixture_pkgs: &[(Algorithm, RpmFormat, &str, &str)] = &[
            (
                Algorithm::Rsa,
                RpmFormat::V4,
                common::pkgs::v4::RPM_BASIC_RSA_SIGNED,
                common::keys::v4::RSA_4K_PUBLIC,
            ),
            (
                Algorithm::Ecdsa,
                RpmFormat::V4,
                common::pkgs::v4::RPM_BASIC_ECDSA_SIGNED,
                common::keys::v4::ECDSA_NISTP256_PUBLIC,
            ),
            (
                Algorithm::Eddsa,
                RpmFormat::V4,
                common::pkgs::v4::RPM_BASIC_EDDSA_SIGNED,
                common::keys::v4::ED25519_PUBLIC,
            ),
            (
                Algorithm::Rsa,
                RpmFormat::V6,
                common::pkgs::v6::RPM_BASIC_RSA_SIGNED,
                common::keys::v6::RSA4K_PUBLIC,
            ),
            (
                Algorithm::Eddsa,
                RpmFormat::V6,
                common::pkgs::v6::RPM_BASIC_EDDSA_SIGNED,
                common::keys::v6::ED25519_PUBLIC,
            ),
            // (
            //     Algorithm::Mldsa,
            //     RpmFormat::V6,
            //     common::pkgs::v6::RPM_BASIC_MLDSA_SIGNED,
            //     common::keys::v6::MLDSA65_ED25519_PUBLIC,
            // ),
        ];

        // Verify all packages with rpm-rs (works regardless of distro)
        for (_alg, _fmt, pkg_path, pubkey_path) in fixture_pkgs {
            let verifier = Verifier::from_asc_file(pubkey_path)?;
            let package = rpm::Package::open(pkg_path)?;
            package.verify_signature(verifier)?;
        }

        // Then, verify with each distro's rpm --checksig, filtered by capability
        for distro in DISTROS {
            let mut cmd = String::new();

            for (alg, fmt, pkg_path, _pubkey_path) in fixture_pkgs {
                if !distro.supports(*alg, *fmt) {
                    continue;
                }

                let rpm_file = Path::new(pkg_path).file_name().unwrap().to_str().unwrap();

                let assets_subdir = match fmt {
                    RpmFormat::V4 => "RPMS/v4/signed",
                    RpmFormat::V6 => "RPMS/v6/signed",
                };

                cmd.push_str(&format!(
                    r#"
echo ">>> verify signature with rpm: {rpm_file}"
rpm -vv --checksig /assets/{assets_subdir}/{rpm_file} 2>&1
"#,
                ));
            }

            if !cmd.is_empty() {
                podman_container_launcher(&cmd, distro.image, vec![])?;
            }
        }

        Ok(())
    }

    /// Build an empty RPM using rpm-rs, and install it
    #[test]
    #[serial_test::serial]
    fn test_install_empty_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let pkg =
            PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package").build()?;
        let out_file = Path::new(common::CARGO_OUT_DIR).join("empty_rpm_nosig.rpm");
        pkg.write_file(&out_file)?;

        try_installation_and_verify_signatures(None, "/out/empty_rpm_nosig.rpm")?;

        Ok(())
    }

    /// Build and sign an empty RPM using rpm-rs, install it, test verifying the signatures
    #[test]
    #[serial_test::serial]
    fn test_install_empty_rpm_with_signature() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;

        let pkg = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
            .build_and_sign(&signer)?;
        let out_file = Path::new(common::CARGO_OUT_DIR).join("empty_rpm_sig.rpm");
        pkg.write_file(&out_file)?;

        try_installation_and_verify_signatures(
            Some((Algorithm::Rsa, RpmFormat::V4)),
            "/out/empty_rpm_sig.rpm",
        )?;

        Ok(())
    }

    /// Build an RPM using rpm-rs, and install it
    #[test]
    #[serial_test::serial]
    fn test_install_full_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let pkg = build_full_rpm()?.build()?;
        let out_file = Path::new(common::CARGO_OUT_DIR).join("full_rpm_nosig.rpm");
        pkg.write_file(&out_file)?;
        assert_eq!(1, pkg.metadata.get_epoch()?);

        try_installation_and_verify_signatures(None, "/out/full_rpm_nosig.rpm")?;

        Ok(())
    }

    /// Build and sign an RPM using rpm-rs, install it, test verifying the signatures
    #[test]
    #[serial_test::serial]
    fn test_install_full_rpm_with_signature() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;

        let pkg = build_full_rpm()?.build_and_sign(signer)?;
        let out_file = Path::new(common::CARGO_OUT_DIR).join("full_rpm_sig.rpm");
        pkg.write_file(&out_file)?;
        assert_eq!(1, pkg.metadata.get_epoch()?);

        try_installation_and_verify_signatures(
            Some((Algorithm::Rsa, RpmFormat::V4)),
            "/out/full_rpm_sig.rpm",
        )?;

        Ok(())
    }

    /// Build and sign an RPM using rpm-rs with a passphrase-protected key, install it, test verifying the signatures
    #[test]
    #[serial_test::serial]
    fn test_install_full_rpm_with_sig_key_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let signer = Signer::from_asc_file(common::keys::v4::RSA_3K_PROTECTED_PRIVATE)?
            .with_key_passphrase(common::keys::v4::RSA_3K_PASSPHRASE);

        let pkg = build_full_rpm()?.build_and_sign(signer)?;
        let out_file = Path::new(common::CARGO_OUT_DIR).join("full_rpm_sig_protected.rpm");
        pkg.write_file(&out_file)?;
        assert_eq!(1, pkg.metadata.get_epoch()?);

        try_installation_and_verify_signatures(
            Some((Algorithm::Rsa, RpmFormat::V4)),
            "/out/full_rpm_sig_protected.rpm",
        )?;

        Ok(())
    }
}

fn wait_and_print_helper(mut child: std::process::Child, stdin_cmd: &str) -> std::io::Result<()> {
    if let Some(ref mut stdin) = child.stdin {
        write!(stdin, "{}", stdin_cmd).unwrap();
    } else {
        unreachable!("Must have stdin");
    }
    // not perfect, but gets it done
    if let Some(ref mut stdout) = child.stdout {
        if let Some(ref mut stderr) = child.stderr {
            let stdout_rdr = BufReader::new(stdout);
            let mut stdout_line = stdout_rdr.lines();

            let stderr_rdr = BufReader::new(stderr);
            let mut stderr_line = stderr_rdr.lines();

            let mut done: bool = false;
            while !done {
                done = true;
                for line in &mut stdout_line {
                    done = false;
                    println!("[stdout] {}", line.unwrap().as_str());
                }
                for line in &mut stderr_line {
                    done = false;
                    println!("[stderr] {}", line.unwrap().as_str());
                }
            }
        } else {
            unreachable!("Must have stderr");
        }
    } else {
        unreachable!("Must have stdout");
    }

    let status = child.wait()?;
    assert!(status.success());
    Ok(())
}

fn podman_container_launcher(
    cmd: &str,
    image: &str,
    mut mappings: Vec<String>,
) -> std::io::Result<()> {
    // always mount assets and out directory into container
    let var_cache = Path::new(common::CARGO_MANIFEST_DIR).join("dnf-cache");
    let _ = std::fs::create_dir(var_cache.as_path());
    let var_cache = format!("{}:/var/cache/dnf", var_cache.display());
    let out = format!("{}:/out", common::CARGO_OUT_DIR);
    let assets = format!("{}/tests/assets:/assets:ro", common::CARGO_MANIFEST_DIR,);
    mappings.extend(vec![out, assets, var_cache]);
    let mut args = mappings.iter().fold(
        vec!["run", "-i", "--rm", "--security-opt", "label=disable"],
        |mut acc, mapping| {
            acc.extend(vec!["-v", mapping]);
            acc
        },
    );
    args.extend(vec![image, "sh"]);

    let mut podman_cmd = std::process::Command::new("podman");

    podman_cmd.args(dbg!(args));
    podman_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    podman_cmd.stdin(Stdio::piped());

    podman_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    podman_cmd.stdin(Stdio::piped());

    // partially following: https://access.redhat.com/articles/3359321
    let setup = r#"
set -e

# Common defaults for package management
REPOS="--disablerepo=* --enablerepo=fedora"
PACKAGES="rpm-sign gpg"

# Mirrorlist no longer supported on centos, disable
if grep -Eq "ID=.*(centos|almalinux)" /etc/os-release; then
    mirrorlist_repos=$(grep -l mirrorlist.centos.org /etc/yum.repos.d/* || true)
    if [ -n "$mirrorlist_repos" ]; then
        sed -i s/mirror.centos.org/vault.centos.org/g $mirrorlist_repos
        sed -i s/^#.*baseurl=http/baseurl=http/g $mirrorlist_repos
        sed -i s/^mirrorlist=http/#mirrorlist=http/g $mirrorlist_repos
    fi

    REPOS="--disablerepo=* --enablerepo=base*"
    PACKAGES="rpm-sign gpg"
fi

echo "\### install tooling for signing"

dnf install ${REPOS} -y ${PACKAGES}

pushd assets/
sh import_keys.sh
popd

gpg --keyid-format long --list-secret-keys
gpg --keyid-format long --list-public-keys

set -x

echo "\### Prelude over, executing user-provided command"
"#;

    let teardown = r#"
echo "\### Container should exit any second now"
exit 0
"#;

    let cmd = vec![setup, cmd, teardown].join("\n");

    println!("Container execution starting using image \"{}\"...", image);

    // this is far from perfect, but at least pumps stdio and stderr out
    wait_and_print_helper(podman_cmd.spawn()?, cmd.as_str())?;
    println!("Container execution ended.");
    Ok(())
}
