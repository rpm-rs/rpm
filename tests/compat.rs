use std::io::BufReader;
use std::io::prelude::*;
use std::path::Path;
use std::process::Stdio;

use rpm::*;

mod common;

#[cfg(target_os = "linux")]
mod pgp {
    use super::*;
    use rpm::signature::pgp::Signer;

    #[track_caller]
    fn execute_against_supported_distros(cmd: &str) -> Result<(), Box<dyn std::error::Error>> {
        let distros = [
            "quay.io/fedora/fedora:latest",
            "quay.io/centos/centos:stream10",
            "quay.io/centos/centos:stream9",
            "quay.io/almalinuxorg/8-base",
        ];

        distros.iter().try_for_each(|image| {
            podman_container_launcher(&cmd, image, vec![])?;
            Ok(())
        })
    }

    /// Verify that the RPM is installable with valid signatures on the various supported distros
    #[track_caller]
    fn try_installation_and_verify_signatures(
        path: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cmd = format!(
            r#"
dnf ${{REPOS}} install -y {pkg_path};
rpm -vv --checksig {pkg_path} 2>&1;"#,
            pkg_path = path.as_ref().display()
        );

        execute_against_supported_distros(&cmd)
    }

    fn build_full_rpm() -> Result<PackageBuilder, Box<dyn std::error::Error>> {
        let cargo_file = common::cargo_manifest_dir().join("Cargo.toml");
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
                    .mode(0o100_777)
                    .is_config_noreplace(),
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
            .with_file(
                "./test_assets/empty_file_for_symlink_create",
                FileOptions::new("/usr/bin/awesome_link")
                    .mode(0o120644)
                    .symlink("/usr/bin/awesome"),
            )?
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

    /// Verify fixture packages against both rpm-rs and rpm (with --checksig)
    #[test]
    #[ignore = "TODO: needs static assets"]
    fn test_verify_externally_signed_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        // let pkgs = [
        //     (
        //         common::rpm_basic_pkg_path_rsa_signed(),
        //         common::rsa_public_key(),
        //     ),
        //     (common::rpm_basic_pkg_path_rsa_signed_protected(), common::rsa_public_key_protected()),
        //     (common::rpm_basic_pkg_path_ecdsa_signed(), common::ecdsa_public_key()),
        //     (common::rpm_basic_pkg_path_eddsa_signed(), common::eddsa_public_key()),
        // ];

        // TODO: currently only RSA-signed packages are accepted across the full range of supported distros
        // it would be nice to test others here as well, but that requires a bit more finesse

        let cmd = String::new();

        //         for (pkg_path, pubkey) in &pkgs {
        //             let verifier = Verifier::load_from_asc_bytes(pubkey.as_ref())?;
        //             let package = rpm::Package::open(pkg_path)?;
        //             package.verify_signature(verifier)?;

        //             let pkg_cmd = format!(
        //                 r#"
        // echo ">>> verify signature with rpm"
        // rpm -vv --checksig /assets/RPMS/signed/{rpm_file} 2>&1
        // "#,
        //                 rpm_file = pkg_path.file_name().unwrap().to_str().unwrap()
        //             );
        //             cmd.push_str(&pkg_cmd);
        //         }

        execute_against_supported_distros(&cmd)
    }

    /// Build an empty RPM using rpm-rs, and install it
    #[test]
    #[serial_test::serial]
    fn test_install_empty_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let pkg =
            PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package").build()?;
        let out_file = common::cargo_out_dir().join("empty_rpm_nosig.rpm");
        pkg.write_file(&out_file)?;

        try_installation_and_verify_signatures("/out/empty_rpm_nosig.rpm")?;

        Ok(())
    }

    /// Build and sign an empty RPM using rpm-rs,install it, test verifying the signatures, etc
    #[test]
    #[serial_test::serial]
    fn test_install_empty_rpm_with_signature() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let signing_key = common::rsa_private_key();

        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())
            .expect("Must load signer from signing key");

        let pkg = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
            .build_and_sign(&signer)?;
        let out_file = common::cargo_out_dir().join("empty_rpm_nosig.rpm");
        pkg.write_file(&out_file)?;

        try_installation_and_verify_signatures("/out/empty_rpm_nosig.rpm")?;

        Ok(())
    }

    /// Build an RPM using rpm-rs, and install it
    #[test]
    #[serial_test::serial]
    fn test_install_full_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let pkg = build_full_rpm()?.build()?;
        let out_file = common::cargo_out_dir().join("full_rpm_nosig.rpm");
        pkg.write_file(&out_file)?;
        assert_eq!(1, pkg.metadata.get_epoch()?);

        try_installation_and_verify_signatures("/out/full_rpm_nosig.rpm")?;

        Ok(())
    }

    /// Build and sign an RPM using rpm-rs,install it, test verifying the signatures, etc
    #[test]
    #[serial_test::serial]
    fn test_install_full_rpm_with_signature() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let signing_key = common::rsa_private_key();
        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())
            .expect("Must load signer from signing key");

        let pkg = build_full_rpm()?.build_and_sign(signer)?;
        let out_file = common::cargo_out_dir().join("full_rpm_sig.rpm");
        pkg.write_file(&out_file)?;
        assert_eq!(1, pkg.metadata.get_epoch()?);

        try_installation_and_verify_signatures("/out/full_rpm_sig.rpm")?;

        Ok(())
    }

    /// Build and sign an RPM using rpm-rs and a passphrase-required key,install it, test verifying the signatures, etc
    #[test]
    #[serial_test::serial]
    fn test_install_full_rpm_with_sig_key_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let signing_key = common::rsa_private_key();

        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())
            .expect("Must load signer from signing key")
            .with_key_passphrase(common::test_protected_private_key_passphrase());

        let pkg = build_full_rpm()?.build_and_sign(signer)?;
        let out_file = common::cargo_out_dir().join("full_rpm_sig_protected.rpm");
        pkg.write_file(&out_file)?;
        assert_eq!(1, pkg.metadata.get_epoch()?);

        try_installation_and_verify_signatures("/out/full_rpm_sig_protected.rpm")?;

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
    let var_cache = common::cargo_manifest_dir().join("dnf-cache");
    let _ = std::fs::create_dir(var_cache.as_path());
    let var_cache = format!("{}:/var/cache/dnf:z", var_cache.display());
    let out = format!("{}:/out:z", common::cargo_out_dir().display());
    let assets = format!(
        "{}/test_assets:/assets:z",
        common::cargo_manifest_dir().display()
    );
    let new_assets = format!(
        "{}/tests/assets:/new_assets:z",
        common::cargo_manifest_dir().display(),
    );
    mappings.extend(vec![out, assets, new_assets, var_cache]);
    let mut args = mappings
        .iter()
        .fold(vec!["run", "-i", "--rm"], |mut acc, mapping| {
            acc.extend(vec!["-v", mapping]);
            acc
        });
    args.extend(vec![image, "sh"]);

    let mut podman_cmd = std::process::Command::new("podman");

    podman_cmd.args(dbg!(args));
    podman_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    podman_cmd.stdin(Stdio::piped());

    podman_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    podman_cmd.stdin(Stdio::piped());

    // partially following:
    //
    //  https://access.redhat.com/articles/3359321
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

pushd new_assets/
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
