use rpm::*;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::process::Stdio;

mod common;

use signature::{self, Verifying};

mod pgp {
    use super::*;
    use signature::pgp::{Signer, Verifier};

    /// Verify that the RPM is installable with valid signatures on the various supported distros
    #[track_caller]
    fn try_installation_and_verify_signatures(
        path: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dnf_cmd = format!("dnf --disablerepo=updates,updates-testing,updates-modular,fedora-modular install -y {};", path.as_ref().display());
        let rpm_sig_check = format!("rpm -vv --checksig {} 2>&1;", path.as_ref().display());
        // TODO: check signatures on all distros?
        [
            ("fedora:38", &rpm_sig_check),
            ("fedora:38", &dnf_cmd),
            ("centos:stream9", &dnf_cmd),
            ("centos:stream8", &dnf_cmd),
        ]
        .iter()
        .try_for_each(|(image, cmd)| {
            podman_container_launcher(cmd, image, vec![])?;
            Ok(())
        })
    }

    fn build_full_rpm() -> Result<PackageBuilder, Box<dyn std::error::Error>> {
        let cargo_file = common::cargo_manifest_dir().join("Cargo.toml");

        let bldr = PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some package")
            .compression(CompressionType::Gzip)
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
                    .is_config(),
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

    #[test]
    #[serial_test::serial]
    fn test_install_full_rpm_with_signature() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let (signing_key, _) = common::load_asc_keys();

        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())
            .expect("Must load signer from signing key");

        let pkg = build_full_rpm()?.build_and_sign(signer)?;
        let out_file = common::cargo_out_dir().join("full_rpm_sig.rpm");
        pkg.write_file(&out_file)?;
        assert_eq!(1, pkg.metadata.get_epoch()?);

        try_installation_and_verify_signatures("/out/full_rpm_sig.rpm")?;

        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn test_install_empty_rpm_with_signature() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let (signing_key, _) = common::load_asc_keys();

        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())
            .expect("Must load signer from signing key");

        let pkg = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
            .build_and_sign(&signer)?;
        let out_file = common::cargo_out_dir().join("empty_rpm_nosig.rpm");
        pkg.write_file(&out_file)?;

        try_installation_and_verify_signatures("/out/empty_rpm_nosig.rpm")?;

        Ok(())
    }

    // @todo: we don't really need to sign the RPMs as part of the test. Can use fixture.
    #[test]
    #[serial_test::serial]
    fn test_verify_externally_signed_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let (_, verification_key) = common::load_asc_keys();

        let verifier = Verifier::load_from_asc_bytes(verification_key.as_ref())?;

        let rpm_file_path = common::rpm_389_ds_file_path();
        let out_file =
            common::cargo_out_dir().join(rpm_file_path.file_name().unwrap().to_str().unwrap());

        println!("cpy {} -> {}", rpm_file_path.display(), out_file.display());
        std::fs::copy(rpm_file_path.as_path(), out_file.as_path()).expect("Must be able to copy");

        // avoid any further usage
        drop(rpm_file_path);

        let cmd = format!(
            r#"
echo ">>> sign"
rpm -vv --addsign /out/{rpm_file} 2>&1

echo ">>> verify signature with rpm"
rpm -vv --checksig /out/{rpm_file} 2>&1
"#,
            rpm_file = out_file.file_name().unwrap().to_str().unwrap()
        );

        podman_container_launcher(cmd.as_str(), "fedora:38", vec![])?;

        let out_file = std::fs::File::open(&out_file).expect("should be able to open rpm file");
        let mut buf_reader = std::io::BufReader::new(out_file);
        let package = rpm::Package::parse(&mut buf_reader)?;

        package.verify_signature(verifier)?;

        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn test_verify_raw_gpg_signature() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let (_signing_key, verification_key) = common::load_asc_keys();

        let test_file = common::cargo_out_dir().join("test.file");
        let test_file_sig = common::cargo_out_dir().join("test.file.sig");

        std::fs::write(&test_file, "test").expect("Must be able to write");
        let _ = std::fs::remove_file(&test_file_sig);

        let cmd= r#"
echo "test" > /out/test.file

echo ">>> sign like rpm"
cmd="$(rpm -vv --define "__signature_filename /out/test.file.sig" \
        --define "__plaintext_filename /out/test.file" \
        --define "_gpg_name Package Manager" \
        --eval "%{__gpg_sign_cmd}" | sd '\n' ' ')"

echo "cmd: ${cmd}"
eval ${cmd}

alias gpg='gpg --batch --verbose --keyid-format long --no-armor --pinentry-mode error --no-secmem-warning --local-user "Package Manager"'
#gpg \
#    --sign \
#    --detach-sign \
#    --output /out/test.file.sig \
#    /out/test.file 2>&1

echo ">>> inspect signature"
gpg -d /out/test.file.sig 2>&1

echo ">>> verify external gpg signature"
gpg --verify /out/test.file.sig /out/test.file 2>&1

"#.to_owned();

        podman_container_launcher(cmd.as_str(), "fedora:38", vec![])
            .expect("Container execution must be flawless");

        let verifier =
            Verifier::load_from_asc_bytes(verification_key.as_slice()).expect("Must load");

        let raw_sig = std::fs::read(&test_file_sig).expect("must load signature");
        let data = std::fs::read(&test_file).expect("must load file");
        verifier.verify(data.as_slice(), raw_sig.as_slice())?;

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
    mappings.extend(vec![out, assets, var_cache]);
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
    let cmd = vec![
        r#"
set -e

# prepare rpm macros

cat > ~/.rpmmacros << EOF_RPMMACROS
%_signature gpg
%_gpg_path /root/.gnupg
%_gpg_name Package Manager
%_gpgbin /usr/bin/gpg2
%__gpg_sign_cmd %{__gpg} \
    --batch \
    --verbose \
    --no-armor \
    --keyid-format long \
    --pinentry-mode error \
    --no-secmem-warning \
    %{?_gpg_digest_algo:--digest-algo %{_gpg_digest_algo}} \
    --local-user "%{_gpg_name}" \
    --sign \
    --detach-sign \
    --output %{__signature_filename} \
    %{__plaintext_filename}
EOF_RPMMACROS

cat ~/.rpmmacros

### either

#cat > gpgkeyspec <<EOF
#     %echo Generating a basic OpenPGP key
#     Key-Type: RSA
#     Key-Length: 2048
#     Subkey-Type: RSA
#     Subkey-Length: 2048
#     Name-Real: Package Manager
#     Name-Comment: unprotected
#     Name-Email: pmanager@example.com
#     Expire-Date: 0
#     %no-ask-passphrase
#     %no-protection
#     %commit
#     %echo done
#EOF
#gpg --batch --generate-key gpgkeyspec  2>&1

### or (which has a couple of advantages regarding reproducibility)

export PK=/assets/public_key.asc
export SK=/assets/secret_key.asc

gpg --allow-secret-key-import --import "${SK}" 2>&1
gpg --import "${PK}" 2>&1

gpg --keyid-format long --list-secret-keys
gpg --keyid-format long --list-public-keys

echo -e "5\ny\n" | gpg --no-tty --command-fd 0 --expert --edit-key 2E5A802A67EA36B83018F654CFD331925AB27F39 trust;



echo "\### create a test signature with this particular key id"

echo "test" | gpg -s --local-user "77500CC056DB3521" > /tmp/test.signature 2>&1
gpg -d < /tmp/test.signature 2>&1

echo "\### export PK"

gpg --export -a "Package Manager" > /assets/RPM-GPG-KEY-pmanager

dig1=$(gpg "/assets/RPM-GPG-KEY-pmanager" | sha256sum)
dig2=$(gpg "${PK}" | sha256sum)

if [ "$dig1" != "$dig2" ]; then
echo "\### expected pub key and exported pubkey differ"
    echo "EEE /assets/RPM-GPG-KEY-pmanager"
    gpg /assets/RPM-GPG-KEY-pmanager
    echo "EEE ${PK}"
    gpg "${PK}"
    exit 77
fi

echo "\### install tooling for signing"

dnf install --disablerepo=updates,updates-testing,updates-modular -y rpm-sign sd || \
yum install --disablerepo=updates,updates-testing,updates-modular -y rpm-sign

echo "\### import pub key"

rpm -vv --import "${PK}" 2>&1

set -x

"#,
cmd,
r#"

echo "\### Container should exit any second now"
exit 0
"#].join("\n");

    println!("Container execution starting...");

    // this is far from perfect, but at least pumps
    // stdio and stderr out
    wait_and_print_helper(podman_cmd.spawn()?, cmd.as_str())?;
    println!("Container execution ended.");
    Ok(())
}
