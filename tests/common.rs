#![allow(dead_code)]

pub const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
pub const CARGO_OUT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target");

pub mod pkgs {
    pub const RPM_EMPTY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/x86_64/rpm-empty-0-0.x86_64.rpm");

    pub const RPM_EMPTY_SRC: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/SRPMS/rpm-empty-0-0.src.rpm");

    pub const RPM_BASIC: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/noarch/rpm-basic-2.3.4-5.el9.noarch.rpm");

    pub const RPM_BASIC_SRC: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/SRPMS/rpm-basic-2.3.4-5.el9.src.rpm");

    pub const RPM_BASIC_IMA_SIGNED: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/signed/rpm-basic-with-ima-2.3.4-5.el9.noarch.rpm");

    pub const RPM_BASIC_RSA_SIGNED: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm");

    pub const RPM_BASIC_ECDSA_SIGNED: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/signed/rpm-basic-with-ecdsa-2.3.4-5.el9.noarch.rpm");

    pub const RPM_BASIC_EDDSA_SIGNED: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/signed/rpm-basic-with-ed25519-2.3.4-5.el9.noarch.rpm");

    pub const RPM_BASIC_SOURCE: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/SRPMS/rpm-basic-2.3.4-5.el9.src.rpm");

    pub const RPM_BASIC_SOURCE_EDDSA_SIGNED: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/SRPMS/signed/rpm-basic-with-ed25517-2.3.4-5.el9.src.rpm");

    pub const RPM_BASIC_SOURCE_RSA_SIGNED: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/SRPMS/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.src.rpm");

    pub const RPM_WITH_PATCH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/noarch/rpm-with-patch-1.0-0.noarch.rpm");

    pub const RPM_FILE_ATTRS: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/RPMS/noarch/rpm-file-attrs-1.0-1.noarch.rpm");
}

pub mod keys {
    pub mod v4 {
        pub const RSA4096_PUBLIC: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa4096.asc");
        pub const RSA4096_PRIVATE: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa4096.secret");

        pub const RSA3072_PROTECTED_PUBLIC: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa3072-protected.asc");
        pub const RSA3072_PROTECTED_PRIVATE: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-rsa3072-protected.secret");
        pub const RSA3072_PROTECTED_PASSPHRASE: &str = "thisisN0Tasecuredpassphrase";

        pub const ED25519_PUBLIC: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-ed25519.asc");
        pub const ED25519_PRIVATE: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-ed25519.secret");

        pub const ECDSA_NISTP256_PUBLIC: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.asc");
        pub const ECDSA_NISTP256_PRIVATE: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v4/rpm-testkey-v4-ecdsa-nistp256.secret");

        pub fn load_rsa() -> (Vec<u8>, Vec<u8>) {
            (rsa_private(), rsa_public())
        }

        pub fn rsa_private() -> Vec<u8> {
            std::fs::read(RSA4096_PRIVATE).unwrap()
        }

        pub fn rsa_public() -> Vec<u8> {
            std::fs::read(RSA4096_PUBLIC).unwrap()
        }

        pub fn load_protected_rsa() -> (Vec<u8>, Vec<u8>) {
            let signing_key = include_bytes!("assets/signing_keys/v4/rpm-testkey-v4-rsa3072-protected.secret");
            let verification_key = include_bytes!("assets/signing_keys/v4/rpm-testkey-v4-rsa3072-protected.asc");
            (signing_key.to_vec(), verification_key.to_vec())
        }

        pub fn eddsa_private() -> Vec<u8> {
            std::fs::read(ED25519_PRIVATE).unwrap()
        }

        pub fn eddsa_public() -> Vec<u8> {
            std::fs::read(ED25519_PUBLIC).unwrap()
        }

        pub fn load_eddsa() -> (Vec<u8>, Vec<u8>) {
            (eddsa_private(), eddsa_public())
        }

        pub fn ecdsa_private() -> Vec<u8> {
            std::fs::read(ECDSA_NISTP256_PRIVATE).unwrap()
        }

        pub fn ecdsa_public() -> Vec<u8> {
            std::fs::read(ECDSA_NISTP256_PUBLIC).unwrap()
        }

        pub fn load_ecdsa() -> (Vec<u8>, Vec<u8>) {
            (ecdsa_private(), ecdsa_public())
        }
    }

    pub mod v6 {
        pub const RSA4K_PUBLIC: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc");
        pub const RSA4K_PRIVATE: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.secret");

        pub const ED25519_PUBLIC: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.asc");
        pub const ED25519_PRIVATE: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret");

        pub const MLDSA65_ED25519_PUBLIC: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.asc");
        pub const MLDSA65_ED25519_PRIVATE: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/signing_keys/v6/rpm-testkey-v6-mldsa65-ed25519.secret");
    }
}
