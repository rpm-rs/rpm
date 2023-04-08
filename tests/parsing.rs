use rpm::*;

mod common;

// @todo: replace with a new fixture that serves more than one purpose
#[test]
fn test_rpm_file_signatures() -> Result<(), Box<dyn std::error::Error>> {
    let rpm_file_path = common::rpm_ima_signed_file_path();
    let package = RPMPackage::open(rpm_file_path)?;
    let metadata = &package.metadata;

    let signatures = metadata.get_file_ima_signatures()?;

    assert_eq!(
        signatures,
        [
            "0302041adfaa0e004630440220162785458f5d81d1393cc72afc642c86167c15891ea39213e28907b1c4e8dc6c02202fa86ad2f5e474d36c59300f736f52cb5ed24abb55759a71ec224184a7035a78",
            "0302041adfaa0e00483046022100bd940093777b75650980afb656507f2729a05c9b1bc9986993106de9f301a172022100b3384f6ba200a5a80647a0f0727c5b8f3ab01f74996a1550db605b44af3d10bf",
            "0302041adfaa0e00473045022068953626d7a5b65aa4b1f1e79a2223f2d3500ddcb3d75a7050477db0480a13e10221008637cefe8c570044e11ff95fa933c1454fd6aa8793bbf3e87edab2a2624df460",
        ],
    );

    Ok(())
}

#[test]
fn test_empty_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = RPMPackage::open(common::rpm_empty_path())?;
    let metadata = &package.metadata;

    assert_eq!(metadata.get_name().unwrap(), "rpm-empty");
    assert!(metadata.get_epoch().is_err());
    assert_eq!(metadata.get_version().unwrap(), "0");
    assert_eq!(metadata.get_release().unwrap(), "0");
    assert_eq!(metadata.get_arch().unwrap(), "x86_64");
    assert_eq!(metadata.get_description().unwrap(), "");
    assert_eq!(metadata.get_summary().unwrap(), "\"\"");

    assert!(matches!(metadata.get_url(), Err(RPMError::TagNotFound(_))));

    // assert_eq!(metadata.get_file_paths().unwrap(), vec![]);
    assert_eq!(metadata.get_file_entries().unwrap(), vec![]);

    assert_eq!(metadata.get_changelog_entries().unwrap(), vec![]);

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![
            Dependency::eq("rpm-empty".to_owned(), "0-0".to_owned()),
            Dependency::eq("rpm-empty(x86-64)".to_owned(), "0-0".to_owned()),
        ]
    );
    // // @todo: need some way to express generalized flags outside of the crate
    // assert_eq!(
    //     metadata.get_requires().unwrap(),
    //     vec![
    //         Dependency::greater_eq(
    //             "rpmlib(CompressedFileNames)".to_owned(),
    //             "3.0.4-1".to_owned()
    //         ),
    //         Dependency::greater_eq("rpmlib(FileDigests)".to_owned(), "4.6.0-1".to_owned()),
    //         Dependency::greater_eq(
    //             "rpmlib(PayloadFilesHavePrefix)".to_owned(),
    //             "4.0-1".to_owned()
    //         ),
    //     ]
    // );
    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    Ok(())
}

// #[test]
// fn test_rpm_header_fixture() -> Result<(), Box<dyn std::error::Error>> {
//     let package = RPMPackage::open(common::rpm_389_ds_file_path())?;

//     let metadata = &package.metadata;

//     assert_eq!(package.metadata.get_name().unwrap(), "389-ds-base-devel");
//     assert!(package.metadata.get_epoch().is_err());
//     assert_eq!(package.metadata.get_version().unwrap(), "1.3.8.4");
//     assert_eq!(package.metadata.get_release().unwrap(), "15.el7");
//     assert_eq!(package.metadata.get_arch().unwrap(), "x86_64");

//     assert_eq!(
//         package.metadata.get_url().unwrap(),
//         "https://www.port389.org/"
//     );

//     // TODO: vcs
//     // assert_eq!(
//     //     package.metadata.get_vcs().unwrap(),
//     //     "git://pkgs.fedoraproject.org/389-ds-base.git"
//     // );

//     assert_eq!(
//         package.metadata.get_packager().unwrap(),
//         "CentOS BuildSystem <http://bugs.centos.org>"
//     );
//     assert_eq!(package.metadata.get_license().unwrap(), "GPLv3+");
//     assert_eq!(package.metadata.get_vendor().unwrap(), "CentOS");

//     assert_eq!(
//         package.metadata.get_summary().unwrap(),
//         "Development libraries for 389 Directory Server"
//     );
//     assert_eq!(
//         package.metadata.get_description().unwrap(),
//         "Development Libraries and headers for the 389 Directory Server base package."
//     );
//     assert_eq!(
//         package.metadata.get_group().unwrap(),
//         "Development/Libraries"
//     );
//     assert_eq!(
//         package.metadata.get_source_rpm().unwrap(),
//         "389-ds-base-1.3.8.4-15.el7.src.rpm"
//     );
//     assert_eq!(
//         package.metadata.get_build_host().unwrap(),
//         "x86-01.bsys.centos.org"
//     );
//     assert_eq!(package.metadata.get_build_time().unwrap(), 1540945151);

//     assert_eq!(package.metadata.get_payload_compressor().unwrap(), "xz");
//     // @todo: too many to test for, need a new fixture RPM. it works though.
//     assert!(!package.metadata.get_changelog_entries().unwrap().is_empty());

//     assert_eq!(
//         package.metadata.get_provides().unwrap(),
//         vec![
//             Dependency {
//                 dep_name: "389-ds-base-devel".to_string(),
//                 sense: 8,
//                 version: "1.3.8.4-15.el7".to_string()
//             },
//             Dependency {
//                 dep_name: "389-ds-base-devel(x86-64)".to_string(),
//                 sense: 8,
//                 version: "1.3.8.4-15.el7".to_string()
//             },
//             Dependency {
//                 dep_name: "pkgconfig(dirsrv)".to_string(),
//                 sense: 32776,
//                 version: "1.3.8.4".to_string()
//             },
//             Dependency {
//                 dep_name: "pkgconfig(libsds)".to_string(),
//                 sense: 32776,
//                 version: "1.3.8.4".to_string()
//             },
//             Dependency {
//                 dep_name: "pkgconfig(nunc-stans)".to_string(),
//                 sense: 32776,
//                 version: "1.3.8.4".to_string()
//             }
//         ]
//     );
//     assert_eq!(
//         package.metadata.get_requires().unwrap(),
//         vec![
//             Dependency {
//                 dep_name: "/usr/bin/pkg-config".to_string(),
//                 sense: 16384,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "389-ds-base-libs".to_string(),
//                 sense: 8,
//                 version: "1.3.8.4-15.el7".to_string()
//             },
//             Dependency {
//                 dep_name: "libevent".to_string(),
//                 sense: 0,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "libldaputil.so.0()(64bit)".to_string(),
//                 sense: 16384,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "libnunc-stans.so.0()(64bit)".to_string(),
//                 sense: 16384,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "libsds.so.0()(64bit)".to_string(),
//                 sense: 16384,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "libslapd.so.0()(64bit)".to_string(),
//                 sense: 16384,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "libtalloc".to_string(),
//                 sense: 0,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "libtevent".to_string(),
//                 sense: 0,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "nspr-devel".to_string(),
//                 sense: 0,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "nss-devel".to_string(),
//                 sense: 12,
//                 version: "3.34".to_string()
//             },
//             Dependency {
//                 dep_name: "openldap-devel".to_string(),
//                 sense: 0,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "pkgconfig".to_string(),
//                 sense: 0,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "pkgconfig(nspr)".to_string(),
//                 sense: 16384,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "rpmlib(CompressedFileNames)".to_string(),
//                 sense: 16777226,
//                 version: "3.0.4-1".to_string()
//             },
//             Dependency {
//                 dep_name: "rpmlib(FileDigests)".to_string(),
//                 sense: 16777226,
//                 version: "4.6.0-1".to_string()
//             },
//             Dependency {
//                 dep_name: "rpmlib(PayloadFilesHavePrefix)".to_string(),
//                 sense: 16777226,
//                 version: "4.0-1".to_string()
//             },
//             Dependency {
//                 dep_name: "svrcore-devel".to_string(),
//                 sense: 12,
//                 version: "4.1.3".to_string()
//             },
//             Dependency {
//                 dep_name: "systemd-libs".to_string(),
//                 sense: 0,
//                 version: "".to_string()
//             },
//             Dependency {
//                 dep_name: "rpmlib(PayloadIsXz)".to_string(),
//                 sense: 16777226,
//                 version: "5.2-1".to_string()
//             }
//         ]
//     );
//     assert_eq!(package.metadata.get_conflicts().unwrap(), vec![]);
//     assert_eq!(package.metadata.get_obsoletes().unwrap(), vec![]);
//     assert_eq!(package.metadata.get_supplements().unwrap(), vec![]);
//     assert_eq!(package.metadata.get_suggests().unwrap(), vec![]);
//     assert_eq!(package.metadata.get_enhances().unwrap(), vec![]);
//     assert_eq!(package.metadata.get_recommends().unwrap(), vec![]);

//     assert_eq!(package.metadata.is_source_package(), false);
//     // @todo: add a test where this is true
//     // also https://github.com/rpm-rs/rpm/issues/66
//     assert_eq!("xz", metadata.get_payload_compressor()?);

//     let expected_file_checksums = vec![
//         "",
//         "3e4e2501e2a70343a661b0b85b82e27b2090a7e595dc3b5c91e732244ffc3272",
//         "d36ab638ed0635afcb1582387d676b2e461c5a88ac05a6e2aada8b40b4175bc1",
//         "9667aa81021c9f4d48690ef6fbb3e7d623bdae94e2da414abd044dc38e52f037",
//         "1e8235e08aac746155c209c1e641e73bf7a4c34d9971aaa9f864226bd5de9d99",
//         "53a1e216749208c0bdfc9e8ec70f4bb9459ad1ff224571a7a432e472d2202986",
//         "2807bb4e77579c81dc7e283d60612a6ecc3ce56000691cac744a4bca73cea241",
//         "",
//         "",
//         "",
//         "",
//         "",
//         "a839e2870b7a212ca9dc6f92007907bc42de1984eac6c278a519d4115071f322",
//         "3ca364e71a110cd0f2317fbaf99bc8552b8374dbeaf0a989695990f940d88bea",
//         "eead9f55f0774559d37b20fbc5448f978e1a80d27f488768cbbb278a932e7e9f",
//         "",
//         "495b7c1e22dcc0f37d78076a1fcad786b69ac78f1e806466d798fd8fc4a5d10d",
//         "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
//         "a73b7d3598e98f46aeb0559e641d3e6ac83c0fc34e1e5fa98cb9d4a6050bacd9",
//         "97a6a0413ce3664e192dff12a29bc3f690c24e8a0d48d986478c56cdfe370c3b",
//         "d110052464fd35c5dc227b3f071606ec40c12ba773fec9ec88ad01430bd4a27b",
//         "5c3adbdea58a8bb7663c65216dda7d1f38a17b067f718df46ece04ecb503f689",
//         "005dc9d5aa85b10c3200535af8b0ed2123770e3a79d48be5067e81cc553d55bd",
//         "aa7ea2def38dfc965b27ae20467006aca779e02ad366d50824c4615a7d43af27",
//         "5ee25b47a83b1431f6ecb1d0a292a8e9a2917c1de9e87129c86cdda743be3f55",
//         "413aae4fb264aad9d35db94eb28b5f70a7183101692943e81bc90d6718418d8e",
//         "66004b2e338ce29e59d6a26467e251f092ae0a0f33b67dbba67d2ea9f3ec89f6",
//         "3db4ad3317bff658a04a1bdbc01fab83cd348f76a1d44585b892fdb0223f2b77",
//         "ccac76a229e6739ab318d9ede59f6b980d3200fc50669409d3b1e8a0ff1fa029",
//         "5a3378c84c68e2a407add0f850c64d701af2aedcca67dd2489e86cb1e08dbb6b",
//         "da188ece6801b97c98031b854d4000e348e969edea239cb1bcbfae7a194e3520",
//         "28a93db2fe665e8b08494fe5adf3d8dc00c2f96a4994a09eb70cf982d912fa09",
//         "ba92ea5c90389b38a3c003a5e4a7b09e57473cbd2fb3645c2c0012808023fd0b",
//         "502dd15afe5609a113108cad047a810b7a97cc8819e830f1d5b00cb5bf65a295",
//         "4445b3e6550a3d7da96a246e6138d3f349160420085ce14222d3f686eb29915c",
//         "649f748bffe197539db9237d56da8a3e408731488550617596359cd32731ec06",
//         "4bd801d053bf456c3dd2c94f9721d1bb0c44d2c119e233b8ad4c5189bd39b256",
//         "d444bb47f4a83ebd0e6b669f73bb2d6d3dde804b70a0bbd2be66693d88ce8e16",
//         "087be3693057db21a0b1d38844bb5efa8112f67f3572063546215f25f9fe8d9e",
//         "2c639c8768e323f2ad4ea96f1667989cb97d49947e9bcebcd449163d9c9bb85c",
//     ];

//     let checksums = metadata.get_file_checksums()?;

//     assert_eq!(expected_file_checksums, checksums);

//     Ok(())
// }
