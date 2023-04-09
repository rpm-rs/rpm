use rpm::*;
use std::path::PathBuf;

mod common;

#[test]
fn test_feature_coverage_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = RPMPackage::open(common::rpm_feature_coverage_pkg_path())?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-feature-coverage");
    assert_eq!(metadata.get_epoch().unwrap(), 1);
    assert_eq!(metadata.get_version().unwrap(), "2.3.4");
    assert_eq!(metadata.get_release().unwrap(), "5.el8");
    assert_eq!(metadata.get_arch().unwrap(), "x86_64");
    assert_eq!(
        metadata.get_description().unwrap(),
        "This package attempts to exercise many different features of RPM packages."
    );
    assert_eq!(
        metadata.get_summary().unwrap(),
        "A package for exercising many different features of RPM"
    );
    assert_eq!(metadata.get_license().unwrap(), "MPLv2");
    assert_eq!(metadata.get_url().unwrap(), "http://bobloblaw.com");
    assert_eq!(metadata.get_packager().unwrap(), "Michael Bluth");
    assert_eq!(metadata.get_vendor().unwrap(), "Bluth Company");
    assert_eq!(metadata.get_group().unwrap(), "Development/Tools");
    assert_eq!(metadata.get_vcs().unwrap(), "https://github.com/rpm-rs/rpm");
    assert_eq!(metadata.get_cookie().unwrap(), "localhost 1681068559");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert_eq!(
        metadata.get_file_paths().unwrap(),
        vec![
            PathBuf::from("/etc/complex/pkg.cfg"),
            PathBuf::from("/usr/bin/complex_a"),
            PathBuf::from("/usr/share/doc/rpm-feature-coverage"),
            PathBuf::from("/usr/share/doc/rpm-feature-coverage/README"),
            PathBuf::from("/var/lib/complex"),
            PathBuf::from("/var/log/complex.log"),
        ]
    );
    assert_eq!(
        metadata.get_file_checksums().unwrap(),
        vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "",
            "bc1c6832a5a5f002a2fd7435b58ce6852408b7750f9c1c4a69098972f44dd1b7",
            "",
            "",
        ]
    );

    assert_eq!(
        metadata.get_changelog_entries().unwrap(),
        vec![
            ChangelogEntry {
                author: "George Bluth <george@federalprison.gov> - 3.3.3-3".to_owned(),
                timestamp: 1623672000,
                description: "- There’s always money in the banana stand".to_owned()
            },
            ChangelogEntry {
                author: "Job Bluth <job@alliance-of-magicians.com> - 2.2.2-2".to_owned(),
                timestamp: 1619352000,
                description: "- I've made a huge mistake".to_owned()
            },
            ChangelogEntry {
                author: "Lucille Bluth <lucille@bluthcompany.com> - 1.1.1-1".to_owned(),
                timestamp: 1617192000,
                description: "- It's a banana, Michael. How much could it cost, $10?".to_owned()
            },
        ]
    );

    // assert_eq!(
    //     metadata.get_provides().unwrap(),
    //     vec![
    //         Dependency::eq("rpm-empty".to_owned(), "0-0".to_owned()),
    //         Dependency::eq("rpm-empty(x86-64)".to_owned(), "0-0".to_owned()),
    //     ]
    // );
    // // // @todo: need some way to express generalized flags outside of the crate
    // // assert_eq!(
    // //     metadata.get_requires().unwrap(),
    // //     vec![
    // //         Dependency::greater_eq(
    // //             "rpmlib(CompressedFileNames)".to_owned(),
    // //             "3.0.4-1".to_owned()
    // //         ),
    // //         Dependency::greater_eq("rpmlib(FileDigests)".to_owned(), "4.6.0-1".to_owned()),
    // //         Dependency::greater_eq(
    // //             "rpmlib(PayloadFilesHavePrefix)".to_owned(),
    // //             "4.0-1".to_owned()
    // //         ),
    // //     ]
    // // );
    // assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    // assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    // assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    // assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    // assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    // assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    Ok(())
}

#[test]
fn test_empty_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = RPMPackage::open(common::rpm_empty_path())?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-empty");
    assert!(metadata.get_epoch().is_err());
    assert_eq!(metadata.get_version().unwrap(), "0");
    assert_eq!(metadata.get_release().unwrap(), "0");
    assert_eq!(metadata.get_arch().unwrap(), "x86_64");
    assert_eq!(metadata.get_description().unwrap(), "");
    assert_eq!(metadata.get_summary().unwrap(), "\"\"");
    assert_eq!(metadata.get_license().unwrap(), "LGPL");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert!(matches!(
        metadata.get_vendor(),
        Err(RPMError::TagNotFound(_))
    ));
    assert!(matches!(
        metadata.get_payload_compressor(),
        Err(RPMError::TagNotFound(_))
    ));
    assert!(matches!(metadata.get_url(), Err(RPMError::TagNotFound(_))));

    // assert_eq!(metadata.get_file_paths().unwrap(), vec![]);
    assert_eq!(metadata.get_file_entries().unwrap(), vec![]);
    // assert_eq!(metadata.get_file_checksums().unwrap(), vec![]);

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

#[test]
fn test_empty_source_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = RPMPackage::open(common::rpm_empty_source_path())?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), true);
    assert_eq!(metadata.get_name().unwrap(), "rpm-empty");
    assert!(metadata.get_epoch().is_err());
    assert_eq!(metadata.get_version().unwrap(), "0");
    assert_eq!(metadata.get_release().unwrap(), "0");
    assert_eq!(metadata.get_arch().unwrap(), "x86_64");
    assert_eq!(metadata.get_description().unwrap(), "");
    assert_eq!(metadata.get_summary().unwrap(), "\"\"");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");
    assert_eq!(metadata.get_license().unwrap(), "LGPL");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert!(matches!(
        metadata.get_vendor(),
        Err(RPMError::TagNotFound(_))
    ));
    assert!(matches!(
        metadata.get_payload_compressor(),
        Err(RPMError::TagNotFound(_))
    ));
    assert!(matches!(metadata.get_url(), Err(RPMError::TagNotFound(_))));

    // assert_eq!(metadata.get_file_paths().unwrap(), vec![]);
    // assert_eq!(metadata.get_file_entries().unwrap(), vec![]);
    // assert_eq!(metadata.get_file_checksums().unwrap(), vec![]);

    // assert_eq!(metadata.get_changelog_entries().unwrap(), vec![]);

    // assert_eq!(
    //     metadata.get_provides().unwrap(),
    //     vec![
    //         Dependency::eq("rpm-empty".to_owned(), "0-0".to_owned()),
    //         Dependency::eq("rpm-empty(x86-64)".to_owned(), "0-0".to_owned()),
    //     ]
    // );
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

// @todo: get rid of this as soon as we can do ima-signing for our pre-built fixture packages
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
