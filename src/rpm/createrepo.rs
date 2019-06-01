struct RepoMD {
    revision: u64,
    data: Vec<RepoMDData>,
}

impl RepoMD {}

struct RepoMDData {
    data_type: String,
    checksum: Checksum,
    location: String,
    timestamp: u64,
    size: u64,
    open_size: u64,
}

struct Checksum {
    checksum_type: ChecksumType,
    value: String,
    pkgid: Option<bool>,
}

enum ChecksumType {
    SHA256,
    SHA1,
    MD5,
}

enum DataType {
    Group,
    GroupGZ,
    FileLists,
    FileListsDB,
    Primary,
    PrimaryDB,
    OtherDB,
    Other,
}

struct OtherData {
    num_packages: u64,
}

struct OtherDataPackage {
    pkgid: String,
    name: String,
    arch: String,
    version: Version,
    changelog: Vec<ChangelogEntry>,
}

struct Version {
    epoch: String,
    ver: String,
    rel: String,
}

struct ChangelogEntry {
    author: String,
    date: u64,
    description: String,
}

struct Metadata {
    packages: u64,
}

struct PrimaryPackage {
    package_type: PackageType,
    name: String,
    arch: Arch,
    checksum: Checksum,
    summary: String,
    description: String,
    packager: String,
    url: String,
    file_time: u64,
    build_time: u64,
    package_size: u64,
    installed_size: u64,
    archived_size: u64,
    location: String,
    format: RpmFormat,
}

enum PackageType {
    RPM,
}
enum Arch {
    X86_64,
}

struct RpmFormat {
    license: String,
    vendor: String,
    group: String,
    buildhost: String,
    sourcerpm: String,
    header_range: HeaderRange,
    provides: Vec<RpmEntry>,
    requires: Vec<RpmEntry>,
    conflicts: Vec<RpmEntry>,
    obsoletes: Vec<RpmEntry>,
    files: Vec<String>,
    dirs: Vec<String>,
}

struct RpmEntry {
    name: String,
    flags: Option<EntryFlag>,
    epoch: Option<String>,
    ver: Option<String>,
    rel: Option<String>,
}

enum EntryFlag {
    EQ,
    GE,
}

struct HeaderRange {
    start: u64,
    end: u64,
}
