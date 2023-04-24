use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

/// A full RPM "version" specifier has 3 different components - Epoch, Version, and Release.
///
/// You are not expected to create these manually, but rather from existing RPMs.
///
/// Epoch overrides all other fields and is generally only used as a last resort - in cases where
/// a change to the versioning scheme or packaging error creates a situation where newer packages
/// might otherwise sort as being older.
///
/// Version is the normal version string used by the upstream project. This shouldn't be tweaked
/// by the packager.
///
/// Release indicates firstly the number of times this package has been released - for instance,
/// with custom patches and backports not present in the upstream, but may also indicate other
/// details such as the OS it was built for (fc38, el9) or portions of a git commit hash.
///
/// Tilde (~) and caret (^) are special values used in particular situations. Including ~ in
/// a version is used for denoting pre-releases and will force it to sort as less than a version
/// without a caret, e.g. 0.5.0 vs 0.5.0~rc1. Including ^ in a version is used for denoting snapshots
/// not directly associated with an upstream release and will force it to sort higher, e.g.
/// 0.5.0 vs 0.5.0^deadbeef
#[derive(Debug, Eq, Default, Clone)]
pub struct EVR<'a> {
    epoch: Cow<'a, str>,
    version: Cow<'a, str>,
    release: Cow<'a, str>,
}

impl<'a> EVR<'a> {
    pub fn new<T: Into<Cow<'a, str>>>(epoch: T, version: T, release: T) -> EVR<'a> {
        EVR {
            epoch: epoch.into(),
            version: version.into(),
            release: release.into(),
        }
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn values(&self) -> (&str, &str, &str) {
        (&self.epoch, &self.version, &self.release)
    }

    pub fn parse_values(evr: &'a str) -> (&'a str, &'a str, &'a str) {
        let (epoch, vr) = evr.split_once(':').unwrap_or(evr.split_at(0));
        let (version, release) = vr.split_once('-').unwrap_or((vr, ""));

        (epoch, version, release)
    }

    pub fn parse(evr: &'a str) -> Self {
        EVR::parse_values(evr).into()
    }
}

impl<'a> From<(&'a str, &'a str, &'a str)> for EVR<'a> {
    fn from(val: (&'a str, &'a str, &'a str)) -> Self {
        EVR::new(val.0, val.1, val.2)
    }
}

impl<'a> PartialEq for EVR<'a> {
    fn eq(&self, other: &Self) -> bool {
        ((self.epoch == other.epoch)
            || (self.epoch == "" && other.epoch == "0")
            || (self.epoch == "0" && other.epoch == ""))
            && self.version == other.version
            && self.release == other.release
    }
}

impl<'a> fmt::Display for EVR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.epoch.is_empty() {
            write!(f, "{}:", self.epoch)?;
        }

        write!(f, "{}-{}", self.version, self.release)
    }
}

impl<'a> PartialOrd for EVR<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for EVR<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        let epoch_1 = if self.epoch.is_empty() {
            "0"
        } else {
            &self.epoch
        };
        let epoch_2 = if other.epoch.is_empty() {
            "0"
        } else {
            &other.epoch
        };

        let epoch_cmp = compare_version_string(epoch_1, epoch_2);
        if epoch_cmp != Ordering::Equal {
            return epoch_cmp;
        }

        let version_cmp = compare_version_string(&self.version, &other.version);
        if version_cmp != Ordering::Equal {
            return version_cmp;
        }

        compare_version_string(&self.release, &other.release)
    }
}

fn compare_version_string(version1: &str, version2: &str) -> Ordering {
    if version1 == version2 {
        return Ordering::Equal;
    }

    let mut version1_part = version1.clone();
    let mut version2_part = version2.clone();

    let not_alphanumeric_tilde_or_caret =
        |c: char| !c.is_ascii_alphanumeric() && c != '~' && c != '^';

    loop {
        // Strip any leading non-alphanumeric, non-tilde characters
        version1_part = version1_part.trim_start_matches(not_alphanumeric_tilde_or_caret);
        version2_part = version2_part.trim_start_matches(not_alphanumeric_tilde_or_caret);

        // Tilde separator parses as "older" or less
        match (
            version1_part.strip_prefix('~'),
            version2_part.strip_prefix('~'),
        ) {
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                version1_part = a;
                version2_part = b;
                continue;
            }
            _ => (),
        }

        // if two strings are equal but one is longer, the longer one is considered greater
        match (
            version1_part.strip_prefix('^'),
            version2_part.strip_prefix('^'),
        ) {
            (Some(_), None) => match version2_part.is_empty() {
                true => return Ordering::Greater,
                false => return Ordering::Less,
            },
            (None, Some(_)) => match version1.is_empty() {
                true => return Ordering::Less,
                false => return Ordering::Greater,
            },
            (Some(a), Some(b)) => {
                version1_part = a;
                version2_part = b;
                continue;
            }
            _ => (),
        }

        if version1_part.is_empty() || version2_part.is_empty() {
            break;
        }

        fn matching_contiguous<F>(string: &str, pat: F) -> Option<(&str, &str)>
        where
            F: Fn(char) -> bool,
        {
            Some(
                string.split_at(
                    string
                        .find(|c| !pat(c))
                        .or(Some(string.len()))
                        .filter(|&x| x > 0)?,
                ),
            )
        }

        if version1_part.starts_with(|c: char| c.is_ascii_digit()) {
            match (
                matching_contiguous(version1_part, |c| c.is_ascii_digit()),
                matching_contiguous(version2_part, |c| c.is_ascii_digit()),
            ) {
                (Some(a), Some(b)) => {
                    let (prefix1, version1) = a;
                    let (prefix2, version2) = b;
                    version1_part = version1;
                    version2_part = version2;
                    let ordering = prefix1
                        .trim_start_matches('0')
                        .len()
                        .cmp(&prefix2.trim_start_matches('0').len());
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                    let ordering = prefix1.cmp(&prefix2);
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
                (Some(_), None) => return Ordering::Greater,
                _ => unreachable!(),
            }
        } else {
            match (
                matching_contiguous(version1_part, |c| c.is_ascii_alphabetic()),
                matching_contiguous(version2_part, |c| c.is_ascii_alphabetic()),
            ) {
                (Some(a), Some(b)) => {
                    let (prefix1, version1) = a;
                    let (prefix2, version2) = b;
                    version1_part = version1;
                    version2_part = version2;
                    let ordering = prefix1.cmp(&prefix2);
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
                (Some(_), None) => return Ordering::Less,
                _ => unreachable!(),
            }
        }
    }

    if version1_part.is_empty() && version2_part.is_empty() {
        return Ordering::Equal;
    }

    version1_part.len().cmp(&version2_part.len())
}


/// Compare two strings as RPM EVR values
pub fn rpmvercmp(evr1: &str, evr2: &str) -> Ordering {
    let evr1 = EVR::parse(evr1);
    let evr2 = EVR::parse(evr2);
    evr1.cmp(&evr2)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_evr_tostr() {
        let evr = EVR::new("", "1.2.3", "45");
        assert_eq!("1.2.3-45", evr.to_string());

        let evr = EVR::new("0", "1.2.3", "45");
        assert_eq!("0:1.2.3-45", evr.to_string());
    }

    #[test]
    fn test_evr_parse() {
        let evr = EVR::new("", "1.2.3", "45");
        assert_eq!(EVR::parse("1.2.3-45"), evr);

        let evr = EVR::new("0", "1.2.3", "45");
        assert_eq!(EVR::parse("0:1.2.3-45"), evr);
    }

    #[test]
    fn test_rpmvercmp() {
        assert_eq!(Ordering::Equal, rpmvercmp("0:1.2.3-45", "1.2.3-45"));
        assert_eq!(Ordering::Less, rpmvercmp("1.2.3-45", "1:1.2.3-45"));
        assert_eq!(Ordering::Greater, rpmvercmp("1.2.3-46", "1.2.3-45"));
    }

    #[test]
    fn test_evr_ord() {
        // compare the same EVR without as equal
        let evr1 = EVR::parse("1.2.3-45");
        let evr2 = EVR::parse("1.2.3-45");
        assert!(evr1 == evr2);

        // compare the same EVR with epoch as equal
        let evr1 = EVR::parse("2:1.2.3-45");
        let evr2 = EVR::parse("2:1.2.3-45");
        assert!(evr1 == evr2);

        // compare the same EVR with a default epoch as equal
        let evr1 = EVR::parse("1.2.3-45");
        let evr2 = EVR::parse("0:1.2.3-45");
        assert!(evr1 == evr2);

        // compare EVR with higher epoch and same version / release
        let evr1 = EVR::parse("1.2.3-45");
        let evr2 = EVR::parse("1:1.2.3-45");
        assert!(evr1 < evr2);

        // compare EVR with higher epoch taken over EVR with higher version
        let evr1 = EVR::parse("4.2.3-45");
        let evr2 = EVR::parse("1:1.2.3-45");
        assert!(evr1 < evr2);

        // compare versions
        let evr1 = EVR::parse("1.2.3-45");
        let evr2 = EVR::parse("1.2.4-45");
        assert!(evr1 < evr2);

        // compare versions
        let evr1 = EVR::parse("1.23.3-45");
        let evr2 = EVR::parse("1.2.3-45");
        assert!(evr1 > evr2);

        // compare versions
        let evr1 = EVR::parse("12.2.3-45");
        let evr2 = EVR::parse("1.2.3-45");
        assert!(evr1 > evr2);

        // compare versions
        let evr1 = EVR::parse("1.2.3-45");
        let evr2 = EVR::parse("1.12.3-45");
        assert!(evr1 < evr2);

        // compare versions with tilde parsing as older
        let evr1 = EVR::parse("~1.2.3-45");
        let evr2 = EVR::parse("1.2.3-45");
        assert!(evr1 < evr2);

        // compare versions with tilde parsing as older
        let evr1 = EVR::parse("~12.2.3-45");
        let evr2 = EVR::parse("1.2.3-45");
        assert!(evr1 < evr2);

        // compare versions with tilde parsing as older
        let evr1 = EVR::parse("~12.2.3-45");
        let evr2 = EVR::parse("~1.2.3-45");
        assert!(evr1 > evr2);

        // compare versions with tilde parsing as older
        let evr1 = EVR::parse("~3:12.2.3-45");
        let evr2 = EVR::parse("0:1.2.3-45");
        assert!(evr1 < evr2);

        // compare release
        let evr1 = EVR::parse("1.2.3-45");
        let evr2 = EVR::parse("1.2.3-46");
        assert!(evr1 < evr2);

        // compare release
        let evr1 = EVR::parse("1.2.3-3");
        let evr2 = EVR::parse("1.2.3-10");
        assert!(evr1 < evr2);
    }

    #[test]
    fn test_compare_version_string() {
        // pedestrian cases
        assert_eq!(Ordering::Less, compare_version_string("1.0", "2.0"));
        assert_eq!(Ordering::Greater, compare_version_string("2.0", "1.0"));
        assert_eq!(Ordering::Equal, compare_version_string("1.0", "1.0"));

        assert_eq!(Ordering::Less, compare_version_string("2.0", "2.0.1"));
        assert_eq!(Ordering::Greater, compare_version_string("2.0.1", "2.0"));
        assert_eq!(Ordering::Equal, compare_version_string("2.0.1", "2.0.1"));

        assert_eq!(Ordering::Equal, compare_version_string("3.0.1a", "3.0.1a"));
        assert_eq!(Ordering::Greater, compare_version_string("3.0.1a", "3.0.1"));
        assert_eq!(Ordering::Equal, compare_version_string("3.0.1a", "3.0.1a"));

        // dot v. underscore equivalence
        assert_eq!(Ordering::Equal, compare_version_string("4_0", "4_0"));
        assert_eq!(Ordering::Equal, compare_version_string("4_0", "4.0"));
        assert_eq!(Ordering::Equal, compare_version_string("4.0", "4_0"));

        assert_eq!(Ordering::Less, compare_version_string("4.999", "5.0"));
        assert_eq!(Ordering::Less, compare_version_string("4.999.9", "5.0"));
        assert_eq!(Ordering::Greater, compare_version_string("5.0", "4.999_9"));

        // version comparisons with tilde and caret
        assert_eq!(Ordering::Equal, compare_version_string("1.0^", "1.0^"));
        assert_eq!(Ordering::Greater, compare_version_string("1.0^", "1.0"));
        assert_eq!(Ordering::Less, compare_version_string("1.0", "1.0git1^"));
        assert_eq!(
            Ordering::Less,
            compare_version_string("1.0^git1", "1.0^git2")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.01", "1.0^git1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0^20210501", "1.0^20210501")
        );
        assert_eq!(
            Ordering::Less,
            compare_version_string("1.0^20210501", "1.0.1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0^20210501^git1", "1.0^20210501^git1")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0^20210502", "1.0^20210501^git1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0~rc1^git1", "1.0~rc1^git1")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0~rc1^git1", "1.0~rc1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0^git1~pre", "1.0^git1~pre")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0^git1", "1.0^git1~pre")
        );

        // non-intuitive behavior
        assert_eq!(Ordering::Less, compare_version_string("1e.fc33", "1.fc33"));
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1g.fc33", "1.fc33")
        );

        // non-ascii characters compare as the same
        assert_eq!(Ordering::Equal, compare_version_string("1.1.α", "1.1.α"));
        assert_eq!(Ordering::Equal, compare_version_string("1.1.α", "1.1.β"));
        assert_eq!(Ordering::Equal, compare_version_string("1.1.αα", "1.1.α"));
        assert_eq!(Ordering::Equal, compare_version_string("1.1.α", "1.1.ββ"));
    }

    #[test]
    fn test_edge_cases() {
        assert_eq!(EVR::parse_values("-"), ("", "", ""));
        assert_eq!(EVR::parse_values("."), ("", ".", ""));
        assert_eq!(EVR::parse_values(":"), ("", "", ""));
        assert_eq!(EVR::parse_values(":-"), ("", "", ""));
        assert_eq!(EVR::parse_values(".-"), ("", ".", ""));
        assert_eq!(EVR::parse_values("0"), ("", "0", ""));
        assert_eq!(EVR::parse_values("0-"), ("", "0", ""));
        assert_eq!(EVR::parse_values(":0"), ("", "0", ""));
        assert_eq!(EVR::parse_values("0:"), ("0", "", ""));
        assert_eq!(EVR::parse_values("asdf:"), ("asdf", "", ""));
        assert_eq!(EVR::parse_values("~:"), ("~", "", ""));
    }
}
