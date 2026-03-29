use crate::errors::Error;

/// Allowed special characters in RPM package names (matching RPM's ALLOWED_CHARS_NAME).
const ALLOWED_CHARS_NAME: &[u8] = b".-_+%{}";

/// Allowed first characters in RPM package names (matching RPM's ALLOWED_FIRSTCHARS_NAME),
/// in addition to alphanumeric characters.
const ALLOWED_FIRSTCHARS_NAME: &[u8] = b"_%";

/// Allowed special characters in RPM version/release strings (matching RPM's ALLOWED_CHARS_VERREL).
const ALLOWED_CHARS_VERSION_RELEASE: &[u8] = b"._+%{}~^";

/// Reject strings containing ASCII control characters (except tab and newline).
/// These characters cause problems in downstream consumers like XML repository metadata.
pub(crate) fn reject_control_chars(field: &'static str, value: &str) -> Result<(), Error> {
    if value
        .bytes()
        .any(|b| b.is_ascii_control() && b != b'\t' && b != b'\n')
    {
        return Err(Error::InvalidControlChar {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

/// Validate an RPM package name. Names must start with an alphanumeric character, `_`, or `%`,
/// and may only contain alphanumeric characters plus `.-_+%{}`.
pub(crate) fn validate_name(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidCharacters {
            field: "name",
            value: value.to_string(),
            reason: "must not be empty",
        });
    }
    let first = value.as_bytes()[0];
    if !first.is_ascii_alphanumeric() && !ALLOWED_FIRSTCHARS_NAME.contains(&first) {
        return Err(Error::InvalidCharacters {
            field: "name",
            value: value.to_string(),
            reason: "must start with an alphanumeric character, '_', or '%'",
        });
    }
    if let Some(bad) = value
        .bytes()
        .find(|b| !b.is_ascii_alphanumeric() && !ALLOWED_CHARS_NAME.contains(b))
    {
        return Err(Error::InvalidCharacters {
            field: "name",
            value: value.to_string(),
            reason: if bad.is_ascii_whitespace() {
                "must not contain whitespace"
            } else {
                "contains invalid character (allowed: alphanumeric, '.', '-', '_', '+', '%', '{', '}')"
            },
        });
    }
    Ok(())
}

/// Validate an RPM version or release string. May only contain alphanumeric characters
/// plus `._+%{}~^`.
pub(crate) fn validate_version(field: &'static str, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidCharacters {
            field,
            value: value.to_string(),
            reason: "must not be empty",
        });
    }
    if value
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && !ALLOWED_CHARS_VERSION_RELEASE.contains(&b))
    {
        return Err(Error::InvalidCharacters {
            field,
            value: value.to_string(),
            reason: "contains invalid character (allowed: alphanumeric, '.', '_', '+', '%', '{', '}', '~', '^')",
        });
    }
    Ok(())
}

/// Normalize an RPM file path by collapsing repeated slashes and removing trailing slashes.
///
/// The input must start with `/` or `./` and must not be `/` or `./` alone
/// (callers should validate and reject these before calling this function).
///
/// This is analogous to RPM's `normalize_path()` which uses `std::filesystem::path::lexically_normal()`,
/// but does not resolve `.` or `..` path components.
pub(crate) fn normalize_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                result.push(ch);
            }
            prev_slash = true;
        } else {
            result.push(ch);
            prev_slash = false;
        }
    }
    // Remove trailing slash. Callers must reject "/" and "./" before calling this.
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error;

    mod normalize_path {
        use super::*;

        #[test]
        fn test_normalize_path_already_normalized() {
            assert_eq!(normalize_path("/usr/bin/foo"), "/usr/bin/foo");
            assert_eq!(normalize_path("./usr/bin/foo"), "./usr/bin/foo");
            assert_eq!(normalize_path("/foo"), "/foo");
            assert_eq!(normalize_path("./foo"), "./foo");
        }

        #[test]
        fn test_normalize_path_collapse_slashes() {
            assert_eq!(normalize_path("//usr//bin//foo"), "/usr/bin/foo");
            assert_eq!(normalize_path(".//usr//bin"), "./usr/bin");
            assert_eq!(normalize_path("/usr///bin////foo"), "/usr/bin/foo");
        }

        #[test]
        fn test_normalize_path_strip_trailing_slash() {
            assert_eq!(normalize_path("/usr/bin/"), "/usr/bin");
            assert_eq!(normalize_path("./usr/bin/"), "./usr/bin");
            assert_eq!(normalize_path("/foo/"), "/foo");
            assert_eq!(normalize_path("./foo/"), "./foo");
        }

        #[test]
        fn test_normalize_path_collapse_and_strip() {
            assert_eq!(normalize_path("//usr///bin//foo/"), "/usr/bin/foo");
            assert_eq!(normalize_path(".//etc//"), "./etc");
            assert_eq!(normalize_path("/usr/bin///"), "/usr/bin");
        }
    }

    mod reject_control_chars {
        use super::*;

        #[test]
        fn test_reject_control_chars() {
            // ASCII control characters should be rejected
            assert!(matches!(
                reject_control_chars("test", "foo\x07bar"),
                Err(Error::InvalidControlChar { .. })
            ));
            assert!(matches!(
                reject_control_chars("test", "foo\x00bar"),
                Err(Error::InvalidControlChar { .. })
            ));
            assert!(matches!(
                reject_control_chars("test", "foo\x1b[0m"),
                Err(Error::InvalidControlChar { .. })
            ));
            // DEL (0x7F) should be rejected
            assert!(matches!(
                reject_control_chars("test", "foo\x7f"),
                Err(Error::InvalidControlChar { .. })
            ));
        }

        #[test]
        fn test_reject_control_chars_allows_tab_and_newline() {
            assert!(reject_control_chars("test", "line1\nline2\ttabbed").is_ok());
        }

        #[test]
        fn test_reject_control_chars_allows_normal_text() {
            assert!(reject_control_chars("test", "hello world").is_ok());
            assert!(reject_control_chars("test", "").is_ok());
        }
    }

    mod validate_name {
        use super::*;

        #[test]
        fn test_validate_name_valid() {
            assert!(validate_name("foo").is_ok());
            assert!(validate_name("foo-bar").is_ok());
            assert!(validate_name("foo_bar").is_ok());
            assert!(validate_name("foo.bar").is_ok());
            assert!(validate_name("foo+bar").is_ok());
            assert!(validate_name("_foo").is_ok());
            assert!(validate_name("%{name}").is_ok());
        }

        #[test]
        fn test_validate_name_empty() {
            assert!(matches!(
                validate_name(""),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        #[test]
        fn test_validate_name_invalid_first_char() {
            assert!(matches!(
                validate_name("-foo"),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        #[test]
        fn test_validate_name_invalid_chars() {
            assert!(matches!(
                validate_name("foo bar"),
                Err(Error::InvalidCharacters { .. })
            ));
            assert!(matches!(
                validate_name("foo@bar"),
                Err(Error::InvalidCharacters { .. })
            ));
        }
    }

    mod validate_version {
        use super::*;

        #[test]
        fn test_validate_version_valid() {
            assert!(validate_version("version", "1.0.0").is_ok());
            assert!(validate_version("version", "1.0.0~rc1").is_ok());
            assert!(validate_version("version", "1.0.0^post1").is_ok());
            assert!(validate_version("version", "1.0+git123").is_ok());
        }

        #[test]
        fn test_validate_version_empty() {
            assert!(matches!(
                validate_version("version", ""),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        #[test]
        fn test_validate_version_invalid_chars() {
            // Hyphen not allowed in version (allowed in name)
            assert!(matches!(
                validate_version("version", "1.0-beta"),
                Err(Error::InvalidCharacters { .. })
            ));
            assert!(matches!(
                validate_version("version", "1.0 0"),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        #[test]
        fn test_validate_version_release() {
            assert!(matches!(
                validate_version("release", "1-beta"),
                Err(Error::InvalidCharacters { .. })
            ));
        }
    }
}
