use std::fmt;

use std::io;

pub struct RPMError {
    message: String,
}

impl std::error::Error for RPMError {}

impl RPMError {
    pub fn new(message: &str) -> Self {
        RPMError {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for RPMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message) // user-facing output
    }
}

impl fmt::Debug for RPMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message) // programmer-facing output
    }
}

impl From<io::Error> for RPMError {
    fn from(error: io::Error) -> Self {
        RPMError {
            message: error.to_string(),
        }
    }
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for RPMError {
    fn from(error: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Self {
        match error {
            nom::Err::Error((_, kind)) | nom::Err::Failure((_, kind)) => RPMError {
                message: kind.description().to_string(),
            },
            nom::Err::Incomplete(_) => RPMError {
                message: "unhandled incomplete".to_string(),
            },
        }
    }
}
