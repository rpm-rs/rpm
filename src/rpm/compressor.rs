use std::io::Write;

use crate::errors::*;

pub enum Compressor {
    None(Vec<u8>),
    Gzip(libflate::gzip::Encoder<Vec<u8>>),
}

impl Write for Compressor {
    fn write(&mut self, content: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Compressor::None(data) => data.write(content),
            Compressor::Gzip(encoder) => encoder.write(content),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Compressor::None(data) => data.flush(),
            Compressor::Gzip(encoder) => encoder.flush(),
        }
    }
}

impl std::str::FromStr for Compressor {
    type Err = RPMError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "none" => Ok(Compressor::None(Vec::new())),
            "gzip" => Ok(Compressor::Gzip(libflate::gzip::Encoder::new(Vec::new())?)),
            _ => Err(RPMError::new(&format!("unknown compressor type {}", raw))),
        }
    }
}

impl Compressor {
    pub(crate) fn finish_compression(self) -> Result<Vec<u8>, RPMError> {
        match self {
            Compressor::None(data) => Ok(data),
            Compressor::Gzip(encoder) => Ok(encoder.finish().into_result()?),
        }
    }

    pub(crate) fn get_details(&self) -> Option<CompressionDetails> {
        match self {
            Compressor::None(_) => None,
            Compressor::Gzip(_) => Some(CompressionDetails {
                compression_level: "9",
                compression_name: "gzip",
            }),
        }
    }
}

pub(crate) struct CompressionDetails {
    pub(crate) compression_level: &'static str,
    pub(crate) compression_name: &'static str,
}
