use crate::errors::*;
use std::io::Write;

pub enum Compressor {
    None(Vec<u8>),
    Gzip(libflate::gzip::Encoder<Vec<u8>>),
    Zstd(zstd::stream::Encoder<'static, Vec<u8>>),
}

impl Write for Compressor {
    fn write(&mut self, content: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Compressor::None(data) => data.write(content),
            Compressor::Gzip(encoder) => encoder.write(content),
            Compressor::Zstd(encoder) => encoder.write(content),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Compressor::None(data) => data.flush(),
            Compressor::Gzip(encoder) => encoder.flush(),
            Compressor::Zstd(encoder) => encoder.flush(),
        }
    }
}
// 19 is used here as its 19 for fedora
impl std::str::FromStr for Compressor {
    type Err = RPMError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "none" => Ok(Compressor::None(Vec::new())),
            "gzip" => Ok(Compressor::Gzip(libflate::gzip::Encoder::new(Vec::new())?)),
            "zstd" => Ok(Compressor::Zstd(zstd::stream::Encoder::new(
                Vec::new(),
                19,
            )?)),
            _ => Err(RPMError::UnknownCompressorType(raw.to_string())),
        }
    }
}

impl Compressor {
    pub(crate) fn finish_compression(self) -> Result<Vec<u8>, RPMError> {
        match self {
            Compressor::None(data) => Ok(data),
            Compressor::Gzip(encoder) => Ok(encoder.finish().into_result()?),
            Compressor::Zstd(encoder) => Ok(encoder.finish().unwrap()),
        }
    }

    pub(crate) fn get_details(&self) -> Option<CompressionDetails> {
        match self {
            Compressor::None(_) => None,
            Compressor::Gzip(_) => Some(CompressionDetails {
                compression_level: "9",
                compression_name: "gzip",
            }),
            Compressor::Zstd(_) => Some(CompressionDetails {
                compression_level: "19",
                compression_name: "zstd",
            }),
        }
    }
}

pub(crate) struct CompressionDetails {
    pub(crate) compression_level: &'static str,
    pub(crate) compression_name: &'static str,
}
