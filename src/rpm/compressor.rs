use std::io::Write;

use crate::errors::*;

/// Supported payload compression types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum CompressionType {
    #[default]
    None,
    Gzip,
    Zstd,
    Xz,
}

impl std::str::FromStr for CompressionType {
    type Err = RPMError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "gzip" => Ok(CompressionType::Gzip),
            "zstd" => Ok(CompressionType::Zstd),
            "xz" => Ok(CompressionType::Xz),
            _ => Err(RPMError::UnknownCompressorType(raw.to_string())),
        }
    }
}

pub enum Compressor {
    None(Vec<u8>),
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Zstd(zstd::stream::Encoder<'static, Vec<u8>>),
    Xz(xz2::write::XzEncoder<Vec<u8>>),
}

impl TryFrom<CompressionWithLevel> for Compressor {
    type Error = RPMError;

    fn try_from(value: CompressionWithLevel) -> Result<Self, Self::Error> {
        match value {
            CompressionWithLevel::None => Ok(Compressor::None(Vec::new())),
            CompressionWithLevel::Gzip(level) => Ok(Compressor::Gzip(
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level)),
            )),
            CompressionWithLevel::Zstd(level) => Ok(Compressor::Zstd(zstd::stream::Encoder::new(
                Vec::new(),
                level,
            )?)),
            CompressionWithLevel::Xz(level) => Ok(Compressor::Xz(xz2::write::XzEncoder::new(
                Vec::new(),
                level,
            ))),
        }
    }
}

impl Write for Compressor {
    fn write(&mut self, content: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Compressor::None(data) => data.write(content),
            Compressor::Gzip(encoder) => encoder.write(content),
            Compressor::Zstd(encoder) => encoder.write(content),
            Compressor::Xz(encoder) => encoder.write(content),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Compressor::None(data) => data.flush(),
            Compressor::Gzip(encoder) => encoder.flush(),
            Compressor::Zstd(encoder) => encoder.flush(),
            Compressor::Xz(encoder) => encoder.flush(),
        }
    }
}

impl Compressor {
    pub(crate) fn finish_compression(self) -> Result<Vec<u8>, RPMError> {
        match self {
            Compressor::None(data) => Ok(data),
            Compressor::Gzip(encoder) => Ok(encoder.finish()?),
            Compressor::Zstd(encoder) => Ok(encoder.finish()?),
            Compressor::Xz(encoder) => Ok(encoder.finish()?),
        }
    }
}

/// Supported compression types, with an associated compression level. This is used for setting
/// a custom compression configuration during RPM building.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionWithLevel {
    None,
    Zstd(i32),
    Gzip(u32),
    Xz(u32),
}

impl CompressionWithLevel {
    pub(crate) fn compression_type(&self) -> CompressionType {
        match self {
            Self::None => CompressionType::None,
            Self::Gzip(_) => CompressionType::Gzip,
            Self::Zstd(_) => CompressionType::Zstd,
            Self::Xz(_) => CompressionType::Xz,
        }
    }
}

impl Default for CompressionWithLevel {
    fn default() -> Self {
        CompressionType::Gzip.into()
    }
}

impl From<CompressionType> for CompressionWithLevel {
    fn from(value: CompressionType) -> Self {
        match value {
            CompressionType::None => CompressionWithLevel::None,
            CompressionType::Gzip => CompressionWithLevel::Gzip(9),
            CompressionType::Xz => CompressionWithLevel::Xz(9),
            CompressionType::Zstd => CompressionWithLevel::Zstd(19),
        }
    }
}
