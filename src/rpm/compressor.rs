use std::io::Write;

use crate::errors::*;

pub const GZIP: Gzip = Gzip::new();
pub const ZSTD: Zstd = Zstd::new();
pub const XZ: Xz = Xz::new();

#[derive(Default, Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionType {
    #[default]
    None,
    Gzip {
        level: u8,
    },
    Zstd {
        level: u8,
    },
    Xz {
        level: u8,
    },
}

pub struct Gzip {
    level: u8,
}
pub struct Zstd {
    level: u8,
}
pub struct Xz {
    level: u8,
}

pub(crate) enum Compressor {
    None(Vec<u8>),
    Gzip(libflate::gzip::Encoder<Vec<u8>>),
    Zstd(zstd::stream::Encoder<'static, Vec<u8>>),
    Xz(xz2::write::XzEncoder<Vec<u8>>),
}

// 19 is used here as its 19 for fedora
impl std::str::FromStr for CompressionType {
    type Err = RPMError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "none" => Ok(CompressionType::None),
            "gzip" => Ok(Gzip::new().into()),
            "zstd" => Ok(Zstd::new().into()),
            "xz" => Ok(Xz::new().into()),
            _ => Err(RPMError::UnknownCompressorType(raw.to_string())),
        }
    }
}

impl AsRef<str> for CompressionType {
    fn as_ref(&self) -> &str {
        match self {
            CompressionType::None => "none",
            CompressionType::Gzip { .. } => "gzip",
            CompressionType::Zstd { .. } => "zstd",
            CompressionType::Xz { .. } => "xz",
        }
    }
}

impl From<Gzip> for CompressionType {
    fn from(value: Gzip) -> Self {
        CompressionType::Gzip { level: value.level }
    }
}

impl From<Zstd> for CompressionType {
    fn from(value: Zstd) -> Self {
        CompressionType::Zstd { level: value.level }
    }
}

impl From<Xz> for CompressionType {
    fn from(value: Xz) -> Self {
        CompressionType::Xz { level: value.level }
    }
}

impl From<()> for CompressionType {
    fn from(_: ()) -> Self {
        CompressionType::None
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
            Compressor::Gzip(encoder) => Ok(encoder.finish().into_result()?),
            Compressor::Zstd(encoder) => Ok(encoder.finish()?),
            Compressor::Xz(encoder) => Ok(encoder.finish()?),
        }
    }
}

impl Compressor {
    pub(crate) fn new(compression: CompressionType) -> Result<Self, RPMError> {
        match compression {
            CompressionType::None => Ok(Compressor::None(Vec::new())),
            CompressionType::Gzip { .. } => {
                Ok(Compressor::Gzip(libflate::gzip::Encoder::new(Vec::new())?))
            }
            CompressionType::Zstd { level } => Ok(Compressor::Zstd(zstd::stream::Encoder::new(
                Vec::new(),
                level as i32,
            )?)),
            CompressionType::Xz { level } => Ok(Compressor::Xz(xz2::write::XzEncoder::new(
                Vec::new(),
                level as u32,
            ))),
        }
    }
}

impl Gzip {
    pub const fn new() -> Self {
        Self { level: 9 }
    }

    pub fn with_level(level: u8) -> Self {
        Self { level }
    }
}

impl Zstd {
    pub const fn new() -> Self {
        Self { level: 19 }
    }

    pub fn with_level(level: u8) -> Self {
        Self { level }
    }
}

impl Xz {
    pub const fn new() -> Self {
        Self { level: 9 }
    }

    pub fn with_level(level: u8) -> Self {
        Self { level }
    }
}
