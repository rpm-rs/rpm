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
    Bzip2,
}

impl std::str::FromStr for CompressionType {
    type Err = Error;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "gzip" => Ok(CompressionType::Gzip),
            "zstd" => Ok(CompressionType::Zstd),
            "xz" => Ok(CompressionType::Xz),
            "bzip2" => Ok(CompressionType::Bzip2),
            _ => Err(Error::UnknownCompressorType(raw.to_string())),
        }
    }
}

pub enum Compressor {
    None(Vec<u8>),
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    /// If the `zstdmt` feature flag is enabled, compression will use all available cores to
    /// compress the file.
    Zstd(zstd::stream::Encoder<'static, Vec<u8>>),
    Xz(xz2::write::XzEncoder<Vec<u8>>),
    Bzip2(bzip2::write::BzEncoder<Vec<u8>>),
}

impl TryFrom<CompressionWithLevel> for Compressor {
    type Error = Error;

    fn try_from(value: CompressionWithLevel) -> Result<Self, Self::Error> {
        match value {
            CompressionWithLevel::None => Ok(Compressor::None(Vec::new())),
            CompressionWithLevel::Gzip(level) => Ok(Compressor::Gzip(
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level)),
            )),
            CompressionWithLevel::Zstd(level) => {
                #[cfg_attr(not(feature = "zstdmt"), allow(unused_mut))]
                let mut stream = zstd::stream::Encoder::new(Vec::new(), level)?;

                #[cfg(feature = "zstdmt")]
                {
                    let threads = std::thread::available_parallelism()?;
                    // If someone has more than 2^32 threads, I'm impressed
                    stream.multithread(threads.get() as u32)?;
                }

                Ok(Compressor::Zstd(stream))
            }
            CompressionWithLevel::Xz(level) => Ok(Compressor::Xz(xz2::write::XzEncoder::new(
                Vec::new(),
                level,
            ))),
            CompressionWithLevel::Bzip2(level) => Ok(Compressor::Bzip2(
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level)),
            )),
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
            Compressor::Bzip2(encoder) => encoder.write(content),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Compressor::None(data) => data.flush(),
            Compressor::Gzip(encoder) => encoder.flush(),
            Compressor::Zstd(encoder) => encoder.flush(),
            Compressor::Xz(encoder) => encoder.flush(),
            Compressor::Bzip2(encoder) => encoder.flush(),
        }
    }
}

impl Compressor {
    pub(crate) fn finish_compression(self) -> Result<Vec<u8>, Error> {
        match self {
            Compressor::None(data) => Ok(data),
            Compressor::Gzip(encoder) => Ok(encoder.finish()?),
            Compressor::Zstd(encoder) => Ok(encoder.finish()?),
            Compressor::Xz(encoder) => Ok(encoder.finish()?),
            Compressor::Bzip2(encoder) => Ok(encoder.finish()?),
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
    Bzip2(u32),
}

impl CompressionWithLevel {
    pub(crate) fn compression_type(&self) -> CompressionType {
        match self {
            Self::None => CompressionType::None,
            Self::Gzip(_) => CompressionType::Gzip,
            Self::Zstd(_) => CompressionType::Zstd,
            Self::Xz(_) => CompressionType::Xz,
            Self::Bzip2(_) => CompressionType::Bzip2,
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
            CompressionType::Bzip2 => CompressionWithLevel::Bzip2(9),
        }
    }
}
