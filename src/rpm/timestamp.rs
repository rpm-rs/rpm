use std::time::SystemTime;

/// Timestamp as a number of seconds that have elapsed since
/// January 1, 1970 (midnight UTC/GMT), not counting leap seconds
/// (in ISO 8601: 1970-01-01T00:00:00Z).
///
/// It can be converted from [`SystemTime`][std::time::SystemTime] and
/// [`chrono::DateTime`] using the [`TryInto`] trait.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Timestamp(pub u32);

impl Timestamp {
    /// Returns the timestamp corresponding to “now”.
    pub fn now() -> Self {
        SystemTime::now().try_into().unwrap()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TimestampError {
    Underflow,
    Overflow,
}

impl From<u32> for Timestamp {
    fn from(t: u32) -> Timestamp {
        Timestamp(t)
    }
}

impl From<Timestamp> for u32 {
    fn from(t: Timestamp) -> u32 {
        t.0
    }
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = TimestampError;

    fn try_from(st: SystemTime) -> Result<Timestamp, Self::Error> {
        st.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TimestampError::Underflow)
            .and_then(|t| t.as_secs().try_into().map_err(|_| TimestampError::Overflow))
            .map(Timestamp)
    }
}

#[cfg(feature = "chrono")]
impl<TZ: chrono::TimeZone> TryFrom<chrono::DateTime<TZ>> for Timestamp {
    type Error = TimestampError;

    fn try_from(dt: chrono::DateTime<TZ>) -> Result<Timestamp, Self::Error> {
        let t = dt.with_timezone(&chrono::Utc).timestamp();
        if t < 0 {
            return Err(TimestampError::Underflow);
        }
        t.try_into()
            .map_err(|_| TimestampError::Overflow)
            .map(Timestamp)
    }
}
