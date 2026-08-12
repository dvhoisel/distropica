use core::fmt;

/// `scrypt()` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidOutputLen;

/// `ScryptParams` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidParams;

/// Error returned by the allocation-aware low-level scrypt API.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ScryptError {
    /// The caller supplied an invalid output buffer length.
    InvalidOutputLen,
    /// A temporary work buffer could not be allocated without aborting.
    AllocationFailed,
}

impl fmt::Display for InvalidOutputLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid output buffer length")
    }
}

impl core::error::Error for InvalidOutputLen {}

#[cfg(feature = "kdf")]
impl From<InvalidOutputLen> for kdf::Error {
    fn from(_err: InvalidOutputLen) -> kdf::Error {
        kdf::Error
    }
}

impl fmt::Display for InvalidParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid scrypt parameters")
    }
}

impl core::error::Error for InvalidParams {}

impl fmt::Display for ScryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOutputLen => f.write_str("invalid output buffer length"),
            Self::AllocationFailed => f.write_str("scrypt work buffer allocation failed"),
        }
    }
}

impl core::error::Error for ScryptError {}

impl From<InvalidOutputLen> for ScryptError {
    fn from(_: InvalidOutputLen) -> Self {
        Self::InvalidOutputLen
    }
}
