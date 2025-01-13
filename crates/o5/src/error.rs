use crate::framing::FrameError;

use std::array::TryFromSliceError;
use std::num::NonZeroUsize;
use std::string::FromUtf8Error;
use std::{fmt::Display, str::FromStr};

use hex::FromHexError;
use sha2::digest::InvalidLength;

use crate::common::ntor_arti::RelayHandshakeError;

/// Result type returning [`Error`] or `T`
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when using the transports, including wrapped from dependencies.
impl std::error::Error for Error {}
#[derive(Debug)]
pub enum Error {
    Bug(tor_error::Bug),

    Other(Box<dyn std::error::Error + Send + Sync>),
    IOError(std::io::Error),
    EncodeError(Box<dyn std::error::Error + Send + Sync>),
    Utf8Error(FromUtf8Error),
    RngSourceErr(getrandom::Error),
    Crypto(String),
    NullTransport,
    NotImplemented,
    NotSupported,
    Cancelled,
    HandshakeTimeout,
    BadCircHandshakeAuth,
    InvalidKDFOutputLength,

    /// An error that occurred in the tor_bytes crate while decoding an
    /// object.
    // #[error("Unable to parse {object}")]
    BytesError {
        /// What we were trying to parse.
        object: &'static str,
        /// The error that occurred while parsing it.
        // #[source]
        err: tor_bytes::Error,
    },
    // TODO: do we need to keep this?
    CellDecodeErr {
        /// What we were trying to parse.
        object: &'static str,
        /// The error that occurred while parsing it.
        err: tor_cell::Error,
    },
    HandshakeErr(RelayHandshakeError),

    O5Framing(FrameError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::Bug(_) => write!(f, "Internal error occured (bug)"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::Other(e) => write!(f, "{}", e),
            Error::IOError(e) => write!(f, "{}", e),
            Error::EncodeError(e) => write!(f, "{}", e),
            Error::Utf8Error(e) => write!(f, "{}", e),
            Error::RngSourceErr(e) => write!(f, "{}", e),
            Error::Crypto(e) => write!(f, "cryptographic err: {}", e),
            Error::NotImplemented => write!(f, "NotImplemented"),
            Error::NotSupported => write!(f, "NotSupported"),
            Error::NullTransport => write!(f, "NullTransport"),
            Error::HandshakeTimeout => write!(f, "handshake timed out"),
            Error::BadCircHandshakeAuth => write!(f, "failed authentication for circuit handshake"),
            Error::InvalidKDFOutputLength => {
                write!(f, "Tried to extract too many bytes from a KDF")
            }
            Error::BytesError { object, err } => write!(f, "Unable to parse {object}: {err}"),
            Error::CellDecodeErr { object, err } => {
                write!(f, "Unable to decode cell {object}: {err}")
            }
            Error::HandshakeErr(err) => write!(f, "handshake failed or unable to complete: {err}"),

            Error::O5Framing(e) => write!(f, "obfs4 framing error: {e}"),
        }
    }
}

unsafe impl Send for Error {}

impl Error {
    pub fn other<T: Into<Box<dyn std::error::Error + Send + Sync>>>(e: T) -> Self {
        Error::Other(e.into())
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::IOError(io_err) => io_err,
            e => std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")),
        }
    }
}

impl FromStr for Error {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Error::other(s))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<Box<std::io::Error>> for Error {
    fn from(e: Box<std::io::Error>) -> Self {
        Error::IOError(*e)
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        Error::EncodeError(Box::new(e))
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for Error {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Error::Other(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e.into())
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Error::Other(e.into())
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::Utf8Error(e)
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::RngSourceErr(e)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(e: TryFromSliceError) -> Self {
        Error::Other(Box::new(e))
    }
}

impl From<InvalidLength> for Error {
    fn from(e: InvalidLength) -> Self {
        Error::Other(Box::new(e))
    }
}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Error::O5Framing(e)
    }
}

impl From<RelayHandshakeError> for Error {
    fn from(value: RelayHandshakeError) -> Self {
        Error::HandshakeErr(value)
    }
}

impl From<tor_error::Bug> for Error {
    fn from(value: tor_error::Bug) -> Self {
        Error::Bug(value)
    }
}

impl From<tor_cell::Error> for Error {
    fn from(value: tor_cell::Error) -> Self {
        Error::CellDecodeErr {
            object: "",
            err: value,
        }
    }
}

impl Error {
    /// Create an error for a tor_bytes error that occurred while encoding
    /// something of type `object`.
    pub(crate) fn from_bytes_enc(err: tor_bytes::EncodeError, _object: &'static str) -> Error {
        Error::EncodeError(Box::new(err))
    }

    /// Create an error for a tor_bytes error that occurred while parsing
    /// something of type `object`.
    pub(crate) fn from_bytes_err(err: tor_bytes::Error, object: &'static str) -> Error {
        Error::BytesError { err, object }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_other_error() {
        let err = Error::other("some other error");
        assert_eq!(format!("{}", err), "some other error");
    }

    #[test]
    fn test_display_io_error() {
        let err = Error::IOError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "some io error",
        ));
        assert_eq!(format!("{}", err), "some io error");
    }

    #[test]
    fn test_display_encode_error() {
        let err = Error::EncodeError(Box::new(FromHexError::InvalidHexCharacter {
            c: 'z',
            index: 0,
        }));
        assert_eq!(format!("{}", err), "Invalid character 'z' at position 0");
    }

    #[test]
    fn test_display_null_transport_error() {
        let err = Error::NullTransport;
        assert_eq!(format!("{}", err), "NullTransport");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "some io error");
        let err = Error::from(io_err);
        assert_eq!(format!("{}", err), "some io error");
    }

    #[test]
    fn test_from_encode_error() {
        let hex_err = FromHexError::InvalidHexCharacter { c: 'z', index: 0 };
        let err = Error::from(hex_err);
        assert_eq!(format!("{}", err), "Invalid character 'z' at position 0");
    }

    #[test]
    fn test_from_other_error() {
        let other_err = Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "some other error",
        ));
        let err = Error::from(other_err);
        assert_eq!(format!("{}", err), "some other error");
    }
}
