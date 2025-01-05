//!  Generic Handshake for Tor. Extension of Tor circuit creation handshake design.
//!
//! Tor circuit handshakes all implement a one-way-authenticated key
//! exchange, where a client that knows a public "onion key" for a
//! relay sends a "client onionskin" to extend to a relay, and receives a
//! "relay onionskin" in response.  When the handshake is successful,
//! both the client and relay share a set of session keys, and the
//! client knows that nobody _else_ shares those keys unless they
//! relay's private onion key.
//!
//! Currently, this module implements only the "ntor" handshake used
//! for circuits on today's Tor.
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use crate::{common::colorize, Error, Result};

use bytes::BufMut;
use tor_bytes::SecretBuf;

pub const SESSION_ID_LEN: usize = 8;
#[derive(PartialEq, PartialOrd, Clone, Copy)]
pub struct SessionID([u8; SESSION_ID_LEN]);

impl core::fmt::Display for SessionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", colorize(hex::encode(self.0)))
    }
}

impl core::fmt::Debug for SessionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl From<[u8; SESSION_ID_LEN]> for SessionID {
    fn from(value: [u8; SESSION_ID_LEN]) -> Self {
        SessionID(value)
    }
}

impl TryFrom<&[u8]> for SessionID {
    type Error = Error;
    fn try_from(buf: &[u8]) -> Result<Self> {
        if buf.len() < SESSION_ID_LEN {
            return Err(
                IoError::new(IoErrorKind::InvalidInput, "too few bytes for session id").into(),
            );
        }
        let v: [u8; SESSION_ID_LEN] = core::array::from_fn(|i| buf[i]);
        Ok(SessionID(v))
    }
}

pub trait ClientHandshakeMaterials {
    /// The type for the onion key.
    type IdentityKeyType;
    /// Type of extra data sent from client (without forward secrecy).
    type ClientAuxData: ?Sized;

    fn node_pubkey(&self) -> &Self::IdentityKeyType;
    fn aux_data(&self) -> Option<&Self::ClientAuxData>;
}

/// A ClientHandshake is used to generate a client onionskin and
/// handle a relay onionskin.
pub trait ClientHandshake {
    type HandshakeMaterials: ClientHandshakeMaterials;
    /// The type for the state that the client holds while waiting for a reply.
    type StateType;
    /// Type of extra data returned by server (without forward secrecy).
    type HsOutput: ClientHandshakeComplete;

    /// Generate a new client onionskin for a relay with a given onion key,
    /// including `client_aux_data` to be sent without forward secrecy.
    ///
    /// On success, return a state object that will be used to
    /// complete the handshake, along with the message to send.
    fn client1(materials: Self::HandshakeMaterials) -> Result<(Self::StateType, Vec<u8>)>;

    /// Handle an onionskin from a relay, and produce aux data returned
    /// from the server, and a key generator.
    ///
    /// The state object must match the one that was used to make the
    /// client onionskin that the server is replying to.
    fn client2<T: AsRef<[u8]>>(state: &mut Self::StateType, msg: T) -> Result<(Self::HsOutput)>;
}

pub trait ClientHandshakeComplete {
    type KeyGen;
    type ServerAuxData;
    type Remainder;
    fn keygen(&self) -> Self::KeyGen;
    fn extensions(&self) -> &Self::ServerAuxData;
    fn remainder(&self) -> Self::Remainder;
}

/// Trait for an object that handles incoming auxiliary data and
/// returns the server's auxiliary data to be included in the reply.
///
/// This is implemented for `FnMut(&H::ClientAuxData) -> Option<H::ServerAuxData>` automatically.
pub(crate) trait AuxDataReply<H>
where
    H: ServerHandshake + ?Sized,
{
    /// Given a list of extensions received from a client, decide
    /// what extensions to send in reply.
    ///
    /// Return None if the handshake should fail.
    fn reply(&mut self, msg: &H::ClientAuxData) -> Option<H::ServerAuxData>;
}

impl<F, H> AuxDataReply<H> for F
where
    H: ServerHandshake + ?Sized,
    F: FnMut(&H::ClientAuxData) -> Option<H::ServerAuxData>,
{
    fn reply(&mut self, msg: &H::ClientAuxData) -> Option<H::ServerAuxData> {
        self(msg)
    }
}

/// A ServerHandshake is used to handle a client onionskin and generate a
/// server onionskin. It is assumed that the (long term identity) keys are stored
/// as part of the object implementing this trait.
pub(crate) trait ServerHandshake {
    /// Custom parameters used per handshake rather than long lived config stored
    /// in the object implementing this trait.
    type HandshakeParams;
    /// The returned key generator type.
    type KeyGen;
    /// Type of extra data sent from client (without forward secrecy).
    type ClientAuxData: ?Sized;
    /// Type of extra data returned by server (without forward secrecy).
    type ServerAuxData;

    /// Perform the server handshake.  Take as input a function for processing
    /// requested extensions, a slice of all our private onion keys, and the
    /// client's message.
    ///
    /// On success, return a key generator and a server handshake message
    /// to send in reply.
    ///
    /// The self parameter is a type / struct for (potentially shared) state
    /// accessible during the server handshake.
    fn server<REPLY: AuxDataReply<Self>, T: AsRef<[u8]>, Out:BufMut>(
        &self,
        reply_fn: &mut REPLY,
        materials: Self::HandshakeParams,
        msg: T,
        reply_buf: &mut Out,
    ) -> RelayHandshakeResult<Self::KeyGen>;
}

/// A KeyGenerator is returned by a handshake, and used to generate
/// session keys for the protocol.
///
/// Typically, it wraps a KDF function, and some seed key material.
///
/// It can only be used once.
#[allow(unreachable_pub)] // This is only exported depending on enabled features.
pub trait KeyGenerator {
    /// Consume the key
    fn expand(self, keylen: usize) -> Result<SecretBuf>;
}

pub trait SessionIdentifier {
    type ID: core::fmt::Display + core::fmt::Debug + PartialEq;
    fn session_id(&mut self) -> Self::ID;
}

/// Generates keys based on SHAKE-256.
pub(crate) struct ShakeKeyGenerator {
    /// Seed for the key generator
    seed: SecretBuf,
}

impl ShakeKeyGenerator {
    /// Create a key generator based on a provided seed
    #[allow(dead_code)] // We'll construct these for v3 onion services
    pub(crate) fn new(seed: SecretBuf) -> Self {
        ShakeKeyGenerator { seed }
    }
}

impl KeyGenerator for ShakeKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        use crate::common::kdf::{Kdf, ShakeKdf};
        ShakeKdf::new().derive(&self.seed[..], keylen)
    }
}

/// An error produced by a Relay's attempt to handle a client's onion handshake.
#[derive(Debug, thiserror::Error)]
pub enum RelayHandshakeError {
    /// Occurs when a check did not fail, but requires updated input from the
    /// calling context. For example, a handshake that requires more bytes to
    /// before it can succeed or fail.
    #[error("try again with updated input")]
    EAgain,

    /// An error in parsing a handshake message.
    #[error("Problem decoding onion handshake")]
    Fmt(#[from] tor_bytes::Error),

    /// The client asked for a key we didn't have.
    #[error("Client asked for a key or ID that we don't have")]
    MissingKey,

    /// The client did something wrong with their handshake or cryptography.
    #[error("Bad handshake from client")]
    BadClientHandshake,

    /// The server did something wrong with their handshake or cryptography or
    /// an otherwise invalid response was received
    #[error("Bad handshake from server")]
    BadServerHandshake,

    /// The client's handshake matched a previous handshake indicating a potential replay attack.
    #[error("Handshake from client was seen recently -- potentially replayed.")]
    ReplayedHandshake,

    /// Cryptography error occurred while performing the handshake
    // I think this could happen when someone tries to connect with a valid client, but invalid
    // identity key. I am not sure about that though. TODO: add test
    #[error("Failed to decapsulate a message despite finding the mark and validating the MAC")]
    FailedDecapsulation,

    /// Cryptography error occurred while performing the server handshake
    // This should never happen in production, but could happen in dev environments, tests, or custom
    // implementations.
    #[error("Failed to encapsulate a shared secret. Likely a bug in the OKEM impl or a bad rng")]
    FailedEncapsulation,

    /// Encountered an Error while attempting to parse a cryptographic value (key / ciphertext)
    // TODO: add test
    #[error("Failed to parse cryptographic value")]
    FailedParse,

    /// Error occurred while creating a frame.
    #[error("Problem occurred while building handshake")]
    FrameError(String),

    /// An internal error.
    #[error("Internal error")]
    Internal(#[from] tor_error::Bug),
}

/// Type alias for results from a relay's attempt to handle a client's onion
/// handshake.
pub(crate) type RelayHandshakeResult<T> = std::result::Result<T, RelayHandshakeError>;
