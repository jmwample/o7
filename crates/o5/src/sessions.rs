//! obfs4 session details and construction
//!
/// Session state management as a way to organize session establishment and
/// steady state transfer.
use crate::common::{drbg, xwing};

use tor_bytes::Readable;

mod client;
pub(crate) use client::{new_client_session, ClientSession};

mod server;
pub(crate) use server::ServerSession;

/// Ephermeral single use session secret key type
pub type SessionSecretKey = xwing::DecapsulationKey;

/// Public key type associated with SessionSecretKey.
pub type SessionPublicKey = xwing::EncapsulationKey;

impl Readable for SessionPublicKey {
    fn take_from(_b: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
        todo!("SessionPublicKey Reader needs implemented");
    }
}

/// Initial state for a Session, created with any params.
pub(crate) struct Initialized;

/// A session has completed the handshake and made it to steady state transfer.
pub(crate) struct Established;

/// The session broke due to something like a timeout, reset, lost connection, etc.
trait Fault {}

pub enum Session {
    Client(ClientSession<Established>),
    Server(ServerSession<Established>),
}

impl Session {
    #[allow(unused)]
    pub fn id(&self) -> String {
        match self {
            Session::Client(cs) => format!("c{}", cs.session_id()),
            Session::Server(ss) => format!("s{}", ss.session_id()),
        }
    }

    pub fn biased(&self) -> bool {
        match self {
            Session::Client(cs) => cs.biased(),
            Session::Server(ss) => ss.biased, //biased,
        }
    }

    pub fn len_seed(&self) -> drbg::Seed {
        match self {
            Session::Client(cs) => cs.len_seed(),
            Session::Server(ss) => ss.len_seed(),
        }
    }
}
