//! obfs5 session details and construction
//!
/// Session state management as a way to organize session establishment and
/// steady state transfer.
use crate::{common::drbg, traits::OKemCore, Digest};

use tor_bytes::Readable;

mod client;
pub(crate) use client::{new_client_session, ClientSession};

mod server;
pub(crate) use server::ServerSession;

/// Initial state for a Session, created with any params.
pub(crate) struct Initialized;

/// A session has completed the handshake and made it to steady state transfer.
pub(crate) struct Established;

/// The session broke due to something like a timeout, reset, lost connection, etc.
trait Fault {}

pub enum Session<K: OKemCore> {
    Client(ClientSession<Established, K>),
    Server(ServerSession<Established>),
}

impl<K: OKemCore> Session<K> {
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
