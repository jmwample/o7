//! # Keys used for testing
//!
//! The hex representations of X-Wing keys are rather large. This module exists to house
//! those representations so they don't muddy up the whole crate.
//!
//! ## Naming Conventions:
//!
//! id: Node ID
//! b: Node identity secret key
//! B: Node identity public key
//!
//! x: Client session secret Key
//! X: Client session public Key
//!
//! y: Server session secret Key
//! Y: Server session public Key
//!
//! within the X-Wing Keys X indicates an X25519 element, and M indicates an ML-KEM element
//!
//! xX: client session secret key x25519 element
//! xM: client session secret key ML-KEM element
//!
//!
//! The shared secrets used in a handshake are
//!
//! xB: client session secret key KEM with node identity public key
//! Xb: server identity secret key KEM with client session public key
//!
//! xB == Xb == xX*BX + xM*BM = XX*bX + XM*bM
//!
//! Xy: server session secret key KEM with client session public key
//! xY: client session secret key KEM with server session public key
//!
//! xY == Xy == xX*YX + xM*YM = XX*yX + XM*yM

#[allow(non_snake_case)]
pub struct HexKeys {
    pub id: &'static str,
    pub b: &'static str,
    pub x: &'static str,
    pub y: &'static str,

    pub xB: &'static str,
    pub xY: &'static str,

    // Ciphertext of x encapsulated using B encoded using Elligator2 and Kemeleon
    pub xB_C_EK: &'static str,

    // Ciphertext of y encapsulated using X encoded using elligator2 and Kemeleon.
    pub Xy_C_EK: &'static str,
}

pub const KEYS: [HexKeys; 1] = [HexKeys {
    id: "aaaaaaaaaaaaaaaaaaaaaaaa9fad2af287ef942632833d21f946c6260c33fae6",
    b: "4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a",
    x: "b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49",
    y: "4865a5b7689dafd978f529291c7171bc159be076b92186405d13220b80e2a053",
    xB: "",
    xY: "",
    xB_C_EK: "",
    Xy_C_EK: "",
}];
