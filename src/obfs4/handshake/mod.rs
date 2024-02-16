//! Implements the ntor handshake, as used in modern Tor.

use crate::common::ct;
use crate::common::curve25519::{
    EphemeralSecret, PublicKey, PublicRepresentative, SharedSecret, StaticSecret,
};
use crate::common::ntor_arti::{
    AuxDataReply, ClientHandshake, KeyGenerator, RelayHandshakeError, RelayHandshakeResult,
    ServerHandshake,
};
use crate::{Error, Result};

use std::borrow::Borrow;

use tor_bytes::{EncodeResult, Reader, SecretBuf, Writer};
use tor_error::into_internal;
use tor_llcrypto::d::{self, Sha256};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_llcrypto::util::ct::ct_lookup;

use crate::common::kdf::{Kdf, Ntor1Kdf};
use digest::Mac;
use hmac::Hmac;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

pub(crate) const PROTO_ID: &[u8; 24] = b"ntor-curve25519-sha256-1";
pub(crate) const T_MAC: &[u8; 28] = b"ntor-curve25519-sha256-1:mac";
pub(crate) const T_VERIFY: &[u8; 35] = b"ntor-curve25519-sha256-1:key_verify";
pub(crate) const T_KEY: &[u8; 36] = b"ntor-curve25519-sha256-1:key_extract";
pub(crate) const T_EXPAND: &[u8; 35] = b"ntor-curve25519-sha256-1:key_expand";

/// Client side of the Ntor handshake.
pub(crate) struct Obfs4NtorClient;

impl ClientHandshake for Obfs4NtorClient {
    type KeyType = Obfs4NtorPublicKey;
    type StateType = NtorHandshakeState;
    type KeyGen = NtorHkdfKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = ();

    fn client1<R: RngCore + CryptoRng, M: Borrow<()>>(
        rng: &mut R,
        key: &Self::KeyType,
        _client_aux_data: &M,
    ) -> Result<(Self::StateType, Vec<u8>)> {
        client_handshake_obfs4(rng, key)
    }

    fn client2<T: AsRef<[u8]>>(state: Self::StateType, msg: T) -> Result<((), Self::KeyGen)> {
        let keygen = client_handshake2_obfs4(msg, &state)?;
        Ok(((), keygen))
    }
}

/// Server side of the ntor handshake.
pub(crate) struct Obfs4NtorServer;

impl ServerHandshake for Obfs4NtorServer {
    type KeyType = Obfs4NtorSecretKey;
    type KeyGen = NtorHkdfKeyGenerator;
    type ClientAuxData = ();
    type ServerAuxData = ();

    fn server<R: RngCore + CryptoRng, REPLY: AuxDataReply<Self>, T: AsRef<[u8]>>(
        rng: &mut R,
        reply_fn: &mut REPLY,
        key: &[Self::KeyType],
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        reply_fn
            .reply(&())
            .ok_or(RelayHandshakeError::BadClientHandshake)?;

        server_handshake_obfs4(rng, msg, key)
    }
}

/// Key information about a relay used for the ntor v3 handshake.
///
/// Contains a single curve25519 ntor onion key, and the relay's ed25519
/// identity.
#[derive(Clone, Debug)]
pub(crate) struct Obfs4NtorPublicKey {
    /// Public RSA identity fingerprint for the relay; used in authentication
    /// calculation.
    pub(crate) id: RsaIdentity,
    /// The Bridge's identity key.
    pub(crate) pk: PublicKey,
    /// The Elligator2 representative for the public key
    pub(crate) rp: Option<PublicRepresentative>,
}

/// Secret key information used by a relay for the ntor v3 handshake.
pub(crate) struct Obfs4NtorSecretKey {
    /// The relay's public key information
    pk: Obfs4NtorPublicKey,
    /// The secret onion key.
    sk: StaticSecret,
}

impl Obfs4NtorSecretKey {
    /// Construct a new Obfs4NtorSecretKey from its components.
    #[allow(unused)]
    pub(crate) fn new(
        sk: StaticSecret,
        pk: PublicKey,
        rp: Option<PublicRepresentative>,
        id: RsaIdentity,
    ) -> Self {
        Self {
            pk: Obfs4NtorPublicKey { id, pk, rp },
            sk,
        }
    }

    /// Generate a key using the given `rng`, suitable for testing.
    #[cfg(test)]
    pub(crate) fn generate_for_test<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut id = [0_u8; 20];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        let mut sk: StaticSecret = [0u8; 32].into();
        let mut pk1: PublicKey = [0u8; 32].into();
        let mut rp: Option<PublicRepresentative> = None;

        for _ in 0..64 {
            // artificial ceil of 64 so this can't infinite loop

            // approx 50% of keys do not have valid representatives so we just
            // iterate until we find a key where it is valid. This should take
            // a low number of iteratations and always succeed eventually.
            sk = StaticSecret::random_from_rng(&mut rng);
            rp = (&sk).into();
            if rp.is_none() {
                continue;
            }
            pk1 = (&sk).into();
            break;
        }

        let pk = Obfs4NtorPublicKey {
            pk: pk1,
            id: id.into(),
            rp,
        };
        Self { pk, sk }
    }

    /// Return true if the curve25519 public key in `self` matches `pk`.
    ///
    /// Used for looking up keys in an array.
    fn matches_pk(&self, pk: &PublicKey) -> Choice {
        self.pk.pk.as_bytes().ct_eq(pk.as_bytes())
    }
}

/// Client state for an ntor handshake.
pub(crate) struct NtorHandshakeState {
    /// The relay's public key.  We need to remember this since it is
    /// used to finish the handshake.
    relay_public: Obfs4NtorPublicKey,
    /// The temporary curve25519 secret (x) that we've generated for
    /// this handshake.
    // We'd like to EphemeralSecret here, but we can't since we need
    // to use it twice.
    my_sk: StaticSecret,
    /// The public key `X` corresponding to my_sk.
    my_public: PublicKey,
}

/// KeyGenerator for use with ntor circuit handshake.
pub(crate) struct NtorHkdfKeyGenerator {
    /// Secret key information derived from the handshake, used as input
    /// to HKDF
    seed: SecretBuf,
}

impl NtorHkdfKeyGenerator {
    /// Create a new key generator to expand a given seed
    pub(crate) fn new(seed: SecretBuf) -> Self {
        NtorHkdfKeyGenerator { seed }
    }
}

impl KeyGenerator for NtorHkdfKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        let ntor1_key = &T_KEY[..];
        let ntor1_expand = &T_EXPAND[..];
        Ntor1Kdf::new(ntor1_key, ntor1_expand).derive(&self.seed[..], keylen)
    }
}

/// Alias for an HMAC output, used to validate correctness of a handshake.
type Authcode = digest::CtOutput<hmac::Hmac<d::Sha256>>;

/// Perform a client handshake, generating an onionskin and a state object
fn client_handshake_obfs4<R>(
    rng: &mut R,
    relay_public: &Obfs4NtorPublicKey,
) -> Result<(NtorHandshakeState, Vec<u8>)>
where
    R: RngCore + CryptoRng,
{
    let my_sk = StaticSecret::random_from_rng(rng);
    let my_public = PublicKey::from(&my_sk);

    client_handshake_obfs4_no_keygen(my_public, my_sk, relay_public)
}

/// Helper: client handshake _without_ generating  new keys.
fn client_handshake_obfs4_no_keygen(
    my_public: PublicKey,
    my_sk: StaticSecret,
    relay_public: &Obfs4NtorPublicKey,
) -> Result<(NtorHandshakeState, Vec<u8>)> {
    let mut v: Vec<u8> = Vec::new();

    v.write(&relay_public.id)
        .and_then(|_| v.write(&relay_public.pk.as_bytes()))
        .and_then(|_| v.write(&my_public.as_bytes()))
        .map_err(|e| Error::from_bytes_enc(e, "Can't encode client handshake."))?;

    assert_eq!(v.len(), 20 + 32 + 32);

    let state = NtorHandshakeState {
        relay_public: relay_public.clone(),
        my_public,
        my_sk,
    };

    Ok((state, v))
}

/// Complete a client handshake, returning a key generator on success.
fn client_handshake2_obfs4<T>(msg: T, state: &NtorHandshakeState) -> Result<NtorHkdfKeyGenerator>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());
    let their_pk_bytes: [u8; 32] = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let their_pk = PublicKey::from(their_pk_bytes);
    let auth: Authcode = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&state.relay_public.pk);

    let (keygen, authcode) = ntor_derive(&xy, &xb, &state.relay_public, &state.my_public, &their_pk)
        .map_err(into_internal!("Error deriving keys"))?;

    let okay = authcode.ct_eq(&auth)
        & ct::bool_to_choice(xy.was_contributory())
        & ct::bool_to_choice(xb.was_contributory());

    if okay.into() {
        Ok(keygen)
    } else {
        Err(Error::BadCircHandshakeAuth)
    }
}

#[cfg(test)]
fn client_handshake2_no_auth_check_obfs4<T>(
    msg: T,
    state: &NtorHandshakeState,
) -> Result<(NtorHkdfKeyGenerator, Authcode)>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());
    let their_pk_bytes: [u8; 32] = cur
        .extract()
        .map_err(|e| Error::from_bytes_err(e, "v3 ntor handshake"))?;
    let their_pk = PublicKey::from(their_pk_bytes);

    let xy = state.my_sk.diffie_hellman(&their_pk);
    let xb = state.my_sk.diffie_hellman(&state.relay_public.pk);

    ntor_derive(&xy, &xb, &state.relay_public, &state.my_public, &their_pk)
        .map_err(into_internal!("Error deriving keys"))
        .map_err(|e| Error::Bug(e))
}

/// helper: compute a key generator and an authentication code from a set
/// of ntor parameters.
///
/// These parameter names are as described in tor-spec.txt
fn ntor_derive(
    xy: &SharedSecret,
    xb: &SharedSecret,
    server_pk: &Obfs4NtorPublicKey,
    x: &PublicKey,
    y: &PublicKey,
) -> EncodeResult<(NtorHkdfKeyGenerator, Authcode)> {
    let server_string = &b"Server"[..];

    // obfs4 uses a different order than Ntor V1 and accidentally writes the
    // server's identity public key bytes twice.
    let mut suffix = SecretBuf::new();
    suffix.write(&server_pk.pk.as_bytes())?; // b
    suffix.write(&server_pk.pk.as_bytes())?; // b
    suffix.write(x.as_bytes())?;             // x
    suffix.write(y.as_bytes())?;             // y
    suffix.write(PROTO_ID)?;                 // PROTOID
    suffix.write(&server_pk.id)?;            // ID

    // secret_input = EXP(X,y) | EXP(X,b)   OR    = EXP(Y,x) | EXP(B,x)
    // ^ these are the equivalent x25519 shared secrets concatenated
    //
    // message = (secret_input) | b | b | x | y | PROTOID | ID
    let mut message = SecretBuf::new();
    message.write(xy.as_bytes())?; // EXP(X,y)
    message.write(xb.as_bytes())?; // EXP(X,b)
    message.write(&suffix[..])?;   // b | b | x | y | PROTOID | ID

    // verify = HMAC_SHA256(msg, T_VERIFY)
    let verify = {
        let mut m = Hmac::<Sha256>::new_from_slice(T_VERIFY).expect("Hmac allows keys of any size");
        m.update(&message[..]);
        m.finalize()
    };

    // auth_input = verify | (suffix) | "Server"
    // auth_input = verify | b | b | y | x | PROTOID | ID | "Server"
    //
    // Again obfs4 uses all of the same fields (with the servers identity public
    // key duplicated), but in a different order than Ntor V1.
    let mut auth_input = Vec::new();
    auth_input.write_and_consume(verify)?; // verify
    auth_input.write(&suffix[..])?;        // b | b | x | y | PROTOID | ID
    auth_input.write(server_string)?;      // "Server"

    // auth = HMAC_SHA256(auth_input, T_MAC)
    let auth_mac = {
        let mut m = Hmac::<Sha256>::new_from_slice(T_MAC).expect("Hmac allows keys of any size");
        m.update(&auth_input[..]);
        m.finalize()
    };

    // key_seed = HMAC_SHA256(message, T_KEY)
    let key_seed_bytes = {
        let mut m = Hmac::<Sha256>::new_from_slice(T_KEY).expect("Hmac allows keys of any size");
        m.update(&message[..]);
        m.finalize()
    };
    let mut key_seed = SecretBuf::new();
    key_seed.write_and_consume(key_seed_bytes)?;

    let keygen = NtorHkdfKeyGenerator::new(key_seed);
    Ok((keygen, auth_mac))
}

/// Perform a server-side ntor handshake.
///
/// On success returns a key generator and a server onionskin.
fn server_handshake_obfs4<R, T>(
    rng: &mut R,
    msg: T,
    keys: &[Obfs4NtorSecretKey],
) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    R: RngCore + CryptoRng,
    T: AsRef<[u8]>,
{
    // TODO(nickm): we generate this key whether or not we are
    // actually going to find our nodeid or keyid. Perhaps we should
    // delay that till later?  It shouldn't matter for most cases,
    // though.
    let ephem = EphemeralSecret::random_from_rng(rng);
    let ephem_pub = PublicKey::from(&ephem);

    server_handshake_obfs4_no_keygen(ephem_pub, ephem, msg, keys)
}

/// Helper: perform a server handshake without generating any new keys.
fn server_handshake_obfs4_no_keygen<T>(
    ephem_pub: PublicKey,
    ephem: EphemeralSecret,
    msg: T,
    keys: &[Obfs4NtorSecretKey],
) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
where
    T: AsRef<[u8]>,
{
    let mut cur = Reader::from_slice(msg.as_ref());

    let my_id: RsaIdentity = cur.extract()?;
    let my_key_bytes: [u8; 32] = cur.extract()?;
    let my_key = PublicKey::from(my_key_bytes);
    let their_pk_bytes: [u8; 32] = cur.extract()?;
    let their_pk = PublicKey::from(their_pk_bytes);

    let keypair = ct_lookup(keys, |key| key.matches_pk(&my_key));
    let keypair = match keypair {
        Some(k) => k,
        None => return Err(RelayHandshakeError::MissingKey),
    };

    if my_id != keypair.pk.id {
        return Err(RelayHandshakeError::MissingKey);
    }

    let xy = ephem.diffie_hellman(&their_pk);
    let xb = keypair.sk.diffie_hellman(&their_pk);

    let okay =
        ct::bool_to_choice(xy.was_contributory()) & ct::bool_to_choice(xb.was_contributory());

    let (keygen, authcode) = ntor_derive(&xy, &xb, &keypair.pk, &their_pk, &ephem_pub)
        .map_err(into_internal!("Error deriving keys"))?;

    let mut reply: Vec<u8> = Vec::new();
    reply
        .write(&ephem_pub.as_bytes())
        .and_then(|_| reply.write_and_consume(authcode))
        .map_err(into_internal!(
            "Generated relay handshake we couldn't encode"
        ))?;

    if okay.into() {
        Ok((keygen, reply))
    } else {
        Err(RelayHandshakeError::BadClientHandshake)
    }
}

#[cfg(test)]
mod integration;
