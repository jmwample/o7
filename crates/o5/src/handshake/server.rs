use crate::{
    common::{
        ct,
        drbg::SEED_LENGTH,
        ntor_arti::{AuxDataReply, RelayHandshakeError, RelayHandshakeResult, ServerHandshake},
    },
    handshake::*,
    sessions::SessionSecretKey,
    Error, Server,
};

// use cipher::KeyIvInit;
use digest::{Digest, ExtendableOutput, XofReader};
use hmac::{Hmac, Mac};
use keys::NtorV3KeyGenerator;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tor_bytes::{Reader, SecretBuf, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_error::into_internal;
use tor_llcrypto::d::{Sha3_256, Shake256};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use zeroize::Zeroizing;

/// Server Materials needed for completing a handshake
pub(crate) struct HandshakeMaterials {
    pub(crate) session_id: String,
    pub(crate) len_seed: [u8; SEED_LENGTH],
}

impl<'a> HandshakeMaterials {
    pub fn get_hmac<'b>(&self, identity_keys: &'b IdentitySecretKey) -> Hmac<Sha256> {
        let mut key = identity_keys.pk.ek.as_bytes().to_vec();
        key.append(&mut identity_keys.pk.id.as_bytes().to_vec());
        Hmac::<Sha256>::new_from_slice(&key[..]).unwrap()
    }

    pub fn new<'b>(session_id: String, len_seed: [u8; SEED_LENGTH]) -> Self
    where
        'b: 'a,
    {
        HandshakeMaterials {
            session_id,
            len_seed,
        }
    }
}

impl ServerHandshake for Server {
    type HandshakeParams = SHSMaterials;
    type KeyGen = NtorV3KeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    fn server<REPLY: AuxDataReply<Self>, T: AsRef<[u8]>>(
        &self,
        reply_fn: &mut REPLY,
        _materials: &Self::HandshakeParams, // TODO: do we need materials during server handshake?
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)> {
        let mut bytes_reply_fn = |bytes: &[u8]| -> Option<Vec<u8>> {
            let client_exts = NtorV3Extension::decode(bytes).ok()?;
            let reply_exts = reply_fn.reply(&client_exts)?;
            let mut out = vec![];
            NtorV3Extension::write_many_onto(&reply_exts, &mut out).ok()?;
            Some(out)
        };
        let mut rng = rand::thread_rng();

        let (res, reader) = server_handshake_ntor_v3(
            &mut rng,
            &mut bytes_reply_fn,
            msg.as_ref(),
            &self.identity_keys,
            NTOR3_CIRC_VERIFICATION,
        )?;
        Ok((NtorV3KeyGenerator::new::<ServerRole>(reader), res))
    }
}

/// Complete an ntor v3 handshake as a server.
///
/// Use the provided `rng` to generate keys; use the provided
/// `reply_fn` to handle incoming client secret message and decide how
/// to reply.  The client's handshake is in `message`.  Our private
/// key(s) are in `keys`.  The `verification` string must match the
/// string provided by the client.
///
/// On success, return the server handshake message to send, and an XofReader
/// to use in generating circuit keys.
pub(crate) fn server_handshake_ntor_v3<R: CryptoRng + RngCore, REPLY: MsgReply>(
    rng: &mut R,
    reply_fn: &mut REPLY,
    message: &[u8],
    keys: &IdentitySecretKey,
    verification: &[u8],
) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
    let (dk_session, _ek_session) = xwing::generate_key_pair(rng);
    server_handshake_ntor_v3_no_keygen(rng, reply_fn, &dk_session, message, keys, verification)
}

/// As `server_handshake_ntor_v3`, but take a secret key instead of an RNG.
pub(crate) fn server_handshake_ntor_v3_no_keygen<R: CryptoRng + RngCore, REPLY: MsgReply>(
    rng: &mut R,
    reply_fn: &mut REPLY,
    secret_key_y: &SessionSecretKey,
    message: &[u8],
    keys: &IdentitySecretKey,
    verification: &[u8],
) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
    todo!("server handshake");

    // // Decode the message.
    // let mut r = Reader::from_slice(message);
    // let id: Ed25519Identity = r.extract()?;
    // let requested_pk: IdentityPublicKey = r.extract()?;
    // let client_pk: SessionPublicKey = r.extract()?;
    // let client_msg = if let Some(msg_len) = r.remaining().checked_sub(MAC_LEN) {
    //     r.take(msg_len)?
    // } else {
    //     let deficit = (MAC_LEN - r.remaining())
    //         .try_into()
    //         .expect("miscalculated!");
    //     return Err(Error::incomplete_error(deficit).into());
    // };

    // let msg_mac: MessageMac = r.extract()?;
    // r.should_be_exhausted()?;

    // // See if we recognize the provided (id,requested_pk) pair.
    // let keypair = match keys.matches(id, requested_pk.pk).into() {
    //     Some(k) => keys,
    //     None => return Err(RelayHandshakeError::MissingKey),
    // };

    // let xb = keypair
    //     .hpke(rng, &client_pk)
    //     .map_err(|e| Error::Crypto(e.into()))?;
    // let (enc_key, mut mac) = kdf_msgkdf(&xb, &keypair.pk, &client_pk, verification)
    //     .map_err(into_internal!("Can't apply ntor3 kdf."))?;
    // // Verify the message we received.
    // let computed_mac: DigestVal = {
    //     mac.write(client_msg)
    //         .map_err(into_internal!("Can't compute MAC input."))?;
    //     mac.take().finalize().into()
    // };
    // let y_pk = SessionPublicKey::from(secret_key_y);
    // let xy = secret_key_y.hpke(rng, &client_pk)?;

    // let mut okay = computed_mac.ct_eq(&msg_mac)
    //     & ct::bool_to_choice(xy.was_contributory())
    //     & ct::bool_to_choice(xb.was_contributory());

    // let plaintext_msg = decrypt(&enc_key, client_msg);

    // // Handle the message and decide how to reply.
    // let reply = reply_fn.reply(&plaintext_msg);

    // // It's not exactly constant time to use is_some() and
    // // unwrap_or_else() here, but that should be somewhat
    // // hidden by the rest of the computation.
    // okay &= ct::bool_to_choice(reply.is_some());
    // let reply = reply.unwrap_or_default();

    // // If we reach this point, we are actually replying, or pretending
    // // that we're going to reply.

    // let secret_input = {
    //     let mut si = SecretBuf::new();
    //     si.write(&xy.as_bytes())
    //         .and_then(|_| si.write(&xb.as_bytes()))
    //         .and_then(|_| si.write(&keypair.pk.id))
    //         .and_then(|_| si.write(&keypair.pk.pk.as_bytes()))
    //         .and_then(|_| si.write(&client_pk.as_bytes()))
    //         .and_then(|_| si.write(&y_pk.as_bytes()))
    //         .and_then(|_| si.write(PROTOID))
    //         .and_then(|_| si.write(&Encap(verification)))
    //         .map_err(into_internal!("can't derive ntor3 secret_input"))?;
    //     si
    // };
    // let ntor_key_seed = h_key_seed(&secret_input);
    // let verify = h_verify(&secret_input);

    // let (enc_key, keystream) = {
    //     let mut xof = DigestWriter(Shake256::default());
    //     xof.write(&T_FINAL)
    //         .and_then(|_| xof.write(&ntor_key_seed))
    //         .map_err(into_internal!("can't generate ntor3 xof."))?;
    //     let mut r = xof.take().finalize_xof();
    //     let mut enc_key = Zeroizing::new([0_u8; ENC_KEY_LEN]);
    //     r.read(&mut enc_key[..]);
    //     (enc_key, r)
    // };
    // let encrypted_reply = encrypt(&enc_key, &reply);
    // let auth: DigestVal = {
    //     let mut auth = DigestWriter(Sha3_256::default());
    //     auth.write(&T_AUTH)
    //         .and_then(|_| auth.write(&verify))
    //         .and_then(|_| auth.write(&keypair.pk.id))
    //         .and_then(|_| auth.write(&keypair.pk.pk.as_bytes()))
    //         .and_then(|_| auth.write(&y_pk.as_bytes()))
    //         .and_then(|_| auth.write(&client_pk.as_bytes()))
    //         .and_then(|_| auth.write(&msg_mac))
    //         .and_then(|_| auth.write(&Encap(&encrypted_reply)))
    //         .and_then(|_| auth.write(PROTOID))
    //         .and_then(|_| auth.write(&b"Server"[..]))
    //         .map_err(into_internal!("can't derive ntor3 authentication"))?;
    //     auth.take().finalize().into()
    // };

    // let reply = {
    //     let mut reply = Vec::new();
    //     reply
    //         .write(&y_pk.as_bytes())
    //         .and_then(|_| reply.write(&auth))
    //         .and_then(|_| reply.write(&encrypted_reply))
    //         .map_err(into_internal!("can't encode ntor3 reply."))?;
    //     reply
    // };

    // if okay.into() {
    //     Ok((reply, NtorV3XofReader::new(keystream)))
    // } else {
    //     Err(RelayHandshakeError::BadClientHandshake)
    // }
}
