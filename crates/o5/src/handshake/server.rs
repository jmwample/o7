use crate::{
    common::{
        ct,
        drbg::SEED_LENGTH,
        ntor_arti::{self, AuxDataReply, RelayHandshakeError, RelayHandshakeResult},
        utils::{find_mac_mark, get_epoch_hour},
    },
    constants::*,
    handshake::client::NtorV3Client as Client,
    handshake::*,
    msgs::handshake::{
        ClientHandshakeMessage, ClientStateIncoming, ClientStateOutgoing, ServerHandshakeMessage,
        ServerStateOutgoing,
    },
    traits::{DigestSizes, FramingSizes, OKemCore},
    Digest, Error, Result, Server,
};

use std::time::Instant;

use bytes::BufMut;
use digest::{Digest as _, ExtendableOutput as _};
use hmac::{Mac, SimpleHmac};
use kem::{Decapsulate, Encapsulate};
use keys::NtorV3KeyGenerator;
use ptrs::{debug, trace};
use rand::Rng;
use rand_core::{CryptoRng, CryptoRngCore, RngCore};
use sha3::Shake256;
use subtle::ConstantTimeEq;
use tor_bytes::{Reader, SecretBuf, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_error::into_internal;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use typenum::Unsigned;
use zeroize::Zeroizing;

/// Server Materials needed for completing a handshake
#[derive(Clone, Debug)]
pub(crate) struct HandshakeMaterials {
    pub(crate) session_id: String,
    pub(crate) len_seed: [u8; SEED_LENGTH],
}

impl HandshakeMaterials {
    pub fn new(session_id: String, len_seed: [u8; SEED_LENGTH]) -> Self {
        HandshakeMaterials {
            session_id,
            len_seed,
        }
    }
}

pub(crate) struct ServerHandshake<K: OKemCore, D: Digest> {
    pub(crate) materials: HandshakeMaterials,
    pub(crate) server: Server<K, D>,
}

impl<K: OKemCore, D: Digest> ServerHandshake<K, D> {
    pub(crate) fn new(server: Server<K, D>, materials: HandshakeMaterials) -> Self {
        Self {
            materials,
            server: server.clone(),
        }
    }
}

impl<K: OKemCore, D: Digest> ntor_arti::ServerHandshake for ServerHandshake<K, D> {
    type KeyGen = NtorV3KeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    fn server<REPLY: AuxDataReply<Self>, T: AsRef<[u8]>, Out: BufMut>(
        &self,
        reply_fn: &mut REPLY,
        msg: T,
        reply_buf: &mut Out,
    ) -> RelayHandshakeResult<Self::KeyGen> {
        let mut bytes_reply_fn = |bytes: &[u8]| -> Option<Vec<u8>> {
            let client_exts = NtorV3Extension::decode(bytes).ok()?;
            let reply_exts = reply_fn.reply(&client_exts)?;
            let mut out = vec![];
            NtorV3Extension::write_many_onto(&reply_exts, &mut out).ok()?;
            Some(out)
        };
        let mut rng = rand::thread_rng();

        let (response, reader) =
            self.handshake_ntor_v3(&mut rng, &mut bytes_reply_fn, msg.as_ref())?;

        response.marshall(&mut rng, reply_buf);

        Ok(NtorV3KeyGenerator::new::<ServerRole>(reader))
    }
}

impl<K: OKemCore, D: Digest> ServerHandshake<K, D> {
    /// Complete an ntor v3 handshake as a server.
    ///
    ///    shared_secret_1 = Decapsulate(DKs, ct)
    ///
    ///    CTs, shared_secret_2 = Encapsulate(EKc)
    ///
    ///    ES = F2(NodeID, shared_secret_1)
    ///    ES' = F1(ES, ":derive_key")
    ///    FS = F2(ES', shared_secret_2)
    ///    context = CTco | EKco | EKso | CTso
    ///
    ///    SESSION_KEY = F1(FS, context | PROTOID | ":key_extract")
    ///
    /// On success, return the server handshake message to send, and the session keys
    pub(crate) fn handshake_ntor_v3<'a>(
        &self,
        rng: &mut impl CryptoRngCore,
        reply_fn: &mut impl MsgReply,
        message: &'a [u8],
    ) -> RelayHandshakeResult<(
        ServerHandshakeMessage<K, D, ServerStateOutgoing<D>>,
        NtorV3XofReader,
    )> {
        self.handshake_ntor_v3_no_keygen(rng, reply_fn, message)
    }

    /// As `server_handshake_ntor_v3`, but take a secret key instead of an RNG.
    pub(crate) fn handshake_ntor_v3_no_keygen<'a>(
        &self,
        rng: &mut impl CryptoRngCore,
        extension_handle: &mut impl MsgReply,
        msg: &'a [u8],
    ) -> RelayHandshakeResult<(
        ServerHandshakeMessage<K, D, ServerStateOutgoing<D>>,
        NtorV3XofReader,
    )> {
        // let msg = message.as_ref();
        if Client::<K, D>::CLIENT_MIN_HANDSHAKE_LENGTH > msg.len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        let mut client_hs = match self.try_parse_client_handshake(msg, &self.materials) {
            Ok(chs) => chs,
            Err(RelayHandshakeError::EAgain) => {
                return Err(RelayHandshakeError::EAgain);
            }
            Err(_e) => {
                debug!(
                    "{} failed to parse client handshake: {_e}",
                    self.materials.session_id
                );
                return Err(RelayHandshakeError::BadClientHandshake);
            }
        };

        debug!(
            "{} successfully parsed client handshake",
            self.materials.session_id
        );
        let client_session_ek = client_hs.get_public();
        let ephemeral_secret = client_hs.get_ephemeral_secret();

        // Create the server side KEM challenge.
        let (ciphertext, shared_secret_2) = client_session_ek
            .encapsulate(rng)
            .map_err(|_| RelayHandshakeError::FailedEncapsulation)?;

        let mut f1_es = SimpleHmac::<D>::new_from_slice(ephemeral_secret.as_ref())
            .expect("keying hmac should never fail");

        // compute the Session Ephemeral Secret
        let derivation_ephemeral = {
            f1_es.reset();
            f1_es.update(&KEY_DERIVE_ARG);
            f1_es.finalize_reset().into_bytes()
        };

        let mut f2 = SimpleHmac::<D>::new_from_slice(derivation_ephemeral.as_ref())
            .expect("keying hmac should never fail");

        // compute our Combiner Ephemeral Secret
        let combiner_ephemeral = {
            f2.reset();
            f2.update(&shared_secret_2.as_bytes()[..]);
            Zeroizing::new(f2.finalize_reset().into_bytes())
        };

        // Handshake context = EKco || CTco || EKso || CTso || protocol_id
        let mut context = {
            let mut c = SecretBuf::new();
            c.write(&msg[K::EK_SIZE..K::EK_SIZE + K::CT_SIZE]) // EKco || CTco from client handshake
                .and_then(|_| c.write(&self.server.get_identity().ek.as_bytes()[..])) // EKso server identity key
                .and_then(|_| c.write(&ciphertext.as_bytes()[..])) // CTso server created ciphertext
                .and_then(|_| c.write(Server::<K, D>::protocol_id().as_bytes())) // protocol ID
                .map_err(|_| {
                    RelayHandshakeError::FrameError("failed to wire reply context".into())
                })?;
            c
        };

        let mut f1_fs = SimpleHmac::<D>::new_from_slice(combiner_ephemeral.as_ref())
            .expect("keying hmac should never fail");

        // Compute the Session Key value used to key our cipher.
        let session_key = {
            f1_fs.reset();
            f1_fs.update(&context[..]);
            f1_fs.update(KEY_EXTRACT_ARG);
            Zeroizing::new(f1_fs.finalize_reset().into_bytes())
        };

        // Compute the Server message authentication value
        let auth = {
            f1_fs.reset();
            f1_fs.update(&context[..]);
            f1_fs.update(SERVER_AUTH_ARG);
            f1_fs.finalize_reset().into_bytes()
        };

        let (enc_key, keystream) = {
            use digest::{ExtendableOutput, Update, XofReader};
            let mut xof = Shake256::default();
            xof.update(&T_FINAL);
            xof.update(&session_key);
            let mut r = xof.finalize_xof();
            let mut enc_key = SessionSharedSecret::<D>::default();
            r.read(&mut enc_key[..]);
            (enc_key, r)
        };

        // Handle extension messages and (optionally) craft a reply.
        let extensions_reply = extension_handle
            .reply(&client_hs.get_extensions())
            .unwrap_or_default();

        let pad_len = rng.gen_range(MIN_PAD_LENGTH..Server::<K, D>::SERVER_MAX_PAD_LENGTH); // TODO - recalculate these

        let state_outgoing = ServerStateOutgoing::<D> {
            pad_len,
            encrypted_extension_reply: encrypt::<D>(&enc_key, &extensions_reply),
            ephemeral_secret,
            hs_materials: &self.materials,
        };
        let server_hs_msg = ServerHandshakeMessage::<K, D, ServerStateOutgoing<D>>::new(
            ciphertext,
            auth,
            state_outgoing,
        );

        Ok((server_hs_msg, NtorV3XofReader::new(keystream)))

        // todo!("Add extensions and prng seed to the server hello");
    }

    fn try_parse_client_handshake(
        &self,
        b: impl AsRef<[u8]>,
        materials: &HandshakeMaterials,
    ) -> RelayHandshakeResult<ClientHandshakeMessage<K, ClientStateIncoming<D>>> {
        let buf = b.as_ref();

        if Client::<K, D>::CLIENT_MIN_HANDSHAKE_LENGTH > buf.len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        let server_identity_key = &self.server.identity_keys.sk;
        trace!(
            "id pubkey: {}",
            hex::encode(&self.server.identity_keys.pk.ek.as_bytes()[..])
        );

        // get the chunk containing the clients encapsulation key
        let mut client_ek_obfs = &buf[0..K::EK_SIZE];

        // get the chunk containing the ciphertext
        let mut client_ct_obfs = &buf[K::EK_SIZE..K::EK_SIZE + K::CT_SIZE];

        // decode and decapsulate the secret encoded by the client
        let client_ct = <K as kemeleon::OKemCore>::Ciphertext::try_from_bytes(&client_ct_obfs)
            .map_err(|e| RelayHandshakeError::FailedParse)?;
        let shared_secret = server_identity_key
            .decapsulate(&client_ct)
            .map_err(|e| RelayHandshakeError::FailedDecapsulation)?;
        let shared_secret = &shared_secret.as_bytes()[..];

        let node_id = self.server.get_identity().id;
        let mut f2 = SimpleHmac::<D>::new_from_slice(node_id.as_bytes())
            .expect("keying server f2 hmac should never fail");

        // Compute the Ephemeral Secret
        let ephemeral_secret = {
            f2.reset();
            f2.update(shared_secret);
            Zeroizing::new(f2.finalize_reset().into_bytes())
        };

        trace!("shared secret: {}", hex::encode(shared_secret));

        let mut f1_es = SimpleHmac::<Sha3_256>::new_from_slice(ephemeral_secret.as_ref())
            .expect("Keying server f1_es hmac should never fail");

        // derive the mark from the Ephemeral Secret
        let client_mark = {
            f1_es.reset();
            f1_es.update(&client_ek_obfs);
            f1_es.update(&client_ct_obfs);
            f1_es.update(CLIENT_MARK_ARG);
            f1_es.finalize_reset().into_bytes()
        };

        trace!(
            "{} mark?:{}",
            materials.session_id,
            hex::encode(client_mark)
        );

        let min_position = K::CT_SIZE + K::EK_SIZE + MIN_PAD_LENGTH;

        // find mark + mac position
        let pos = match find_mac_mark::<D>(client_mark, buf, min_position, MAX_PACKET_LENGTH, true)
        {
            Some(p) => p,
            None => {
                trace!("{} didn't find mark", materials.session_id);
                if buf.len() > MAX_PACKET_LENGTH {
                    Err(RelayHandshakeError::BadClientHandshake)?
                }
                Err(RelayHandshakeError::EAgain)?
            }
        };

        // validate he MAC
        let mut mac_found = false;
        let mut epoch_hour = String::new();
        for offset in [0_i64, -1, 1] {
            // Allow the epoch to be off by up to one hour in either direction
            trace!("server trying offset: {offset}");
            let eh = format!("{}", offset + get_epoch_hour() as i64);

            // compute the expected MAC (if the epoch hour is within the valid range)
            f1_es.reset();
            f1_es.update(&buf[..pos + D::MARK_SIZE]);
            f1_es.update(eh.as_bytes());
            f1_es.update(CLIENT_MAC_ARG);
            let mac_calculated = &f1_es.finalize_reset().into_bytes()[..D::MAC_SIZE];

            // check received mac
            let mac_received = &buf[pos + D::MARK_SIZE..pos + D::MARK_SIZE + D::MAC_SIZE];
            trace!(
                "server {}-{}",
                hex::encode(mac_calculated),
                hex::encode(mac_received)
            );

            // // make sure that the clients mac matches and that both x25519 keys contributed (i.e. neither was 0)
            // let mut okay = computed_mac.ct_eq(&msg_mac)
            //     & ct::bool_to_choice(xy.was_contributory())
            //     & ct::bool_to_choice(xb.was_contributory());

            if mac_calculated.ct_eq(mac_received).into() {
                trace!("correct mac");
                // Ensure that this handshake has not been seen previously.
                if self
                    .server
                    .replay_filter
                    .test_and_set(Instant::now(), mac_received)
                {
                    // The client either happened to generate exactly the same
                    // session key and padding, or someone is replaying a previous
                    // handshake.  In either case, fuck them.
                    Err(RelayHandshakeError::ReplayedHandshake)?
                }

                epoch_hour = eh;
                mac_found = true;

                // We break here, but if this creates some kind of timing channel
                // (not sure exactly what that would be) we could reduce timing variance by
                // just evaluating all three MACs. Probably not necessary
                break;
            }
        }

        if !mac_found {
            // This could be a [`RelayHandshakeError::TagMismatch`] :shrug:
            trace!("Matching MAC not found");
            Err(RelayHandshakeError::BadClientHandshake)?
        }

        // client should never send any appended padding at the end.
        if buf.len() != pos + D::MARK_SIZE + D::MAC_SIZE {
            trace!("client sent extra data");
            Err(RelayHandshakeError::BadClientHandshake)?
        }

        let client_ephemeral_ek = EphemeralPub::<K>::try_from_bytes(client_ek_obfs)
            .map_err(|_| RelayHandshakeError::FailedParse)?;
        Ok(ClientHandshakeMessage::<K, ClientStateIncoming<D>>::new(
            client_ephemeral_ek,
            ClientStateIncoming::new(ephemeral_secret),
            Some(epoch_hour),
        ))

        // Is it important that the context for the auth HMAC uses the non obfuscated encoding of the
        // ciphertext sent by the client (ciphertext created using the server's identity encapsulation
        // key) as opposed to the obfuscated encoding?
        //
        // No this should not impact things.

        // -----------------------------------[NTor V3]-------------------------------
        // // TODO: Maybe use the Reader / Ntor interface, it is nice and clean.
        // // Decode the message.

        // let mut r = Reader::from_slice(message);
        // let id: Ed25519Identity = r.extract()?;
        // let requested_pk: IdentityPublicKey<K> = r.extract()?;
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
    }
}
