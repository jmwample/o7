use crate::{
    common::{
        ct,
        drbg::SEED_LENGTH,
        ntor_arti::{AuxDataReply, RelayHandshakeError, RelayHandshakeResult, ServerHandshake},
        utils::{find_mac_mark, get_epoch_hour},
    },
    constants::*,
    framing::{
        ClientHandshakeMessage, ClientStateIncoming, ClientStateOutgoing, ServerHandshakeMessage,
        ServerStateOutgoing,
    },
    handshake::*,
    Digest, Error, Result, Server,
};

use std::time::Instant;

// use cipher::KeyIvInit;
use digest::{Digest as _, ExtendableOutput as _, XofReader as _};
use hmac::{Mac, SimpleHmac};
use kem::{Decapsulate, Encapsulate};
use kemeleon::OKemCore;
use keys::NtorV3KeyGenerator;
use ptrs::{debug, trace};
use rand::Rng;
use rand_core::{CryptoRng, CryptoRngCore, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tor_bytes::{Reader, SecretBuf, Writer};
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_error::into_internal;
use tor_llcrypto::d::{Sha3_256, Shake256};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use typenum::Unsigned;
use zeroize::Zeroizing;

/// Server Materials needed for completing a handshake
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

impl<K: OKemCore, D: Digest> ServerHandshake for Server<K, D> {
    type HandshakeParams = SHSMaterials;
    type KeyGen = NtorV3KeyGenerator;
    type ClientAuxData = [NtorV3Extension];
    type ServerAuxData = Vec<NtorV3Extension>;

    fn server<REPLY: AuxDataReply<Self>, T: AsRef<[u8]>>(
        &self,
        reply_fn: &mut REPLY,
        materials: &Self::HandshakeParams, // TODO: do we need materials during server handshake?
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

        let (res, reader) =
            self.server_handshake_ntor_v3(&mut rng, &mut bytes_reply_fn, msg.as_ref(), materials)?;
        Ok((NtorV3KeyGenerator::new::<ServerRole>(reader), res))
    }
}

impl<K: OKemCore, D: Digest> Server<K, D> {
    const CLIENT_CT_SIZE: usize = CtSize::<K>::USIZE;
    const CLIENT_EK_SIZE: usize = EkSize::<K>::USIZE;

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
    pub(crate) fn server_handshake_ntor_v3(
        &self,
        rng: &mut impl CryptoRngCore,
        reply_fn: &mut impl MsgReply,
        message: impl AsRef<[u8]>,
        materials: &HandshakeMaterials,
    ) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
        self.server_handshake_ntor_v3_no_keygen(rng, reply_fn, message, materials)
    }

    /// As `server_handshake_ntor_v3`, but take a secret key instead of an RNG.
    pub(crate) fn server_handshake_ntor_v3_no_keygen(
        &self,
        rng: &mut impl CryptoRngCore,
        extension_handle: &mut impl MsgReply,
        message: impl AsRef<[u8]>,
        materials: &HandshakeMaterials,
    ) -> RelayHandshakeResult<(Vec<u8>, NtorV3XofReader)> {
        let msg = message.as_ref();
        if CLIENT_MIN_HANDSHAKE_LENGTH > msg.len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        let mut client_hs = match self.try_parse_client_handshake(msg, materials) {
            Ok(chs) => chs,
            Err(RelayHandshakeError::EAgain) => {
                return Err(RelayHandshakeError::EAgain);
            }
            Err(_e) => {
                debug!(
                    "{} failed to parse client handshake: {_e}",
                    materials.session_id
                );
                return Err(RelayHandshakeError::BadClientHandshake);
            }
        };

        debug!(
            "{} successfully parsed client handshake",
            materials.session_id
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
            c.write(&client_session_ek.as_bytes()[..])
                .and_then(|_| c.write(&message.as_ref()[..])) // TODO: We need less than the whole message
                .and_then(|_| c.write(Self::protocol_id()))
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

        // Handle extension messages and (optionally) craft a reply.
        let extensions_reply = extension_handle
            .reply(&client_hs.get_extensions())
            .unwrap_or_default();
        let encrypted_extension_reply = &encrypt::<D>(&session_key, &extensions_reply);

        let pad_len = rng.gen_range(SERVER_MIN_PAD_LENGTH..SERVER_MAX_PAD_LENGTH); // TODO - recalculate these

        let state_outgoing = ServerStateOutgoing::<D> {
            pad_len,
            epoch_hour: get_epoch_hour().to_string(),
            hs_materials: materials,
            encrypted_extension_reply,
            ephemeral_secret,
        };
        let server_hs_msg =
            ServerHandshakeMessage::<D, ServerStateOutgoing<D>>::new(auth, state_outgoing);

        // okay &= ct::bool_to_choice(reply.is_some());
        // let reply = reply.unwrap_or_default();

        // // If we reach this point, we are actually replying, or pretending
        // // that we're going to reply.

        // if okay.into() {
        //     Ok((reply, NtorV3XofReader::new(keystream)))
        // } else {
        //     Err(RelayHandshakeError::BadClientHandshake)
        // }
        todo!("construct & send server handshake");
    }

    pub(crate) fn complete_server_hs(
        &self,
        client_hs: &ClientHandshakeMessage<K, ClientStateIncoming<D>>,
        materials: &HandshakeMaterials,
        authcode: Authcode<D>,
    ) -> RelayHandshakeResult<Vec<u8>> {
        todo!("is this necessary?")
    }

    fn try_parse_client_handshake(
        &self,
        b: impl AsRef<[u8]>,
        materials: &HandshakeMaterials,
    ) -> RelayHandshakeResult<ClientHandshakeMessage<K, ClientStateIncoming<D>>> {
        let buf = b.as_ref();

        if CLIENT_MIN_HANDSHAKE_LENGTH > buf.len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        // chunk off the clients encapsulation key
        let mut client_ek_obfs = vec![0u8; Self::CLIENT_EK_SIZE];
        client_ek_obfs.copy_from_slice(&buf[0..Self::CLIENT_EK_SIZE]);

        // chunk off the ciphertext
        let mut client_ct_obfs = vec![0u8; Self::CLIENT_CT_SIZE];
        client_ct_obfs.copy_from_slice(
            &buf[Self::CLIENT_EK_SIZE..Self::CLIENT_EK_SIZE + Self::CLIENT_CT_SIZE],
        );

        // decode and decapsulate the secret encoded by the client
        let client_ct = <K as OKemCore>::Ciphertext::try_from_bytes(&client_ct_obfs)
            .map_err(|e| RelayHandshakeError::FailedParse)?;
        let shared_secret_1 = self
            .identity_keys
            .sk
            .decapsulate(&client_ct)
            .map_err(|e| RelayHandshakeError::FailedDecapsulation)?;

        let node_id = self.get_identity().id;
        let mut f2 = SimpleHmac::<D>::new_from_slice(node_id.as_bytes())
            .expect("keying server f2 hmac should never fail");

        // Compute the Ephemeral Secret
        let ephemeral_secret = {
            f2.update(&shared_secret_1.as_bytes()[..]);
            Zeroizing::new(f2.finalize_reset().into_bytes())
        };

        let mut f1_es = SimpleHmac::<Sha3_256>::new_from_slice(ephemeral_secret.as_ref())
            .expect("Keying server f1_es hmac should never fail");

        // derive the mark from the Ephemeral Secret
        let client_mark = {
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

        let min_position = Self::CLIENT_CT_SIZE + Self::CLIENT_EK_SIZE + CLIENT_MIN_PAD_LENGTH;

        // find mark + mac position
        let pos = match find_mac_mark(
            client_mark.into(),
            buf,
            min_position,
            MAX_HANDSHAKE_LENGTH,
            true,
        ) {
            Some(p) => p,
            None => {
                trace!("{} didn't find mark", materials.session_id);
                if buf.len() > MAX_HANDSHAKE_LENGTH {
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
            f1_es.update(&buf[..pos + MARK_LENGTH]);
            f1_es.update(eh.as_bytes());
            f1_es.update(CLIENT_MAC_ARG);
            let mac_calculated = &f1_es.finalize_reset().into_bytes()[..MAC_LENGTH];

            // check received mac
            let mac_received = &buf[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
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
        if buf.len() != pos + MARK_LENGTH + MAC_LENGTH {
            trace!("client sent extra data");
            Err(RelayHandshakeError::BadClientHandshake)?
        }

        // // pad_len doesn't matter when we are reading client handshake msg
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
