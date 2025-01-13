use crate::{
    common::{
        utils::get_epoch_hour, // make_hs_pad},
        HmacSha256,
    },
    handshake::{Authcode, CHSMaterials, AUTHCODE_LENGTH},
    sessions::SessionPublicKey,
    Result,
};

use block_buffer::Eager;
use bytes::BufMut;
use digest::{
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    HashMarker,
};
use hmac::{Hmac, Mac};
use ptrs::trace;
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_llcrypto::d::Sha3_256;
use typenum::{consts::U256, marker_traits::NonZero, operator_aliases::Le, type_operators::IsLess};

// -----------------------------[ Server ]-----------------------------

pub struct ServerHandshakeMessage {
    server_auth: [u8; AUTHCODE_LENGTH],
    pad_len: usize,
    session_pubkey: SessionPublicKey,
    epoch_hour: String,
    aux_data: Vec<NtorV3Extension>,
}

impl ServerHandshakeMessage {
    pub fn new(_client_pubkey: SessionPublicKey, _session_pubkey: SessionPublicKey) -> Self {
        todo!("SHS MSG - this should probably be built directly from the client HS MSG");
        // Self {
        //     server_auth: [0u8; AUTHCODE_LENGTH],
        //     pad_len: rand::thread_rng().gen_range(SERVER_MIN_PAD_LENGTH..SERVER_MAX_PAD_LENGTH),
        //     epoch_hour: epoch_hr,
        // }
    }

    pub fn with_pad_len(&mut self, pad_len: usize) -> &Self {
        self.pad_len = pad_len;
        self
    }

    pub fn with_aux_data(&mut self, aux_data: Vec<NtorV3Extension>) -> &Self {
        self.aux_data = aux_data;
        self
    }

    pub fn server_pubkey(&mut self) -> SessionPublicKey {
        self.session_pubkey.clone()
    }

    pub fn server_auth(self) -> Authcode {
        self.server_auth
    }

    pub fn marshall(&mut self, _buf: &mut impl BufMut, mut _h: HmacSha256) -> Result<()> {
        trace!("serializing server handshake");
        todo!("marshall server hello");

        // h.reset();
        // h.update(self.session_pubkey.as_bytes().as_ref());
        // let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // // The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
        // //  * Y is the server's ephemeral Curve25519 public key representative.
        // //  * AUTH is the ntor handshake AUTH value.
        // //  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
        // //  * M_S is HMAC-SHA256-128(serverIdentity | NodeID, Y)
        // //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, Y .... E)
        // //  * E is the string representation of the number of hours since the UNIX
        // //    epoch.

        // // Generate the padding
        // let pad: &[u8] = &make_hs_pad(self.pad_len)?;

        // // Write Y, AUTH, P_S, M_S.
        // let mut params = vec![];
        // params.extend_from_slice(self.session_pubkey.as_bytes());
        // params.extend_from_slice(&self.server_auth);
        // params.extend_from_slice(pad);
        // params.extend_from_slice(mark);
        // buf.put(params.as_slice());

        // // Calculate and write MAC
        // h.update(&params);
        // h.update(self.epoch_hour.as_bytes());
        // buf.put(&h.finalize_reset().into_bytes()[..MAC_LENGTH]);

        // Ok(())
    }
}

// -----------------------------[ Client ]-----------------------------

/// Preliminary message sent in an obfs4 handshake attempting to open a
/// connection from a client to a potential server.
pub struct ClientHandshakeMessage<'a> {
    hs_materials: &'a CHSMaterials,
    client_session_pubkey: SessionPublicKey,

    // only used when parsing (i.e. on the server side)
    pub(crate) epoch_hour: String,
}

impl<'a> ClientHandshakeMessage<'a> {
    pub(crate) fn new(
        client_session_pubkey: SessionPublicKey,
        hs_materials: &'a CHSMaterials,
    ) -> Self {
        Self {
            hs_materials,
            client_session_pubkey,

            // only used when parsing (i.e. on the server side)
            epoch_hour: get_epoch_hour().to_string(),
        }
    }

    pub fn get_public(&mut self) -> SessionPublicKey {
        // trace!("repr: {}", hex::encode(self.client_session_pubkey.id);
        self.client_session_pubkey.clone()
    }

    /// return the epoch hour used in the ntor handshake.
    pub fn get_epoch_hr(&self) -> String {
        self.epoch_hour.clone()
    }

    pub fn marshall(&mut self, buf: &mut impl BufMut, key: &[u8]) -> Result<()> {
        trace!("serializing client handshake");

        let h = Hmac::<Sha3_256>::new_from_slice(key).unwrap();

        self.marshall_inner(buf, h)
    }

    pub fn marshall_inner<D>(&mut self, _buf: &mut impl BufMut, _h: Hmac<D>) -> Result<()>
    where
        D: CoreProxy,
        D::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        todo!("when this is causing panic re-visit");
        // NtorV3Extension::write_many_onto(client_aux_data.borrow(), &mut message)
        //     .map_err(|e| Error::from_bytes_enc(e, "ntor3 handshake extensions"))?;

        // h.reset(); // disambiguate reset() implementations Mac v digest
        // h.update(self.repres.as_bytes().as_ref());
        // let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // // The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
        // //  * X is the client's ephemeral Curve25519 public key representative.
        // //  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
        // //  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
        // //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
        // //  * E is the string representation of the number of hours since the UNIX
        // //    epoch.

        // // Generate the padding
        // let pad = make_hs_pad(self.pad_len)?;

        // // Write X, P_C, M_C
        // let mut params = vec![];
        // params.extend_from_slice(self.repres.as_bytes());
        // params.extend_from_slice(&pad);
        // params.extend_from_slice(mark);
        // buf.put(params.as_slice());

        // // Calculate and write MAC
        // h.update(&params);
        // self.epoch_hour = format!("{}", get_epoch_hour());
        // h.update(self.epoch_hour.as_bytes());
        // let mac = &h.finalize_reset().into_bytes()[..MARK_LENGTH];
        // buf.put(mac);

        // trace!("mark: {}, mac: {}", hex::encode(mark), hex::encode(mac));

        // Ok(())
    }
}
