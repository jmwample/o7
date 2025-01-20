use crate::{
    common::{
        drbg,
        probdist::{self, WeightedDist},
    },
    constants::*,
    framing::{self, FrameError, O5Codec},
    msgs::{InvalidMessage, Messages},
    sessions::Session,
    traits::OKemCore,
    Result,
};

use bytes::{Buf, BytesMut};
use futures::{Sink, Stream};
use pin_project::pin_project;
use ptrs::trace;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant};
use tokio_util::codec::Framed;

use std::{
    io::Error as IoError,
    pin::Pin,
    result::Result as StdResult,
    task::{Context, Poll},
};

#[derive(Debug, Clone)]
pub(crate) enum MaybeTimeout {
    Default_,
    Fixed(Instant),
    Length(Duration),
    Unset,
}

impl MaybeTimeout {
    pub(crate) fn duration(&self) -> Option<Duration> {
        match self {
            MaybeTimeout::Default_ => Some(CLIENT_HANDSHAKE_TIMEOUT),
            MaybeTimeout::Fixed(i) => {
                if *i < Instant::now() {
                    None
                } else {
                    Some(*i - Instant::now())
                }
            }
            MaybeTimeout::Length(d) => Some(*d),
            MaybeTimeout::Unset => None,
        }
    }
}

#[pin_project]
/// AsyncReadable and AsyncWritable Obfuscated stream
///
/// Writing in plaintext gets turned into obfuscated bytes and reading obfuscated
/// ciphertext results in decrypted planitext.
///
/// TODO: this needs significantly more documentation
pub struct O5Stream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    // s: Arc<Mutex<O4Stream<'a, T>>>,
    #[pin]
    s: ObfuscatedStream<T, K>,
}

impl<T, K> O5Stream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    pub(crate) fn from_o5(os: ObfuscatedStream<T, K>) -> Self {
        O5Stream {
            // s: Arc::new(Mutex::new(o4)),
            s: os,
        }
    }
}

#[pin_project]
pub(crate) struct ObfuscatedStream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    #[pin]
    pub stream: Framed<T, O5Codec>,

    pub length_dist: probdist::WeightedDist,
    pub ipt_dist: probdist::WeightedDist,

    pub session: Session<K>,
}

impl<T, K> ObfuscatedStream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    pub(crate) fn new(
        // inner: &'a mut dyn Stream<'a>,
        inner: T,
        codec: O5Codec,
        session: Session<K>,
    ) -> Self {
        let stream = Framed::new(inner, codec);
        let len_seed = session.len_seed();

        let mut hasher = Sha256::new();
        hasher.update(len_seed.as_bytes());
        // the result of a sha256 haash is 32 bytes (256 bits) so we will
        // always have enough for a seed here.
        let ipt_seed = drbg::Seed::try_from(&hasher.finalize()[..SEED_LENGTH]).unwrap();

        let length_dist =
            WeightedDist::new(len_seed, 0, MAX_SEGMENT_LENGTH as i32, session.biased());
        let ipt_dist = WeightedDist::new(ipt_seed, 0, MAX_SEGMENT_LENGTH as i32, session.biased());

        Self {
            stream,
            session,
            length_dist,
            ipt_dist,
        }
    }

    pub(crate) fn try_handle_non_payload_message(&mut self, msg: Messages) -> Result<()> {
        match msg {
            Messages::RawPayload(_) => Err(InvalidMessage::InvalidContext.into()),
            Messages::Padding(_) => Ok(()),

            // TODO: Handle other Messages
            _ => Ok(()),
        }
    }

    /*// TODO Apply pad_burst logic and Inter-packet timing policy to packet assembly (probably as part of AsyncRead / AsyncWrite impl)
    /// Attempts to pad a burst of data so that the last packet is of the length
    /// `to_pad_to`. This can involve creating multiple packets, making this
    /// slightly complex.
    ///
    /// TODO: document logic more clearly
    pub(crate) fn pad_burst(&self, buf: &mut BytesMut, to_pad_to: usize) -> Result<()> {
        let tail_len = buf.len() % MAX_SEGMENT_LENGTH;

        let pad_len: usize = if to_pad_to >= tail_len {
            to_pad_to - tail_len
        } else {
            (MAX_SEGMENT_LENGTH - tail_len) + to_pad_to
        };

        if pad_len > HEADER_LENGTH {
            // pad_len > 19
            Ok(build_and_marshall(
                buf,
                MessageTypes::RawPayload.into(),
                vec![],
                pad_len - HEADER_LENGTH,
            )?)
        } else if pad_len > 0 {
            build_and_marshall(
                buf,
                MessageTypes::RawPayload.into(),
                vec![],
                MAX_MESSAGE_PAYLOAD_LENGTH,
            )?;
            // } else {
            Ok(build_and_marshall(
                buf,
                MessageTypes::RawPayload.into(),
                vec![],
                pad_len,
            )?)
        } else {
            Ok(())
        }
    } */
}

impl<T, K> AsyncWrite for ObfuscatedStream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        let msg_len = buf.remaining();
        let mut this = self.as_mut().project();

        // determine if the stream is ready to send an event?
        if futures::Sink::<&[u8]>::poll_ready(this.stream.as_mut(), cx).is_pending() {
            return Poll::Pending;
        }

        // while we have bytes in the buffer write MAX_MESSAGE_PAYLOAD_LENGTH
        // chunks until we have less than that amount left.
        // TODO: asyncwrite - apply length_dist instead of just full payloads
        let mut len_sent: usize = 0;
        let mut out_buf = BytesMut::with_capacity(MAX_MESSAGE_PAYLOAD_LENGTH);
        while msg_len - len_sent > MAX_MESSAGE_PAYLOAD_LENGTH {
            // package one chunk of the mesage as a payload
            let payload =
                Messages::RawPayload(buf[len_sent..len_sent + MAX_MESSAGE_PAYLOAD_LENGTH].to_vec());

            // send the marshalled payload
            payload.marshall(&mut out_buf)?;
            this.stream.as_mut().start_send(&mut out_buf)?;

            len_sent += MAX_MESSAGE_PAYLOAD_LENGTH;
            out_buf.clear();

            // determine if the stream is ready to send more data. if not back off
            if futures::Sink::<&[u8]>::poll_ready(this.stream.as_mut(), cx).is_pending() {
                return Poll::Ready(Ok(len_sent));
            }
        }

        let payload = Messages::RawPayload(buf[len_sent..].to_vec());

        let mut out_buf = BytesMut::new();
        payload.marshall(&mut out_buf)?;
        this.stream.as_mut().start_send(out_buf)?;

        Poll::Ready(Ok(msg_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} flushing", self.session.id());
        let mut this = self.project();
        match futures::Sink::<&[u8]>::poll_flush(this.stream.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} shutting down", self.session.id());
        let mut this = self.project();
        match futures::Sink::<&[u8]>::poll_close(this.stream.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T, K> AsyncRead for ObfuscatedStream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        // If there is no payload from the previous Read() calls, consume data off
        // the network.  Not all data received is guaranteed to be usable payload,
        // so do this in a loop until we would block on a read or an error occurs.
        loop {
            let msg = {
                // mutable borrow of self is dropped at the end of this block
                let mut this = self.as_mut().project();
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(res) => {
                        // TODO: when would this be None?
                        // It seems like this maybe happens when reading an EOF
                        // or reading from a closed connection
                        if res.is_none() {
                            return Poll::Ready(Ok(()));
                        }

                        match res.unwrap() {
                            Ok(m) => m,
                            Err(e) => Err(e)?,
                        }
                    }
                }
            };

            if let Messages::RawPayload(message) = msg {
                buf.put_slice(&message);
                return Poll::Ready(Ok(()));
            }
            if let Messages::Padding(_) = msg {
                continue;
            }

            match self.as_mut().try_handle_non_payload_message(msg) {
                Ok(_) => continue,
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
    }
}

impl<T, K> AsyncWrite for O5Stream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        let this = self.project();
        this.s.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_shutdown(cx)
    }
}

impl<T, K> AsyncRead for O5Stream<T, K>
where
    T: AsyncRead + AsyncWrite + Unpin,
    K: OKemCore,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_read(cx, buf)
    }
}
