#![allow(dead_code)]

mod fake_prng;
pub(crate) mod test_keys;
pub mod tests;
pub(crate) use fake_prng::*;

use std::env;
use std::io::{Read, Result, Write};
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::sync::Once;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream as AsyncUnixStream;
use tracing_subscriber::filter::LevelFilter;

static SUBSCRIBER_INIT: Once = Once::new();

pub fn init_subscriber() {
    SUBSCRIBER_INIT.call_once(|| {
        let level = env::var("RUST_LOG_LEVEL").unwrap_or("error".into());
        let lf = LevelFilter::from_str(&level).unwrap();

        tracing_subscriber::fmt().with_max_level(lf).init();
    });
}

#[cfg(unix)]
pub fn pipe_set() -> Result<(
    (impl Read + Write + Sized, impl Read + Write + Sized),
    (impl Read + Write + Sized, impl Read + Write + Sized),
)> {
    Ok((UnixStream::pair()?, UnixStream::pair()?))
}

#[cfg(unix)]
pub fn pipes() -> Result<(impl Read + Write + Sized, impl Read + Write + Sized)> {
    UnixStream::pair()
}

#[cfg(unix)]
pub fn pipe_set_async() -> Result<(
    (
        impl AsyncRead + AsyncWrite + Sized,
        impl AsyncRead + AsyncWrite + Sized,
    ),
    (
        impl AsyncRead + AsyncWrite + Sized,
        impl AsyncRead + AsyncWrite + Sized,
    ),
)> {
    Ok((AsyncUnixStream::pair()?, AsyncUnixStream::pair()?))
}

#[cfg(unix)]
pub fn pipe_set_async_unixstream() -> Result<(
    (AsyncUnixStream, AsyncUnixStream),
    (AsyncUnixStream, AsyncUnixStream),
)> {
    Ok((AsyncUnixStream::pair()?, AsyncUnixStream::pair()?))
}

#[cfg(unix)]
pub fn pipes_async() -> Result<(
    impl AsyncRead + AsyncWrite + Sized,
    impl AsyncRead + AsyncWrite + Sized,
)> {
    AsyncUnixStream::pair()
}

// // TODO: implement with something like named_pipes for windows
// #[cfg(windows)]
// pub fn pipe_set<RW>() -> ((RW,RW), (RW,RW))
// where
// 	RW: Read + Write + ?Sized
// {
// 	// Ok((UnixStream::pair()?, UnixStream::pair()?))
// }

#[cfg(test)]
mod test {

    use super::*;
    use std::{io, thread};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(unix)]
    #[tokio::test]
    async fn build_async_pipes() {
        let (mut client_host, mut client_wasm) = pipes_async().unwrap();
        let (mut wasm_remote, mut remote) = AsyncUnixStream::pair().unwrap();

        let buf = b"hello world";

        tokio::spawn(async move {
            let transport_result = {
                client_host.write_all(buf).await.unwrap();
                tokio::io::copy(&mut client_wasm, &mut wasm_remote).await
            };
            assert!(transport_result.is_ok());
            let n = transport_result.unwrap() as usize;
            assert_eq!(n, buf.len());
        });

        let mut out = vec![0_u8; 1024];
        let nr = remote.read(&mut out).await.unwrap();
        assert_eq!(nr, buf.len());
        assert_eq!(std::str::from_utf8(&out[..nr]).unwrap(), "hello world");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_async_pipe_set() {
        let ((mut client_host, mut client_wasm), (mut wasm_remote, mut remote)) =
            pipe_set_async().unwrap();

        let buf = b"hello world";

        tokio::spawn(async move {
            let transport_result = {
                client_host.write_all(buf).await.unwrap();
                tokio::io::copy(&mut client_wasm, &mut wasm_remote).await
            };
            assert!(transport_result.is_ok());
            let n = transport_result.unwrap() as usize;
            assert_eq!(n, buf.len());
        });

        let mut out = vec![0_u8; 1024];
        let nr = remote.read(&mut out).await.unwrap();
        assert_eq!(nr, buf.len());
        assert_eq!(std::str::from_utf8(&out[..nr]).unwrap(), "hello world");
    }

    #[cfg(unix)]
    #[test]
    fn build_pipes() -> Result<()> {
        let (mut client_host, mut client_wasm) = pipes()?;
        let (mut wasm_remote, mut remote) = UnixStream::pair()?;

        let buf = b"hello world";

        thread::spawn(move || {
            let transport_result = {
                client_host.write_all(buf).unwrap();
                io::copy(&mut client_wasm, &mut wasm_remote)
            };
            assert!(transport_result.is_ok());
            let n = transport_result.unwrap() as usize;
            assert_eq!(n, buf.len());
        });

        let mut out = vec![0_u8; 1024];
        let nr = remote.read(&mut out)?;
        assert_eq!(nr, buf.len());
        assert_eq!(std::str::from_utf8(&out[..nr]).unwrap(), "hello world");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn build_pipe_set() -> Result<()> {
        let ((mut client_host, mut client_wasm), (mut wasm_remote, mut remote)) = pipe_set()?;

        let buf = b"hello world";

        thread::spawn(move || {
            let transport_result = {
                client_host.write_all(buf).unwrap();
                io::copy(&mut client_wasm, &mut wasm_remote)
            };
            assert!(transport_result.is_ok());
            let n = transport_result.unwrap() as usize;
            assert_eq!(n, buf.len());
        });

        let mut out = vec![0_u8; 1024];
        let nr = remote.read(&mut out)?;
        assert_eq!(nr, buf.len());
        assert_eq!(std::str::from_utf8(&out[..nr]).unwrap(), "hello world");
        Ok(())
    }
}
