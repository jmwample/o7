use crate::{test_utils::init_subscriber, Result, Server};

use kemeleon::MlKem768;
use ptrs::{debug, trace};
use sha3::Sha3_256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::cmp::Ordering;
use std::time::Duration;

pub(crate) type ServerMK768 = Server<MlKem768, Sha3_256>;

#[tokio::test]
async fn public_handshake() -> Result<()> {
    init_subscriber();
    let (mut c, mut s) = tokio::io::duplex(65_536);
    let mut rng = rand::thread_rng();

    let o4_server = ServerMK768::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let _ = tokio::io::split(o4s_stream);
    });

    let o4_client = client_config.build();
    let _o4c_stream = o4_client.wrap(&mut c).await?;

    Ok(())
}

#[tokio::test]
async fn public_iface() -> Result<()> {
    init_subscriber();
    let message = b"awoewaeojawenwaefaw lfawn;awe da;wfenalw fawf aw";
    let (mut c, mut s) = tokio::io::duplex(65_536);
    let mut rng = rand::thread_rng();

    let o4_server = ServerMK768::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let mut o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        // let (mut r, mut w) = tokio::io::split(o4s_stream);
        // tokio::io::copy(&mut r, &mut w).await.unwrap();

        let mut buf = [0_u8; 50];
        let n = o4s_stream.read(&mut buf).await.unwrap();
        o4s_stream.write_all(&buf[..n]).await.unwrap();
        o4s_stream.flush().await.unwrap();

        if n != 48 {
            debug!("echo lengths don't match {n} != 48");
        }
    });

    let o4_client = client_config.build();
    let mut o4c_stream = o4_client.wrap(&mut c).await?;

    o4c_stream.write_all(&message[..]).await?;
    o4c_stream.flush().await?;

    let mut buf = vec![0_u8; message.len()];
    let n = o4c_stream.read(&mut buf).await?;
    assert_eq!(n, message.len());
    assert_eq!(
        &message[..],
        &buf,
        "\"{}\" != \"{}\"",
        String::from_utf8(message.to_vec())?,
        String::from_utf8(buf.clone())?,
    );

    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_10k_x1() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);
    let mut rng = rand::thread_rng();

    let o4_server = ServerMK768::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        let msg = [0_u8; 10240];
        w.write_all(&msg)
            .await
            .unwrap_or_else(|e| panic!("failed on write {e}"));
        w.flush().await.unwrap();
    });

    let expected_total = 10240;
    let mut buf = vec![0_u8; 1024 * 11];
    let mut received: usize = 0;
    for i in 0..8 {
        debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                let n = res?;
                received += n;
                trace!("received: {n}: total:{received}");
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1000)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_10k_x3() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);

    let mut rng = rand::thread_rng();
    let o4_server = ServerMK768::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        for _ in 0..3 {
            let msg = [0_u8; 10240];
            w.write_all(&msg)
                .await
                .unwrap_or_else(|e| panic!("failed on write {e}"));
            w.flush().await.unwrap();
        }
    });

    let expected_total = 10240 * 3;
    let mut buf = vec![0_u8; 1024 * 32];
    let mut received: usize = 0;
    for i in 0..24 {
        // debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                let n = res?;
                received += n;
                trace!("received: {n}: total:{received}");
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1000)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_1M_1024x1024() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);
    let mut rng = rand::thread_rng();

    let o4_server = ServerMK768::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        let msg = [0_u8; 1024];
        for i in 0..1024 {
            w.write_all(&msg)
                .await
                .unwrap_or_else(|e| panic!("failed on write #{i}: {e}"));
            w.flush().await.unwrap();
        }
    });

    let expected_total = 1024 * 1024;
    let mut buf = vec![0_u8; 1024 * 1024];
    let mut received: usize = 0;
    for i in 0..1024 {
        // debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                received += res?;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_512k_x1() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 512);
    let mut rng = rand::thread_rng();

    let o4_server = ServerMK768::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        let msg = [0_u8; 1024 * 512];
        w.write_all(&msg)
            .await
            .unwrap_or_else(|_| panic!("failed on write"));
        w.flush().await.unwrap();
    });

    let expected_total = 1024 * 512;
    let mut buf = vec![0_u8; 1024 * 1024];
    let mut received: usize = 0;
    let mut i = 0;
    while received < expected_total {
        debug!("client read: {i} / {received}");
        tokio::select! {
            res = r.read(&mut buf) => {
                received += res?;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(2000)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
        i += 1;
    }

    assert_eq!(
        received, expected_total,
        "incorrect amount received {received} != {expected_total}"
    );
    Ok(())
}

#[tokio::test]
async fn transfer_2_x() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);
    let mut rng = rand::thread_rng();

    let o4_server = ServerMK768::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    let base: usize = 2;
    tokio::spawn(async move {
        for i in (0..20).step_by(2) {
            let msg = vec![0_u8; base.pow(i)];
            w.write_all(&msg)
                .await
                .unwrap_or_else(|_| panic!("failed on write #{i}"));
            debug!("wrote 2^{i}");
            w.flush().await.unwrap();
        }
    });

    let mut buf = vec![0_u8; 1024 * 1024 * 100];
    let expected_total: usize = (0..20).step_by(2).map(|i| base.pow(i)).sum();
    let mut received = 0;

    let mut i = 0;
    loop {
        let res_timeout =
            tokio::time::timeout(Duration::from_millis(10000), r.read(&mut buf)).await;

        let res = res_timeout.unwrap();
        let n = res?;
        received += n;
        if n == 0 {
            debug!("read 0?");
            break;
        } else {
            debug!("({i}) read {n}B - {received}");
        }

        match received.cmp(&expected_total) {
            Ordering::Less => {}
            Ordering::Equal => break,
            Ordering::Greater => {
                panic!("received more than expected {received} > {expected_total}")
            }
        }
        i += 1;
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}
