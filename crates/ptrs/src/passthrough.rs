use super::*;

pub struct Passthrough {}

impl<T> PluggableTransport<T> for Passthrough
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientBuilder = BuilderC;
    type ServerBuilder = BuilderS;

    fn name() -> String {
        String::from("passthrough")
    }

    // fn client_builder() -> <<Self as PluggableTransport<T,std::io::Error>>::Client as ClientTransport<T, std::io::Error>>::Builder {
    fn client_builder() -> <Self as PluggableTransport<T>>::ClientBuilder {
        BuilderC::default()
    }

    // fn server_builder() -> <<Self as PluggableTransport<T, std::io::Error>>::Server as ServerTransport<T>>::Builder{
    fn server_builder() -> <Self as PluggableTransport<T>>::ServerBuilder {
        BuilderS::default()
    }
}

#[derive(Debug, Default)]
pub struct BuilderS {}

impl<T> ServerBuilder<T> for BuilderS
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Error = std::io::Error;
    type ServerPT = Passthrough;
    type Transport = Passthrough;

    fn method_name() -> String {
        String::from("passthrough")
    }

    fn build(self) -> Self::ServerPT {
        Passthrough {}
    }

    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn options(&mut self, _opts: &args::Args) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn get_client_params(&self) -> String {
        String::new()
    }

    fn timeout(&mut self, _timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BuilderC {}

impl<T> ClientBuilder<T> for BuilderC
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientPT = Passthrough;
    type Error = std::io::Error;
    type Transport = Passthrough;

    fn method_name() -> String {
        String::from("passthrough")
    }

    fn build(&self) -> Self::ClientPT {
        Passthrough {}
    }

    fn options(&mut self, _opts: &args::Args) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn timeout(&mut self, _timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }
}

/// Example wrapping transport that just passes the incoming connection future through
/// unmodified as a proof of concept.
impl<InRW> ClientTransport<InRW, std::io::Error> for Passthrough
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW = InRW;
    type OutErr = std::io::Error;
    type Builder = BuilderC;

    fn establish(self, input: Pin<F<InRW, std::io::Error>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        input
    }

    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(Self::hs(io))
    }

    fn method_name() -> String {
        String::from("passthrough")
    }
}

// -_-    must be static, even though I wish it didn't
//
// the parameter type `RW` may not live long enough
// help: consider adding an explicit lifetime bound
//     |
// 125 |     impl<RW: 'static> T1<RW> for Passthrough {
//     |            +++++++++
//
//
impl<RW> ServerTransport<RW> for Passthrough
where
    RW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW = RW;
    type OutErr = std::io::Error;
    type Builder = BuilderS;

    fn reveal(self, io: RW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(Self::hs(io))
    }

    fn method_name() -> String {
        String::from("passthrough")
    }

    fn get_client_params(&self) -> String {
        String::new()
    }
}

impl Passthrough {
    async fn hs<RW>(io: RW) -> Result<RW, std::io::Error> {
        Ok(io)
    }
}

#[cfg(test)]
mod design_tests {

    use crate::info;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpStream,
    };
    use tracing_subscriber::filter::LevelFilter;

    use std::env;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::Once;
    use std::time::Duration;

    use super::{BuilderC, BuilderS, Passthrough};
    use crate::{
        ClientBuilder,
        ClientTransport,
        FutureResult,
        PluggableTransport,
        ServerBuilder, // ClientInfo, Conn,
        ServerTransport,
    };

    #[allow(unused)]
    fn print_type_of<T>(_: &T) {
        info!("{}", std::any::type_name::<T>())
    }

    static SUBSCRIBER_INIT: Once = Once::new();

    pub fn init_subscriber() {
        SUBSCRIBER_INIT.call_once(|| {
            let level = env::var("RUST_LOG_LEVEL").unwrap_or("error".into());
            let lf = LevelFilter::from_str(&level).unwrap();

            tracing_subscriber::fmt().with_max_level(lf).init();
        });
    }

    async fn establish_using_pt<T, E, P>(
        t_fut: Pin<FutureResult<T, E>>,
    ) -> Result<
        Pin<
            FutureResult<
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::ClientPT as ClientTransport<T,E>>::OutRW,
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::ClientPT as ClientTransport<T,E>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
        P: PluggableTransport<T>,
        P::ClientBuilder: ClientBuilder<T>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::ClientPT: ClientTransport<T,E>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::Error: std::error::Error + 'static,
        E: std::error::Error + 'static,
    {
        Ok(P::client_builder()
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .establish(t_fut))
    }

    #[tokio::test]
    async fn client_interface_establish_pt() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        rx.await.unwrap();

        let tcp_fut = TcpStream::connect("127.0.0.1:8000");

        // let builder = <Passthrough as PluggableTransport<TcpStream>>::ClientBuilder::default();
        // let builder = <<Passthrough as PluggableTransport<TcpStream, std::io::Error>>::Client as ClientTransport<TcpStream,std::io::Error>>::Builder::default();

        let conn_fut =
            establish_using_pt::<TcpStream, std::io::Error, Passthrough>(Box::pin(tcp_fut))
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        info!("connecting to tcp and pt");
        let mut conn = conn_fut.await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    async fn establish_using_builder<T, E, B>(
        t_fut: Pin<FutureResult<T, E>>,
        mut pt: B,
    ) -> Result<
        Pin<
            FutureResult<
                <<B as ClientBuilder<T>>::ClientPT as ClientTransport<T, E>>::OutRW,
                <<B as ClientBuilder<T>>::ClientPT as ClientTransport<T, E>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
        B: ClientBuilder<T>,
        B::ClientPT: ClientTransport<T, E>,
        B::Error: std::error::Error + 'static,
    {
        Ok(pt
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .establish(t_fut))
    }

    #[tokio::test]
    async fn client_interface_establish() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8001")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        rx.await.unwrap();

        let tcp_fut = TcpStream::connect("127.0.0.1:8001");

        // let builder = <Passthrough as PluggableTransport<TcpStream>>::ClientBuilder::default();
        // let builder = <<Passthrough as PluggableTransport<TcpStream, std::io::Error>>::Client as ClientTransport<TcpStream,std::io::Error>>::Builder::default();
        let builder = <Passthrough as PluggableTransport<TcpStream>>::client_builder();

        let conn_fut = establish_using_builder(Box::pin(tcp_fut), builder)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        info!("connecting to tcp and pt");
        let mut conn = conn_fut.await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    async fn wrap_using_pt<T, E, P>(
        t: T,
    ) -> Result<
        Pin<
            FutureResult<
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::ClientPT as ClientTransport<T,E>>::OutRW,
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::ClientPT as ClientTransport<T,E>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
        P: PluggableTransport<T>,
        P::ClientBuilder: ClientBuilder<T>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::ClientPT: ClientTransport<T,E>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilder<T>>::Error: std::error::Error + 'static,
        E: std::error::Error + 'static,
    {
        Ok(P::client_builder()
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .wrap(t))
    }

    #[tokio::test]
    async fn client_interface_wrap_pt() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8002")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        rx.await.unwrap();

        info!("connecting to tcp");
        let tcp_conn = TcpStream::connect("127.0.0.1:8002").await?;

        info!("connecting to pt over tcp");
        let conn_fut = wrap_using_pt::<TcpStream, std::io::Error, Passthrough>(tcp_conn)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        let mut conn = conn_fut.await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    async fn wrap_conn_in_builder<T, E, B>(
        t: T,
        mut pt: B,
    ) -> Result<
        Pin<
            FutureResult<
                <<B as ClientBuilder<T>>::ClientPT as ClientTransport<T, E>>::OutRW,
                <<B as ClientBuilder<T>>::ClientPT as ClientTransport<T, E>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
        B: ClientBuilder<T>,
        B::ClientPT: ClientTransport<T, E>,
        B::Error: std::error::Error + 'static,
    {
        Ok(pt
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .wrap(t))
    }

    #[tokio::test]
    async fn client_interface_wrap() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8004")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        rx.await.unwrap();

        info!("connecting to tcp");
        let tcp_conn = TcpStream::connect("127.0.0.1:8004").await?;

        let builder = <Passthrough as PluggableTransport<TcpStream>>::client_builder();

        let mut conn = wrap_conn_in_builder(tcp_conn, builder)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?
            .await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }


    async fn wrap_server_using_pt<T, P>(
        t: T,
    ) -> Result<
        Pin<
            FutureResult<
                <<<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder<T>>::ServerPT as ServerTransport<T>>::OutRW,
                <<<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder<T>>::ServerPT as ServerTransport<T>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
        P: PluggableTransport<T>,
        P::ClientBuilder: ClientBuilder<T>,
        <<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder<T>>::ServerPT: ServerTransport<T>,
        <<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder<T>>::Error: std::error::Error + 'static,
    {
        let mut builder = P::server_builder();
        builder
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?;
        let server = builder.build();
        Ok(server.reveal(t))
    }

    #[tokio::test]
    async fn server_interface_wrap_pt() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8005")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (tcp_conn, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let conn_fut = wrap_server_using_pt::<TcpStream, Passthrough>(tcp_conn)
                .await
                .unwrap();
            let mut conn = conn_fut.await.unwrap();
            info!("pt accepted connection");

            let (mut r, mut w) = tokio::io::split(&mut conn);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        rx.await.unwrap();

        info!("connecting to tcp");
        let tcp_conn = TcpStream::connect("127.0.0.1:8005").await?;

        info!("connecting to pt over tcp");
        let conn_fut = wrap_using_pt::<TcpStream, std::io::Error, Passthrough>(tcp_conn)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        let mut conn = conn_fut.await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    async fn wrap_server_in_builder<T, B>(
        t: T,
        mut pt_builder: B,
    ) -> Result<
        Pin<
            FutureResult<
                <<B as ServerBuilder<T>>::ServerPT as ServerTransport<T>>::OutRW,
                <<B as ServerBuilder<T>>::ServerPT as ServerTransport<T>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error + Send + Sync>,
    >
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
        B: ServerBuilder<T>,
        B::ServerPT: ServerTransport<T>,
        B::Error: std::error::Error + 'static,
        <B as ServerBuilder<T>>::Error: std::error::Error + Send + Sync,
    {
        pt_builder
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?;

        Ok(pt_builder.build().reveal(t))
    }

    #[tokio::test]
    async fn server_interface_wrap() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8006")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (tcp_conn, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let builder = <Passthrough as PluggableTransport<TcpStream>>::server_builder();

            let mut conn = wrap_server_in_builder(tcp_conn, builder)
                .await
                .unwrap()
                .await
                .unwrap();

            let (mut r, mut w) = tokio::io::split(&mut conn);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        rx.await.unwrap();

        info!("connecting to tcp");
        let mut conn = TcpStream::connect("127.0.0.1:8006").await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    #[tokio::test]
    async fn basic_wrap_client() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};

        // note that this is not await-ed here so it is not executed until later
        let tcp_dial_fut = TcpStream::connect("127.0.0.1:8007");

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8007")
                .await
                .unwrap();
            info!("tcp listening");

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;
        info!("wrapping client fut");

        // this takes the dial future and creates a new future
        let conn_fut = p.establish(Box::pin(tcp_dial_fut));

        info!("running client fut");
        // once the connection future is await-ed it will await the dial future.
        let mut conn = conn_fut.await?;
        info!("client connected");

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    #[tokio::test]
    async fn basic_wrap_server() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};

        // note that this is not await-ed here so it is not executed until later
        let tcp_dial_fut = Box::pin(TcpStream::connect("127.0.0.1:8008"));

        tokio::spawn(async move {
            let sp = Passthrough {};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8008")
                .await
                .unwrap();
            info!("tcp listening");

            // let (mut sock, _) = sp.wrap_acc(Box::pin(listener.accept())).await.unwrap();
            let (conn, _) = listener.accept().await.unwrap();
            info!("tcp accepted, and handshaked");

            let mut sock = sp.wrap(conn).await.unwrap();
            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;
        info!("wrapping client fut");

        // this takes the dial future and creates a new future
        let conn_fut = p.establish(tcp_dial_fut);

        info!("running client fut");
        // once the connection future is await-ed it will await the dial future.
        let mut conn = conn_fut.await?;
        info!("client connected");

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    #[tokio::test]
    async fn server_composition() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8009")
                .await
                .unwrap();
            tx.send(()).unwrap();

            let (tcp_sock, _) = listener.accept().await.unwrap();

            let pb1: BuilderS = <Passthrough as PluggableTransport<TcpStream>>::server_builder();
            let pb2: BuilderS = <Passthrough as PluggableTransport<TcpStream>>::server_builder();
            let pb3: BuilderS = <Passthrough as PluggableTransport<TcpStream>>::server_builder();

            let client1 = <BuilderS as ServerBuilder<TcpStream>>::build(pb1);
            let conn1 = client1.reveal(tcp_sock).await.unwrap();

            let client2 = <BuilderS as ServerBuilder<TcpStream>>::build(pb2);
            let conn2 = client2.reveal(conn1).await.unwrap();

            let client3 = <BuilderS as ServerBuilder<TcpStream>>::build(pb3);
            let mut sock = client3.reveal(conn2).await.unwrap();

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        rx.await.unwrap();
        let mut conn = Box::pin(TcpStream::connect("127.0.0.1:8009")).await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;

        Ok(())
    }

    #[tokio::test]
    async fn client_composition() -> Result<(), std::io::Error> {
        init_subscriber();

        let tcp_dial_fut = Box::pin(TcpStream::connect("127.0.0.1:8010"));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8010")
                .await
                .unwrap();
            tx.send(()).unwrap();
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let pb: &BuilderC = &<Passthrough as PluggableTransport<TcpStream>>::client_builder();

        rx.await.unwrap();
        let client = <BuilderC as ClientBuilder<TcpStream>>::build(pb);
        let conn_fut1 = client.establish(Box::pin(tcp_dial_fut));
        let client = <BuilderC as ClientBuilder<TcpStream>>::build(pb);
        let conn_fut2 = client.establish(Box::pin(conn_fut1));
        let client = <BuilderC as ClientBuilder<TcpStream>>::build(pb);
        let conn_fut3 = client.establish(Box::pin(conn_fut2));
        let mut conn = conn_fut3.await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;

        Ok(())
    }
}
