use rustls::ServerConfig;
use sha2::{Digest, Sha224};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, span};

pub struct Tr0janServer {
    address: String,
    server_config: Arc<ServerConfig>,
    password: Arc<String>,
}

impl Tr0janServer {
    pub fn new(address: &str, server_config: ServerConfig, password: &str) -> Arc<Self> {
        let mut hasher = Sha224::new();
        hasher.update(password);
        let password = hex::encode(hasher.finalize());

        Arc::new(Self {
            address: address.to_string(),
            server_config: Arc::new(server_config),
            password: Arc::new(password),
        })
    }

    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.address.clone()).await?;
        let tls_acceptor = TlsAcceptor::from(self.server_config.clone());
        let _span = span!(tracing::Level::DEBUG, "listen", address = self.address).entered();

        info!("TCP Server Stated");

        _span.exit();
        loop {
            match listener.accept().await {
                Ok((stream, ..)) => {
                    let this = self.clone();
                    if let Ok(tls_stream) = tls_acceptor
                        .accept(stream)
                        .await
                        .inspect_err(|error| eprintln!("{error}"))
                    {
                        tokio::spawn(async move {
                            this.handle(tls_stream)
                                .await
                                .inspect_err(|error| eprint!("{error}"))
                        });
                    }
                }
                Err(e) => {
                    eprintln!("accept failed: {:?}", e);
                    continue;
                }
            }
        }
    }

    pub async fn handle<IO: AsyncRead + AsyncWrite + Unpin>(
        self: Arc<Self>,
        mut tls_stream: TlsStream<IO>,
    ) -> anyhow::Result<()> {
        let mut password = [0_u8; 56];
        // read head 56 bytes content
        tls_stream.read_exact(&mut password).await?;

        let password_str = match std::str::from_utf8(&password) {
            Ok(password) => password,
            Err(_) => {
                error!("password is not utf8");
                return Ok(());
            }
        };

        if password_str != self.password.as_str() {
            error!("invalid password");
            return Ok(());
        }

        Self::read_crlf(&mut tls_stream).await?;

        let cmd = tls_stream.read_u8().await?;

        // check is tcp, if not tcp return
        if cmd != 0x1 {
            return Ok(());
        }
        // check address type and got address
        let address_type = tls_stream.read_u8().await?;
        let address = match address_type {
            0x1 => {
                let buffer = tls_stream.read_u32().await?;
                IpAddr::V4(Ipv4Addr::from(buffer)).to_string()
            }
            0x3 => {
                let length = tls_stream.read_u8().await?;
                let mut buffer = vec![0_u8; length as usize];
                tls_stream.read_exact(&mut buffer).await?;
                String::from_utf8(buffer)?
            }
            0x4 => {
                let buffer = tls_stream.read_u128().await?;
                IpAddr::V6(Ipv6Addr::from(buffer)).to_string()
            }
            _ => {
                //panic!("unknown address")
                unimplemented!()
            }
        };

        let port = tls_stream.read_u16().await?;
        Self::read_crlf(&mut tls_stream).await?;

        let mut remote = TcpStream::connect(format!("{address}:{port}")).await?;
        copy_bidirectional(&mut remote, &mut tls_stream).await?;
        Ok(())
    }

    async fn read_crlf<IO: AsyncRead + AsyncWrite + Unpin>(
        mut tls_stream: IO,
    ) -> anyhow::Result<()> {
        tls_stream.read_u16().await?;
        Ok(())
    }
}
