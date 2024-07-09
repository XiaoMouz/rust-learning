use anyhow::Result as AnyResult;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::{fs::File, io::BufReader};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, span};

fn load_cert(
    cert_path: &str,
    private_key_path: &str,
) -> AnyResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert = BufReader::new(File::open(cert_path)?);
    let mut private_key = BufReader::new(File::open(private_key_path)?);

    let cert = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
    let private_key = rustls_pemfile::private_key(&mut private_key)?.ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "no private key found",
    ))?;
    Ok((cert, private_key))
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let (cert, key) = load_cert("cert/cert.pem", "cert/key.key")?;

    let listener = TcpListener::bind("0.0.0.0:10000").await?;

    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)?,
    );

    let tls_acceptor = TlsAcceptor::from(config);

    let _span = span!(tracing::Level::DEBUG, "listen", address = "0.0.0.0:443").entered();

    info!("TCP Server Stated");

    _span.exit();

    loop {
        match listener.accept().await {
            Ok((stream, ..)) => {
                if let Ok(tls_stream) = tls_acceptor
                    .accept(stream)
                    .await
                    .inspect_err(|error| eprintln!("{error}"))
                {
                    tokio::spawn(async move {
                        handle(tls_stream)
                            .await
                            .inspect_err(|error| eprint!("{error}"))
                    });
                }
            }
            Err(e) => {
                eprintln!("accept failed: {:?}", e);
                continue;
            }
        };
    }
}

async fn handle<IO: AsyncRead + AsyncWrite + Unpin>(
    mut tls_stream: TlsStream<IO>,
) -> AnyResult<()> {
    let mut password = [0_u8; 56];
    // read head 56 bytes content
    tls_stream.read_exact(&mut password).await?;

    read_crlf(&mut tls_stream).await;

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
            tls_stream.read_exact(&mut buffer).await?.to_string()
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
    read_crlf(&mut tls_stream).await;
    let mut remote = TcpStream::connect(format!("{address}:{port}")).await?;
    copy_bidirectional(&mut remote, &mut tls_stream).await?;
    Ok(())
}

async fn read_crlf<IO: AsyncRead + AsyncWrite + Unpin>(mut tls_stream: IO) {
    tls_stream.read_u16().await.unwrap();
}
