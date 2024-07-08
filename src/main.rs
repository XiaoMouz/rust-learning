use core::panic;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::{fs::File, io::BufReader};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

fn load_cert(
    cert_path: &str,
    private_key_path: &str,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut cert = BufReader::new(File::open(cert_path).unwrap());
    let mut private_key = BufReader::new(File::open(private_key_path).unwrap());

    let cert = rustls_pemfile::certs(&mut cert)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let private_key = rustls_pemfile::private_key(&mut private_key)
        .unwrap()
        .unwrap();
    (cert, private_key)
}

#[tokio::main]
async fn main() {
    let (cert, key) = load_cert("cert/ert.pem", "cert/key.key");

    let listener = TcpListener::bind("0.0.0.0:10000")
        .await
        .expect("Error in bind");

    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .unwrap(),
    );

    let tls_acceptor = TlsAcceptor::from(config);

    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        let tls_stream = tls_acceptor
            .accept(stream)
            .await
            .expect(("Some problem with ".to_string() + addr.ip().to_string().as_str()).as_str());

        tokio::spawn(async move {
            handle(tls_stream).await;
        });
    }
}

async fn handle<IO: AsyncRead + AsyncWrite + Unpin>(mut tls_stream: TlsStream<IO>) {
    let mut password = [0_u8; 56];
    // read head 56 bytes content
    tls_stream.read_exact(&mut password).await.unwrap();

    read_crlf(&mut tls_stream).await;

    let cmd = tls_stream.read_u8().await.unwrap();

    // check is tcp, if not tcp return
    if cmd != 0x1 {
        return;
    }
    // check address type and got address
    let address_type = tls_stream.read_u8().await.unwrap();
    let address = match address_type {
        0x1 => {
            let buffer = tls_stream.read_u32().await.unwrap();
            IpAddr::V4(Ipv4Addr::from(buffer)).to_string()
        }
        0x3 => {
            let length = tls_stream.read_u8().await.unwrap();
            let mut buffer = vec![0_u8; length as usize];
            tls_stream
                .read_exact(&mut buffer)
                .await
                .unwrap()
                .to_string()
        }
        0x4 => {
            let buffer = tls_stream.read_u128().await.unwrap();
            IpAddr::V6(Ipv6Addr::from(buffer)).to_string()
        }
        _ => {
            panic!("unknown address")
        }
    };

    let port = tls_stream.read_u16().await.unwrap();
    read_crlf(&mut tls_stream).await;
    let mut remote = TcpStream::connect(format!("{address}:{port}"))
        .await
        .unwrap();
    copy_bidirectional(&mut remote, &mut tls_stream)
        .await
        .unwrap();
}

async fn read_crlf<IO: AsyncRead + AsyncWrite + Unpin>(mut tls_stream: IO) {
    tls_stream.read_u16().await.unwrap();
}
