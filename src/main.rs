use anyhow::Result as AnyResult;
use clap::Parser;
use server::trojan::Tr0janServer;
use std::io;
use std::{fs::File, io::BufReader};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
mod server;

#[derive(Parser)]
struct Arguments {
    #[arg(short='a',default_value_t=String::from("0.0.0.0:10000"))]
    server_address: String,
    #[arg(short='p',default_value_t=String::from("nopassword"))]
    password: String,
}

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
    let arguments = Arguments::parse();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let (cert, key) = load_cert("cert/cert.pem", "cert/key.key")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;

    let server = Tr0janServer::new(&arguments.server_address, config, &arguments.password);
    server.run().await?;

    //let tls_acceptor = TlsAcceptor::from(config);

    Ok(())
}
