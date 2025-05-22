mod auth;
mod chat;
mod config;
mod error;
mod message;
mod moderation;

use config::Config;
use error::*;
use log::*;
use rustls::pki_types::PrivateKeyDer;
use structopt::*;

use actix::*;
use actix_web::{App, HttpServer, web};
use uuid::Uuid;

// Import rustls directly to avoid version conflicts
#[cfg(feature = "rustls-tls")]
use {
    rustls::ServerConfig,
    rustls_pemfile::{certs, pkcs8_private_keys},
    std::{fs::File, io::BufReader},
};

#[cfg(feature = "openssl-tls")]
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

#[derive(StructOpt)]
enum Opt {
    /// Starts the axochat server.
    #[structopt(name = "start")]
    Start,
    /// Generates a JWT which can be used for logging in.
    /// This should only be used for testing.
    /// If you want to generate JWT for non-testing purposes, send a RequestJWT packet to the server.
    #[structopt(name = "generate")]
    Generate {
        #[structopt(name = "name")]
        name: String,
        #[structopt(name = "uuid")]
        uuid: Option<Uuid>,
    },
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config = config::read_config()?;
    debug!("Read configuration file: {:?}", config);

    let opt = Opt::from_args();
    match opt {
        Opt::Start => start_server(config).await,
        Opt::Generate { name, uuid } => {
            let auth = match config.auth {
                Some(auth) => auth::Authenticator::new(&auth),
                None => {
                    eprintln!("Please add a `auth` segment to your configuration file.");
                    Err(ClientError::NotSupported.into())
                }
            }?;
            let token = auth.new_token(auth::UserInfo {
                name,
                uuid: uuid.unwrap_or_else(|| Uuid::from_u128(0)),
            })?;
            println!("{}", token);
            Ok(())
        }
    }
}

async fn start_server(config: Config) -> Result<()> {
    let server_config = config.clone();
    let server = chat::ChatServer::new(server_config).start();

    let server_data = web::Data::new(server);
    let address = config.net.address.to_string();

    let mut server = HttpServer::new(move || {
        App::new()
            .app_data(server_data.clone())
            .service(web::resource("/ws").to(chat::chat_route))
    });

    if let (Some(cert), Some(key)) = (config.net.cert_file, config.net.key_file) {
        #[cfg(all(feature = "openssl-tls", feature = "rustls-tls"))]
        {
            compile_error!("Can't enable both the `openssl-tls` and the `rustls-tls` feature.")
        }

        #[cfg(feature = "openssl-tls")]
        {
            let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            builder.set_certificate_chain_file(&cert)?;
            let ft = match key.extension() {
                Some(ext) if ext == "pem" => SslFiletype::PEM,
                _ => SslFiletype::ASN1,
            };
            builder.set_private_key_file(&key, ft)?;

            server = server.bind_openssl(address, builder)?;
        }

        #[cfg(feature = "rustls-tls")]
        {
            info!(
                "Loading TLS certificate from {:?} and key from {:?}",
                cert, key
            );

            // Read cert and key files with proper mutability
            let mut cert_file = BufReader::new(File::open(&cert)?);
            let mut key_file = BufReader::new(File::open(&key)?);

            // Load certificate chain and key
            let cert_chain = certs(&mut cert_file).map(|cert| cert.unwrap()).collect();

            let Some(Ok(key)) = pkcs8_private_keys(&mut key_file).next() else {
                return Err(Error::RustTLSNoMsg);
            };

            // Build rustls server configuration
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key))
                .map_err(|_| Error::RustTLSNoMsg)?;

            // Special hack to make rustls versions compatible with actix-web
            // We use unsafe to cast our ServerConfig to the version expected by actix-web
            use std::mem;
            let config_ptr = Box::into_raw(Box::new(config));
            let actix_rustls_config = unsafe { mem::transmute(config_ptr) };

            server = server.bind_rustls(address, unsafe { *Box::from_raw(actix_rustls_config) })?;
        }

        #[cfg(not(any(feature = "openssl-tls", feature = "rustls-tls")))]
        {
            server = server.bind(address)?;
        }
    } else {
        server = server.bind(address)?;
    }

    info!("Started server at {}", config.net.address);
    server.run().await?;
    Ok(())
}
