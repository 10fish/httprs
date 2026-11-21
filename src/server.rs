use super::{
    VERSION_STRING,
    conf::Configuration,
    http::{StaticFiles, text_response},
};
use colored::Colorize;
use hyper::{Request, StatusCode, Version, header, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    error::Error, future::Future, io, net::SocketAddr, path::Path, sync::Arc, time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    signal::ctrl_c,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, info};

/// HTTP/1.1 server for static files.
pub struct Server {
    /// The parsed server configuration.
    pub configuration: Arc<Configuration>,
}

impl Server {
    /// Initialize the server, panicking if its configuration cannot be loaded.
    pub async fn new(conf: Configuration) -> Self {
        Self::try_new(conf).await.expect("cannot parse parameters")
    }

    /// Load configuration without panicking on invalid input.
    pub async fn try_new(conf: Configuration) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            configuration: Arc::new(conf.init().await?),
        })
    }

    /// Bind and run the server. When configured, Ctrl+C initiates graceful shutdown.
    pub async fn run(self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let host = self.configuration.host.as_deref().unwrap_or("0.0.0.0");
        let port = self.configuration.port.unwrap_or(9900);
        let listener = TcpListener::bind((host, port)).await?;
        let graceful = self.configuration.graceful_shutdown;
        self.serve(listener, async move {
            if graceful {
                ctrl_c().await
            } else {
                std::future::pending().await
            }
        })
        .await
    }

    /// Serve on an existing listener until the provided shutdown future completes.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = io::Result<()>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let root = self
            .configuration
            .home
            .as_deref()
            .map(Path::new)
            .unwrap_or(Path::new("."));
        let files = StaticFiles::new(root).await?;
        let acceptor = self.https_acceptor()?;
        self.print_server_info(listener.local_addr()?);

        let tracker = TaskTracker::new();
        let stopping = CancellationToken::new();
        let aborting = CancellationToken::new();
        let _abort_on_drop = aborting.clone().drop_guard();
        tokio::pin!(shutdown);
        let result = loop {
            let incoming = tokio::select! {
                biased;
                result = &mut shutdown => break result,
                incoming = listener.accept() => incoming,
            };
            let (tcp, _) = match incoming {
                Ok(connection) => connection,
                Err(error) => break Err(error),
            };
            let files = files.clone();
            let acceptor = acceptor.clone();
            let stopping = stopping.clone();
            let aborting = aborting.clone();
            tracker.spawn(async move {
                let connection = async {
                    let result = if let Some(acceptor) = acceptor {
                        let tls = tokio::select! {
                            _ = stopping.cancelled() => return,
                            stream = acceptor.accept(tcp) => stream,
                        };
                        match tls {
                            Ok(stream) => serve_connection(stream, files, stopping).await,
                            Err(error) => {
                                debug!(%error, "TLS handshake failed");
                                return;
                            }
                        }
                    } else {
                        serve_connection(tcp, files, stopping).await
                    };
                    if let Err(error) = result {
                        debug!(%error, "HTTP connection failed");
                    }
                };
                tokio::select! {
                    _ = aborting.cancelled() => {}
                    _ = connection => {}
                }
            });
        };

        drop(listener);
        stopping.cancel();
        tracker.close();
        if tokio::time::timeout(Duration::from_secs(5), tracker.wait())
            .await
            .is_err()
        {
            aborting.cancel();
            tracker.wait().await;
        }
        Ok(result?)
    }

    fn https_acceptor(&self) -> Result<Option<TlsAcceptor>, Box<dyn Error + Send + Sync>> {
        let Some(secure) = &self.configuration.secure else {
            return Ok(None);
        };
        let certs = CertificateDer::pem_file_iter(&secure.cert)?.collect::<Result<_, _>>()?;
        let private_key = PrivateKeyDer::from_pem_file(&secure.key)?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;
        Ok(Some(TlsAcceptor::from(Arc::new(config))))
    }

    fn print_server_info(&self, address: SocketAddr) {
        let protocol = self.configuration.protocol();
        info!("Server {} started.", VERSION_STRING.bright_blue());
        info!(
            "Serving {} on: {}",
            protocol.to_uppercase().green(),
            format!("{protocol}://{address}").green()
        );

        if address.ip().is_unspecified() && address.is_ipv4() {
            for ip in super::http::get_all_local_ips() {
                info!(
                    "  -> {}",
                    format!("{protocol}://{ip}:{}", address.port()).green()
                );
            }
        }
    }
}

fn valid_host(request: &Request<impl Sized>) -> bool {
    if request.version() != Version::HTTP_11 {
        return true;
    }
    let mut hosts = request.headers().get_all(header::HOST).iter();
    let Some(host) = hosts.next().and_then(|host| host.to_str().ok()) else {
        return false;
    };
    hosts.next().is_none()
        && !host.contains(['@', ','])
        && hyper::Uri::builder()
            .authority(host)
            .build()
            .is_ok_and(|uri| uri.host().is_some_and(|host| !host.is_empty()))
}

async fn serve_connection(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    files: StaticFiles,
    stopping: CancellationToken,
) -> Result<(), hyper::Error> {
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30));
    let connection = builder.serve_connection(
        TokioIo::new(stream),
        service_fn(move |request| {
            let files = files.clone();
            async move {
                let response = if valid_host(&request) {
                    files.handle(request).await
                } else {
                    text_response(StatusCode::BAD_REQUEST)
                };
                Ok::<_, std::convert::Infallible>(response)
            }
        }),
    );
    tokio::pin!(connection);

    tokio::select! {
        result = &mut connection => result,
        _ = stopping.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn http1_pipeline_and_graceful_shutdown() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let files = StaticFiles::new(env!("CARGO_MANIFEST_DIR")).await.unwrap();
            let (mut client, server) = tokio::io::duplex(4096);
            let stopping = CancellationToken::new();
            let task = tokio::spawn(serve_connection(server, files, stopping.clone()));

            client.write_all(b"HEAD /static/index.html HTTP/1.1\r\nHost: localhost\r\n\r\nGET /static/index.html HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-8\r\n\r\n").await.unwrap();

            let mut response = Vec::new();
            for _ in 0..2 {
                loop {
                    response.push(client.read_u8().await.unwrap());
                    if response.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
            }
            let response = String::from_utf8(response).unwrap();
            let (head, get) = response.split_once("\r\n\r\n").unwrap();
            assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(get.starts_with("HTTP/1.1 206 Partial Content\r\n"));
            assert!(get.contains("content-range: bytes 0-8/"));

            let mut content = [0; 9];
            client.read_exact(&mut content).await.unwrap();
            assert_eq!(&content, b"<!doctype");

            stopping.cancel();
            assert_eq!(client.read(&mut content).await.unwrap(), 0);
            task.await.unwrap().unwrap();
        }).await.unwrap();
    }
}
