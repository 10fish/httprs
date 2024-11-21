use super::{
    conf::Configuration,
    http::{file_service, local_address},
    VERSION_STRING,
};
use colored::Colorize;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    error::Error,
    io::{Error as IoError, ErrorKind},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
};
use tokio::{net::TcpListener, signal::ctrl_c, sync::RwLock};
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info};

/// Simple http(s) server for static files
pub struct Server {
    listener: Option<TcpListener>,
    /// The parsed server configuration
    pub configuration: Arc<Configuration>,
    shutdown: Arc<RwLock<Shutdown>>,
    tracker: Arc<TaskTracker>,
}

impl Server {
    pub async fn new(conf: Configuration) -> Self {
        match conf.init().await {
            Ok(conf) => Server {
                listener: None,
                configuration: Arc::new(conf),
                shutdown: Arc::new(RwLock::new(Shutdown::new())),
                tracker: Arc::new(TaskTracker::new()),
            },
            Err(err) => {
                panic!("cannot parse parameters: {}", err);
            }
        }
    }

    pub async fn run(mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.setup_logging();

        let host = self.configuration.host.as_ref().unwrap();
        let port = self.configuration.port.unwrap();
        debug!(
            "Serving with configuration: {}",
            self.configuration.display()
        );

        let binding_addr = format!("{}:{}", host, port);
        match TcpListener::bind(binding_addr.clone()).await {
            Ok(listener) => {
                self.listener = Some(listener);
                self.print_server_info();

                let result = if self.configuration.graceful_shutdown {
                    self.run_with_graceful_shutdown().await
                } else {
                    self.run_simply(None::<Box<dyn Fn() -> bool>>).await
                };
                match result {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{}", e);
                    }
                }
            }
            Err(err) => {
                panic!("cannot bind to address {}: {}", binding_addr, err);
            }
        }

        Ok(())
    }

    fn setup_logging(&self) {
        let level = if self.configuration.quiet {
            tracing::Level::ERROR
        } else {
            tracing::Level::INFO
        };
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .with_ansi(true)
            .with_level(false)
            .init();
    }

    fn https_acceptor(&self) -> Option<TlsAcceptor> {
        if self.configuration.secure.is_some() {
            let conf_dup = self.configuration.clone();
            let cert_file = conf_dup.as_ref().clone().secure.unwrap().cert.unwrap();
            let key_file = conf_dup.as_ref().clone().secure.unwrap().key.unwrap();
            let certs = CertificateDer::pem_file_iter(cert_file)
                .unwrap()
                .map(|cert| cert.unwrap())
                .collect();
            let private_key = PrivateKeyDer::from_pem_file(key_file).unwrap();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .unwrap();
            Some(TlsAcceptor::from(Arc::new(config)))
        } else {
            None
        }
    }

    async fn run_with_graceful_shutdown(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // with graceful shutdown
        tokio::select! {
            _ = ctrl_c() => {
                info!("ctrl_c signal received, processing shutdown...");
                self.shutdown.write().await.shutdown();
            },

            _ = self.run_simply(Some(
                move ||{
                    let in_shutdown = self.shutdown.try_read();
                    in_shutdown.is_ok() && in_shutdown.unwrap().in_shutdown()
                })) => {
                debug!("main loop terminated");
            },
        }
        self.tracker.close();
        // TODO: add timeout to avoid waiting without a limit
        self.tracker.wait().await;
        info!("Shutting down processed. Bye!");
        Ok(())
    }

    async fn run_simply(
        &self,
        stop_check: Option<impl Fn() -> bool>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // without graceful shutdown
        let acceptor = self.https_acceptor();
        loop {
            let (tcp, _) = self.listener.as_ref().unwrap().accept().await?;
            let http = http1::Builder::new();
            let acceptor = acceptor.clone();
            let configuration = self.configuration.clone();

            self.tracker.clone().spawn(async move {
                let result = if configuration.secure.is_some() {
                    let stream = acceptor.clone().unwrap().accept(tcp).await;
                    match stream {
                        Ok(stream) => {
                            if let Err(err) = http
                                .serve_connection(TokioIo::new(stream), service_fn(file_service))
                                .await
                            {
                                Err(IoError::new(ErrorKind::ConnectionAborted, err.to_string()))
                            } else {
                                Ok(())
                            }
                        }
                        Err(err) => {
                            Err(IoError::new(ErrorKind::ConnectionAborted, err.to_string()))
                        }
                    }
                } else {
                    match http
                        .serve_connection(TokioIo::new(tcp), service_fn(file_service))
                        .await
                    {
                        Ok(_) => Ok(()),
                        Err(err) => {
                            Err(IoError::new(ErrorKind::ConnectionAborted, err.to_string()))
                        }
                    }
                };
                if let Err(err) = result {
                    error!("Error establish connection: {:?}", err);
                }
            });

            if let Some(ref check) = stop_check {
                if check() {
                    debug!("stopping loop...");
                    break Ok(());
                }
            }
        }
    }

    fn print_server_info(&self) {
        let protocol = self.configuration.protocol();
        let host = self.configuration.host.as_ref().unwrap();
        let port = self.configuration.port.unwrap();
        let protocol_colored = protocol.to_uppercase().green();
        info!("Server {} started.", VERSION_STRING.bright_blue());
        info!(
            "Serving {} on: {}",
            protocol_colored,
            format!(
                "{}://{}:{}",
                protocol,
                self.listener.as_ref().unwrap().local_addr().unwrap().ip(),
                port
            )
            .green()
        );
        if host == "0.0.0.0" {
            if let Some(ip) = local_address() {
                info!(
                    "Local Network {} on: {}",
                    protocol_colored,
                    format!("{}://{}:{}", protocol, ip, port).green()
                );
            }
        }
    }
}

struct Shutdown {
    in_shutdown: Arc<AtomicBool>,
}

impl Shutdown {
    pub(crate) fn new() -> Self {
        Self {
            in_shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// check in shutdown state or not
    pub(crate) fn in_shutdown(&self) -> bool {
        self.in_shutdown.load(Ordering::SeqCst)
    }

    /// update the status.
    pub(crate) fn shutdown(&mut self) {
        if self.in_shutdown.load(Ordering::SeqCst) {
            debug!("service is already in closing phase...");
            return;
        }
        self.in_shutdown.store(true, Ordering::SeqCst);
    }
}
