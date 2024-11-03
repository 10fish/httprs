use std::{
    env,
    error::Error,
    path::PathBuf,
    ffi::OsString,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use colored::Colorize;
use hyper::{
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    net::TcpListener,
    signal::ctrl_c,
    sync::broadcast::{channel, Receiver, Sender},
};
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use crate::conf::{DEFAULT_HOST, DEFAULT_PORT, DEFAULT_ROOT_PATH};
use super::{
    conf::{Configuration, ROOT_PATH_KEY},
    http::{file_service, local_address},
    VERSION_STRING,
};

/// Simple http(s) server for static files
pub struct Server {
    listener: Option<TcpListener>,
    notifier: Sender<()>,
    /// The parsed server configuration
    pub configuration: Arc<Configuration>,
    shutdown: Arc<Mutex<Shutdown>>,
}

impl Server {
    pub async fn new(conf: Configuration) -> Self {
        match conf.merged().await {
            Ok(conf) => {
                let (notifier, receiver) = channel(1);
                Server {
                    listener: None,
                    notifier,
                    configuration: Arc::new(conf),
                    shutdown: Arc::new(Mutex::new(Shutdown::new(receiver))),
                }
            }
            Err(err) => {
                panic!("cannot parse parameters: {}", err);
            }
        }
    }

    pub async fn run(mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.setup_logging();

        let default_host = DEFAULT_HOST.to_string();
        let host = self.configuration.host.as_ref().unwrap_or(&default_host);
        let port = self.configuration.port.unwrap_or(DEFAULT_PORT);
        let default_root: OsString = PathBuf::from(DEFAULT_ROOT_PATH).into();
        let root_path = self.configuration.root.as_ref().unwrap_or(&default_root);
        env::set_var(ROOT_PATH_KEY, PathBuf::from(&root_path).as_path());
        debug!("Setting ROOT_PATH environment variable to {}", root_path.to_str().unwrap());
        debug!("Serving with configuration: {}", self.configuration.display());

        let binding_addr = format!("{}:{}", host, port);
        let protocol = self.configuration.protocol();

        match TcpListener::bind(binding_addr.clone()).await {
            Ok(listener) => {
                self.listener = Some(listener);
                let protocol_colored = protocol.to_uppercase().green();
                info!("Server {} started.",VERSION_STRING.bright_blue());
                // TODO: simplify printing
                info!(
                    "Serving {} on: {}",
                    protocol_colored,
                    format!(
                        "{}://{}:{}",
                        protocol,
                        self.listener.as_ref().unwrap().local_addr().unwrap().ip(),
                        port
                    ).green()
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

                if self.configuration.graceful_shutdown {
                    // with graceful shutdown
                    tokio::spawn(async move {
                        ctrl_c().await.unwrap();
                        debug!("ctrl_c signal received, finishing up...");
                        self.notifier.send(()).unwrap();
                    });
                    let shutdown = self.shutdown.clone();
                    tokio::select! {
                        _ = async move {
                            let mut lock = shutdown.lock().await;
                            lock.recv().await;
                            drop(lock);
                            debug!("shutdown signal received...");
                        } => {
                            // TODO: shutdown hook
                            info!("cleaning up...");
                        },

                        _ = async move {
                            loop {
                                let (tcp, _) = self.listener.as_ref().unwrap().accept().await.unwrap();

                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(TokioIo::new(tcp), service_fn(file_service))
                                    .await
                                {
                                    error!("Error serving connection: {:?}", err);
                                }
                                if self.shutdown.lock().await.in_shutdown() {
                                    break;
                                }
                            }
                        } => {},
                    }
                } else {
                    // without graceful shutdown
                    loop {
                        let (tcp, _) = self.listener.as_ref().unwrap().accept().await?;
                        tokio::spawn(async move {
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(TokioIo::new(tcp), service_fn(file_service))
                                .await
                            {
                                error!("Error serving connection: {:?}", err);
                            }
                        });
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
            tracing::Level::WARN
        } else {
            tracing::Level::DEBUG
        };
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .with_ansi(true)
            .with_level(false)
            .init();
    }
}

struct Shutdown {
    in_shutdown: Arc<AtomicBool>,
    notify: Receiver<()>,
}

impl Shutdown {
    /// Create a new `Shutdown` backed by the given `Receiver<_>`.
    pub(crate) fn new(notify: Receiver<()>) -> Self {
        Self {
            in_shutdown: Arc::new(AtomicBool::new(false)),
            notify,
        }
    }

    /// indicates if in shutdown process or not
    pub(crate) fn in_shutdown(&self) -> bool {
        self.in_shutdown.load(Ordering::SeqCst)
    }

    // Receive the shutdown notice, waiting if necessary.
    pub(crate) async fn recv(&mut self) {
        if self.in_shutdown.load(Ordering::SeqCst) {
            debug!("service is already in closing phase...");
            return;
        }

        let _ = self.notify.recv().await;
        self.in_shutdown.store(true, Ordering::SeqCst);
    }
}