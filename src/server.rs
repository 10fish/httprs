use std::{
    env,
    error::Error,
    path::PathBuf,
    ffi::OsString,
    time::Duration
};
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
    time::sleep
};
use tracing::{debug, error, info};
use crate::cli::{DEFAULT_HOST, DEFAULT_PORT, DEFAULT_ROOT_PATH};
use super::{
    cli::{Config, ROOT_PATH_KEY},
    http::{file_service, local_address},
    VERSION_STRING
};

pub struct Server {
    config: Config,
    listener: Option<TcpListener>,
    notifier: Sender<()>,
    shutdown: Shutdown,
}

impl Server {
    pub async fn new(config: Config) -> Self {
        match config.merged().await {
            Ok(config) => {
                let (notifier, receiver) = channel(1);
                Server {
                    config,
                    listener: None,
                    notifier,
                    shutdown: Shutdown::new(receiver),
                }
            }
            Err(err) => {
                panic!("cannot parse parameters: {}", err);
            }
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.setup_logging();

        let default_host = DEFAULT_HOST.to_string();
        let host = self.config.host.as_ref().unwrap_or(&default_host);
        let port = self.config.port.unwrap_or(DEFAULT_PORT);
        let default_root: OsString = PathBuf::from(DEFAULT_ROOT_PATH).into();
        let root_path = self.config.root.as_ref().unwrap_or(&default_root);
        env::set_var(ROOT_PATH_KEY, PathBuf::from(&root_path).as_path());
        debug!("Setting ROOT_PATH environment variable to {}", root_path.to_str().unwrap());
        debug!("Serving with configuration: {}", self.config.display());

        let binding_addr = format!("{}:{}", host, port);
        let protocol = if self.config.tls { "HTTPS" } else { "HTTP" };

        match TcpListener::bind(binding_addr.clone()).await {
            Ok(listener) => {
                self.listener = Some(listener);
                info!("Server {} started.",VERSION_STRING.bright_blue());
                // TODO: simplify printing
                info!(
                    "Serving {} on: {}",
                    protocol.green(),
                    format!(
                        "{}://{}",
                        protocol.to_lowercase(),
                        self.listener.as_ref().unwrap().local_addr().unwrap()
                    ).green()
                );
                if host == "0.0.0.0" {
                    if let Some(ip) = local_address() {
                        info!(
                            "Local Network {} on: {}",
                            protocol.green(),
                            format!("{}://{}:{}", protocol.to_lowercase(), ip, port).green()
                        );
                    }
                }

                if self.config.graceful_shutdown {
                    tokio::select! {
                    _ = async {
                        loop {
                            let (tcp, _) = self.listener.as_ref().unwrap().accept().await.unwrap();

                            tokio::select! {
                                _ = async move {
                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(TokioIo::new(tcp), service_fn(file_service))
                                    .await
                                    {
                                        error!("Error serving connection: {:?}", err);
                                    }
                                } => {},
                                _ = self.shutdown.recv() => {
                                    info!("shutdown signal received...");
                                }
                            }
                            // if self.shutdown.in_shutdown() {
                            //     break;
                            // }
                        }
                    } => {},
                    _ = ctrl_c() => {
                        info!("received ctrl_c signal, exiting...");
                        self.notifier.send(()).unwrap();
                        let _ = sleep(Duration::from_secs(5)).await;
                    }
                }
                } else {
                    // without graceful shutdown
                    loop {
                        let (tcp, _) = self.listener.as_ref().unwrap().accept().await?;
                        tokio::task::spawn(async move {
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
        let level = if self.config.quiet {
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
    in_shutdown: bool,
    notify: Receiver<()>,
}

impl Shutdown {
    /// Create a new `Shutdown` backed by the given `Receiver<_>`.
    pub(crate) fn new(notify: Receiver<()>) -> Self {
        Self {
            in_shutdown: false,
            notify,
        }
    }

    /// indicates if in shutdown process or not
    pub(crate) fn in_shutdown(&self) -> bool {
        self.in_shutdown
    }

    // Receive the shutdown notice, waiting if necessary.
    pub(crate) async fn recv(&mut self) {
        if self.in_shutdown {
            return;
        }

        let _ = self.notify.recv().await;
        self.in_shutdown = true;
    }
}