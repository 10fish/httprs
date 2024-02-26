use std::{
    env,
    error::Error,
    path::PathBuf,
};
use std::ffi::OsString;
use std::time::Duration;
use colored::Colorize;
use hyper::{
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::signal::ctrl_c;
use tokio::sync::broadcast::{channel, Receiver, Sender};
use tokio::time::sleep;
use tracing::{debug, info};
use super::{
    cli::{Config, ROOT_PATH_KEY},
    http::{file_service, local_address},
};

/// default binding host.
const DEFAULT_HOST: &'static str = "127.0.0.1";

/// default binding port.
const DEFAULT_PORT: u16 = 9900;

/// default serving directory.
const DEFAULT_ROOT_PATH: &'static str = ".";

pub struct Server {
    config: Config,
    listener: Option<TcpListener>,
    notifier: Sender<()>,
    shutdown: Shutdown
}

impl Server {
    pub fn new(config: Config) -> Self {
        let (notifier, receiver) = channel(1);
        Server {
            config,
            listener: None,
            notifier,
            shutdown: Shutdown::new(receiver),
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .with_ansi(true)
            .with_level(false)
            .init();

        let default_host = DEFAULT_HOST.to_string();
        let host = self.config.host.as_ref().unwrap_or(&default_host);
        let port = self.config.port.unwrap_or(DEFAULT_PORT);
        let default_root: OsString = PathBuf::from(DEFAULT_ROOT_PATH).into();
        let root_path = self.config.root.as_ref().unwrap_or(&default_root);
        env::set_var(ROOT_PATH_KEY, PathBuf::from(&root_path).as_path());
        debug!("Setting ROOT_PATH environment variable to {}", root_path.to_str().unwrap());

        let binding_addr = format!("{}:{}", host, port);
        let protocol = if self.config.tls { "HTTPS" } else { "HTTP" };

        if let Ok(listener) = TcpListener::bind(binding_addr).await {
            self.listener = Some(listener);
            // TODO: simplify printing
            println!(
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
                    println!(
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
                                        info!("Error serving connection: {:?}", err);
                                    }
                                } => {},
                                _ = self.shutdown.recv() => {
                                    println!("signal received...");
                                }
                            }
                            // if self.shutdown.in_shutdown() {
                            //     break;
                            // }
                        }
                    } => {},
                    _ = ctrl_c() => {
                        println!("received ctrl_c signal, exiting...");
                        self.notifier.send(()).unwrap();
                        let _ = sleep(Duration::from_secs(10)).await;
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
                            info!("Error serving connection: {:?}", err);
                        }
                    });
                }
            }
        }
        Ok(())
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