// Network sockets are required. CI explicitly runs these tests outside the sandbox.
#![cfg(feature = "cli")]

use httprs::{Configuration, Server};
use std::{
    io,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const ROOT: &str = env!("CARGO_MANIFEST_DIR");

async fn request(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    close: bool,
    cors: bool,
) -> Vec<u8> {
    let connection = if close { "close" } else { "keep-alive" };
    stream.write_all(format!("GET /static/index.html HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
        assert!(head.len() < 8192, "response headers exceeded test capacity");
    }
    let head = std::str::from_utf8(&head).unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    if cors {
        assert!(head.contains("access-control-allow-origin: *\r\n"));
    }
    let size = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    let mut body = vec![0; size];
    stream.read_exact(&mut body).await.unwrap();
    body
}

#[tokio::test]
#[ignore = "requires a loopback TCP socket"]
async fn tcp_shutdown_closes_an_established_keep_alive_connection() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = Server::try_new(Configuration {
            home: Some(ROOT.into()),
            ..Configuration::default()
        })
        .await
        .unwrap();
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(server.serve(listener, async move {
            shutdown.await.map_err(io::Error::other)
        }));

        let mut client = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            request(&mut client, false, false).await,
            include_bytes!("../static/index.html")
        );
        stop.send(()).unwrap();
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn cli_address(child: &mut ChildGuard) -> std::net::SocketAddr {
    // The announced address contains the actual OS-assigned port.
    let stdout = child.0.stdout.take().unwrap();
    tokio::task::spawn_blocking(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if let Some((_, addr)) = line.split_once("://") {
                return addr.trim().parse().unwrap();
            }
        }
        panic!("server exited before announcing its address");
    })
    .await
    .unwrap()
}

fn start_cli(args: &[&str]) -> ChildGuard {
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_httprs"))
            .args(["-H", "127.0.0.1", "-P", "0"])
            .args(args)
            .arg(ROOT)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

#[tokio::test]
#[ignore = "requires a loopback TCP socket"]
async fn cli_serves_http_over_an_ephemeral_port() {
    let config = std::path::Path::new(ROOT).join("tests/fixtures/server.toml");
    let mut child = start_cli(&["--cors", "--config", config.to_str().unwrap()]);
    tokio::time::timeout(TEST_TIMEOUT, async {
        let address = cli_address(&mut child).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            request(&mut stream, true, true).await,
            include_bytes!("../static/index.html")
        );
    })
    .await
    .unwrap();
}

#[cfg(feature = "tls")]
#[tokio::test]
#[ignore = "requires a loopback TCP socket"]
async fn cli_serves_https_with_certificate_verification() {
    use rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    };
    use std::{path::Path, sync::Arc};

    let cert = Path::new(ROOT).join("tests/fixtures/localhost-cert.pem");
    let key = Path::new(ROOT).join("tests/fixtures/localhost-key.pem");
    let mut child = start_cli(&[
        "--secure",
        "--cert",
        cert.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
    ]);
    tokio::time::timeout(TEST_TIMEOUT, async {
        let address = cli_address(&mut child).await;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(cert).unwrap())
            .unwrap();
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            request(&mut stream, true, false).await,
            include_bytes!("../static/index.html")
        );
    })
    .await
    .unwrap();
}
