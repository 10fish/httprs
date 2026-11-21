# httprs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/10fish/httprs/blob/main/LICENSE.txt)
[![CI Status](https://github.com/10fish/httprs/actions/workflows/ci.yml/badge.svg)](https://github.com/10fish/httprs/actions/workflows/ci.yml)
[![Audit](https://github.com/10fish/httprs/actions/workflows/audit.yml/badge.svg)](https://github.com/10fish/httprs/actions/workflows/audit.yml)
[![Dependency status](https://deps.rs/repo/github/10fish/httprs/status.svg)](https://deps.rs/repo/github/10fish/httprs)
[![Version](https://img.shields.io/crates/v/httprs.svg)](https://crates.io/crates/httprs)
[![Docs](https://docs.rs/httprs/badge.svg)](https://docs.rs/httprs)
[![Lines of Code](https://tokei.rs/b1/github/10fish/httprs)](https://github.com/10fish/httprs)

A fast simple command line http server tool. 

### Why httprs ?
If you're looking for a simple, fast, easy-to-use, generic-MIME-types-supporting 
and partial-content-supporting static file server like me, it might be an option.

*Warning: It is currently an experimental project. Use it at your own risk!!!*

### Features
the main features are as followings, and certainly more will be added:
- performant and essy to use
- multi-platform support
- multiple MIME support
- partial content support

### HTTP and library support

`httprs` serves files and directory listings over HTTP/1.1, with optional TLS.
It supports `GET`, `HEAD`, `OPTIONS`, full file streaming, and single or multipart
byte ranges for files of any size. Unsatisfiable ranges return `416` with the
representation size. File responses expose `Last-Modified` and support date
preconditions. The server uses the full representation for `If-Range` requests
because it has no strong validators. Directory listings display modification
times in GMT.

The CLI also accepts a TOML configuration file through `--config`. Explicit
command-line arguments take precedence over TOML values, followed by defaults.

Use `StaticFiles` to integrate file serving into an existing HTTP service.
Initialize it once and share it across requests.

```rust
use httprs::{StaticBody, StaticFiles};
use hyper::{Request, Response};

async fn serve_static(files: &StaticFiles, request: Request<()>) -> Response<StaticBody> {
    files.handle(request).await
}

// Initialize once with StaticFiles::new(".").await? and pass it to the handler.
```

Use `Server::try_new` and `Server::serve` to run a standalone instance on a
caller-provided listener with a caller-provided shutdown signal. The CLI
installs its logging subscriber. Embedded applications configure their own
logging.

The integration tests cover response status, headers, and body for regular,
partial, and conditional requests. The HTTP/1.1 connection test runs over an
in-memory duplex connection and checks pipelined responses and graceful
shutdown. Run them with `cargo test --all-targets`.

### Installation
Download pre-built binaries from [release](https://github.com/10fish/httprs/releases) page.

or install with `cargo` in terminal:
```shell
cargo install httprs
```

### Cargo features

Default builds include the command-line binary, TLS, and local IPv4 address
discovery. Library consumers can disable those defaults in their manifest.

```toml
httprs = { version = "0.2.5", default-features = false }
```

- `cli` enables the command-line binary and option parsing.
- `tls` enables HTTPS. Builds without it reject HTTPS configuration.
- `local-ips` enables local IPv4 address discovery and the `get_all_local_ips` API.

```sh
cargo build --release --no-default-features --features cli
```

### Usage
```shell
# quick start, running on all network interfaces (0.0.0.0:9900)
httprs
# run on specific local IP address
httprs -H 192.168.10.1
# run in secure mode
httprs --secure --key /path/to/keyfile --cert /path/to/certfile
# run with graceful shutdown
httprs --graceful-shutdown
# help for more details
httprs --help
```

> Note: By default, the server binds to `0.0.0.0` which means it will listen on all available network interfaces. This makes the server accessible from other devices on the network. If you want to restrict access to localhost only, use `-H 127.0.0.1`.

### Roadmap

- [ ] Logging
    - [x] Request/Response Logging
    - [x] Silent Mode
    - [ ] Logging Level
    - [ ] Logging Output into File
- [ ] File Browser Support
    - [x] Generic File Type Supporting: image/text/video/binary
    - [ ] File Metadata Details
      - [x] File Size
      - [x] Last Modified
      - [ ] More if Necessary
    - [ ] File List Ordering
    - [ ] Content-Type Customization
- [ ] Multiplatform Support
    - [x] macOS
    - [x] Linux
    - [x] Windows
- [x] HTTPS/TLS Transmission Encryption
- [ ] Strong validators for conditional requests and range resumption
    - [x] Date preconditions with `Last-Modified`
    - [x] Single and multipart byte ranges with `206` and `416`
    - [ ] Entity tags and matching `If-Range` requests
- [ ] CORS Support
- [ ] Transmission Compression
- [ ] Authentication
  - [ ] Simple Basic
  - [ ] Token Based
- [x] Graceful Shutdown
- [ ] Proxy
- [ ] Themes and Appearances Customization

### How to contribute
Any advice is welcomed and feel free to make a fork and push your own code.

### Acknowledgements
Thanks to those who are inspiring me, supporting me, providing me with ideas, advice, solutions, and all users who bear much using this.
- [http-server-rs/http-server](https://github.com/http-server-rs/http-server) for initial thoughts.
- [egmkang/local_ipaddress](https://github.com/egmkang/local_ipaddress) for resolving intranet binding IP addresses.

### Licenses

MIT License
