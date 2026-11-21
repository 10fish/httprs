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
representation size. File responses expose `Last-Modified` and a SHA-256
entity tag. Conditional requests can return `304` or `412`. An exact strong
`If-Range` match enables a partial response. A mismatch returns the complete
representation.

Computing the entity tag reads the file once with a fixed-size buffer before
the response body is streamed. Update served files through atomic replacement
so active transfers keep reading a consistent file. Directory listings display
modification times in GMT.

With the default features, the CLI accepts a TOML configuration file through
`--config`. Explicit
command-line arguments take precedence over TOML values, followed by defaults.
Path values are strings. Relative paths are resolved against the process's
working directory.

```toml
host = "127.0.0.1"
port = 9900
home = "./public"
cors = true

[secure]
secure = true
cert = "./tls/server.pem"
key = "./tls/server-key.pem"
```

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
shutdown. Run them with `cargo test --all-features --all-targets`. On a system
with loopback TCP access, run the CLI HTTP, TLS, and listener shutdown tests
with `cargo test --all-features --test connections -- --ignored`.

### Installation
Download pre-built binaries from [release](https://github.com/10fish/httprs/releases) page.

or install with `cargo` in terminal:
```shell
cargo install httprs
```

### Cargo features

Default builds include the command-line binary, TLS, and TOML configuration.
Library consumers can disable those defaults in their manifest.

```toml
httprs = { version = "0.2.6", default-features = false }
```

- `cli` enables the command-line binary and option parsing.
- `tls` enables HTTPS. Builds without it reject HTTPS configuration.
- `toml-config` enables configuration files and Serde deserialization for
  `Configuration`, `Secure`, and `Compression`. Builds without it reject
  `--config` and accept ordinary CLI arguments and Rust configuration values.
- `local-ips` enables printing each local IPv4 address when listening on
  all IPv4 interfaces and exposes the `get_all_local_ips` API.
- `compression` enables opt-in streaming gzip and deflate for files.
  Build with `cargo build --features compression` and run with
  `--compression gzip` or `--compression deflate`. Range requests prefer
  the identity representation when the client accepts it. Compressed files
  use separate weak entity tags.

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
# allow public, credential-free cross-origin access
httprs --cors
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
- [x] Strong validators for conditional requests and range resumption
    - [x] Date preconditions with `Last-Modified`
    - [x] Single and multipart byte ranges with `206` and `416`
    - [x] Entity tags and matching `If-Range` requests
- [x] CORS Support
- [x] Transmission Compression
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
