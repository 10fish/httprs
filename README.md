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
- colored logs
- partial content support

### HTTP Server Standards & Benchmarks

#### Implemented Features

1. HTTP/1.1 Standard Support:
- ✅ Basic HTTP/1.1 protocol support
- ✅ Standard HTTP methods
- ✅ Standard HTTP headers
- ✅ Status codes

2. Performance Features:
- ✅ Asynchronous I/O (using tokio)
- ✅ Chunked file transfer (Range request support)
- ✅ Static file serving
- ✅ Directory listing
- ✅ Graceful shutdown

3. Security Features:
- ✅ HTTPS support (TLS/SSL)
- ✅ Basic error handling
- ✅ Request logging

4. Functional Features:
- ✅ MIME type support
- ✅ File system navigation
- ✅ Breadcrumb navigation
- ✅ Response time tracking

#### Planned Features

1. HTTP Standards:
- ⏳ HTTP/2 support
- ⏳ HTTP/3 support
- ⏳ WebSocket support
- ⏳ Compression support (gzip, deflate)

2. Performance Optimizations:
- ⏳ Connection pool management
- ⏳ Cache control
- ⏳ Compression transmission
- ⏳ Load balancing
- ⏳ Request rate limiting

3. Security Enhancements:
- ⏳ CORS support
- ⏳ Security headers (HSTS, etc.)
- ⏳ Request validation
- ⏳ Access control

4. Advanced Features:
- ⏳ Dynamic content generation
- ⏳ Session management
- ⏳ Authentication & Authorization
- ⏳ API support
- ⏳ Reverse proxy

5. Monitoring & Management:
- ⏳ Performance metrics collection
- ⏳ Health checks
- ⏳ Management interface
- ⏳ Hot reload configuration

### Installation
Download pre-built binaries from [release](https://github.com/10fish/httprs/releases) page.

or install with `cargo` in terminal:
```shell
cargo install httprs
```

### Usage
```shell
# quick start, running on http://127.0.0.1:9900
httprs
# run in insecure mode
httprs -H 0.0.0.0 -P 10000
# run in secure mode
httprs --secure --key /path/to/keyfile --cert /path/to/certfile
# run with graceful shutdown
httprs --graceful-shutdown
# help for more details
httprs --help
```

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
- [ ] Partial Request/Response Support
    - [ ] `If-Range` REQUEST Header
    - [ ] `If-Match` REQUEST Header
    - [x] `Range` REQUEST Header: when file size exceeds 50MB
    - [x] `Accept-Ranges` RESPONSE Header
    - [x] `Content-Range` RESPONSE Header
    - [x] CODE `206` - Partial Content
    - [ ] CODE `416` - Range Not Satisfiable
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
