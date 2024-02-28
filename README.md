# httprs

[![License (MIT)](https://img.shields.io/crates/l/httprs)](https://github.com/10fish/httprs/blob/main/LICENSE)
[![CI Status](https://github.com/10fish/httprs/actions/workflows/ci.yml/badge.svg)](https://github.com/10fish/httprs/actions/workflows/ci.yml)
[![Audit](https://github.com/10fish/httprs/actions/workflows/audit.yml/badge.svg)](https://github.com/10fish/httprs/actions/workflows/audit.yml)
[![Dependency status](https://deps.rs/repo/github/10fish/httprs/status.svg)](https://deps.rs/repo/github/10fish/httprs)
[![Crates.io](https://img.shields.io/crates/v/httprs)](https://crates.io/crates/httprs)
[![docs.rs](https://img.shields.io/badge/docs-website-blue)](https://docs.rs/httprs/)
[![Lines of code](https://tokei.rs/b1/github/10fish/httprs?category=lines)](https://github.com/10fish/httprs)

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

### Installation
Download pre-built binaries from [release](https://github.com/10fish/httprs/releases) page.

or install with `cargo` in terminal:
```shell
cargo install httprs
```
### Roadmap

- [ ] Logging
    - [x] Request/Response Logging
    - [x] Silent Mode
    - [ ] Logging Level
    - [ ] Logging Output into File
- [ ] File Type Support
    - [ ] Generic File Type Supporting: image/text/video/binary
    - [ ] Content-Type Customization
- [ ] Multiplatform Support
    - [x] macOS
    - [x] Linux
    - [ ] Windows
- [ ] HTTP Encryption
- [ ] Partial Request/Response Support
    - [ ] `If-Range` REQUEST Header
    - [ ] `If-Match` REQUEST Header
    - [ ] `Range` REQUEST Header
    - [ ] `Accept-Ranges` RESPONSE Header
    - [ ] `Content-Range` RESPONSE Header
    - [ ] CODE `206` - Partial Content
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

### Licenses

MIT License
