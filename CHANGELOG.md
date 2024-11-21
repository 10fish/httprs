# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Static file serving support
- TLS support
- Graceful shutdown improvements
- Configuration system refactoring

## [0.2.4] - 2024-11-03

### Added
- Support for custom HTTP headers
- Enhanced error handling for network failures
- New middleware system for request processing
- Refactored HTTP module
- Improved configuration system

### Changed
- Improved performance for large file transfers
- Updated dependency versions for security
- Refined logging format for better debugging

### Fixed
- Memory leak in long-running connections
- Race condition in concurrent request handling
- Invalid content-length header handling

## [0.2.3] - 2024-04-21

### Added
- Improved graceful shutdown logic
- CLI parameters parsing improvements
- Gzip and zstd compression algorithm RFCs

### Changed
- Refactored connection handling
- Optimized header parsing
- Updated documentation for new features

### Fixed
- TLS handshake issues
- Keep-alive connection bugs
- Request body parsing errors

## [0.2.2] - 2024-03-10

### Added
- Partial file access support
- HTTP RFC specification implementation
- Improved configuration printing info
- Content-type support for PDF files
- HTML string templates

### Changed
- Improved error messages
- Better TCP connection handling
- Updated API documentation
- Removed project version hardcode

### Fixed
- Buffer overflow in request parsing
- Memory usage optimization
- Connection leaks

## [0.2.1] - 2024-03-03

### Added
- Hotfix release
- Basic error handling improvements

### Fixed
- Empty response error
- Header parsing edge cases
- Connection timeout handling

## [0.2.0] - 2024-02-28

### Added
- Configuration file parsing
- Improved logging system
- Updated dependency constraints

### Changed
- Complete architecture overhaul
- Improved request routing
- Better error handling system
- Updated README roadmap

### Fixed
- Critical HTTP log errors
- Request logging improvements
- General code refactoring

## [0.1.0] - 2024-02-17

### Added
- Initial project structure and setup
- Basic HTTP server implementation
- Project documentation and README
- Development environment configuration
- GitHub workflow integration

### Changed
- Optimized project layout for better organization
- Improved workflow configuration

### Fixed
- Initial configuration issues
- Development environment setup problems

## [0.0.1] - 2024-02-10

### Added
- Project initialization
- Basic repository setup
- Initial commit with core files
- Meta information setup

[Unreleased]: https://github.com/username/httprs/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/username/httprs/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/username/httprs/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/username/httprs/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/username/httprs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/username/httprs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/username/httprs/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/username/httprs/releases/tag/v0.0.1
