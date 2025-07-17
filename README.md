# ICY2-SERVER - Digital Network Audio Server

[![Build Status](https://github.com/davestj/icy2-server/workflows/Build%20and%20Test/badge.svg)](https://github.com/davestj/icy2-server/actions)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Version](https://img.shields.io/badge/Version-1.1.1-green.svg)](https://github.com/davestj/icy2-server/releases)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x64-orange.svg)](https://github.com/davestj/icy2-server)

## 🎵 Project Overview

**ICY2-SERVER** is a next-generation Digital Network Audio Server (DNAS) that combines the best of SHOUTcast v1/v2 and Icecast2 protocols into a unified hybrid streaming platform. Built from the ground up in C++ for maximum performance and reliability.

### 🚀 Key Features

- **Hybrid Protocol Support**: Full SHOUTcast v1/v2 + Icecast2 compatibility
- **ICY 2.0 Metadata Protocol**: Advanced metadata support with social integration
- **SSL/TLS Streaming**: Secure HTTPS audio/video streaming with OpenSSL
- **Token-Based Authentication**: HTTP Bearer token security system
- **Multi-Platform**: Native Linux (Debian 12+) and Windows 11 Pro support
- **YAML Configuration**: Modern, human-readable configuration system
- **YP Directory Integration**: Multi-host directory listing support
- **PHP-FPM Integration**: Embedded PHP support like nginx
- **Real-time API**: JSON REST endpoints for monitoring and control

## 📁 Project Structure

```
/var/www/mcaster1.com/DNAS/icy2-server/
├── README.md                    # This file
├── LICENSE.md                   # MIT License
├── bootstrap.sh                 # Quick setup script
├── configure.ac                 # Autotools configuration
├── Makefile.am                  # Automake configuration
├── autogen.sh                   # Autotools bootstrap
├── config/
│   └── mcaster1.yaml           # Default server configuration
├── src/
│   ├── main.cpp                # Application entry point
│   ├── server.cpp              # Core HTTP/ICY server
│   ├── icy_handler.cpp         # ICY protocol handler
│   ├── auth_token.cpp          # Token authentication
│   ├── config_parser.cpp       # YAML config parser
│   ├── ssl_manager.cpp         # SSL certificate management
│   ├── php_handler.cpp         # PHP-FPM integration
│   └── helper.cpp              # API helper functions
├── include/
│   ├── icy2_server.h           # Public library header
│   ├── server.h                # Server class definitions
│   ├── icy_handler.h           # ICY protocol definitions
│   ├── auth_token.h            # Authentication headers
│   ├── config_parser.h         # Configuration structures
│   ├── ssl_manager.h           # SSL management
│   ├── php_handler.h           # PHP integration
│   └── helper.h                # Utility functions
├── ssl/
│   ├── selfsigned.crt          # Generated SSL certificate
│   ├── selfsigned.key          # Generated SSL private key
│   └── other-ss-chain.crt      # Certificate chain
├── logs/
│   ├── error.log               # Error logging
│   ├── access.log              # Access logging
│   ├── security.log            # Security events
│   └── php_errors.log          # PHP error logging
└── .github/
    └── workflows/
        └── dev.yaml            # GitHub Actions CI/CD
```

## 🛠️ Quick Start

### Prerequisites

```bash
# Debian 12 / Ubuntu 22.04+ requirements
sudo apt update && sudo apt install -y \
    build-essential \
    automake \
    autoconf \
    libtool \
    pkg-config \
    libssl-dev \
    libyaml-cpp-dev \
    libfcgi-dev \
    php8.2-fpm \
    git
```

### Build and Install

```bash
# Clone the repository
git clone git@github.com:davestj/icy2-server.git
cd icy2-server

# Bootstrap the project
./bootstrap.sh

# Configure and build
./autogen.sh
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
```

### Quick Configuration

```bash
# Copy default configuration
sudo cp config/mcaster1.yaml /etc/icy2-server/
sudo mkdir -p /var/www/mcaster1.com/DNAS/icy2-server/{ssl,logs}

# Generate self-signed SSL certificates
sudo icy2-server --generate-ssl

# Test configuration
icy2-server --test-mode --config=/etc/icy2-server/mcaster1.yaml
```

## 🎛️ Usage

### Basic Server Start

```bash
# Start with default configuration
icy2-server

# Custom IP and port
icy2-server --ip=0.0.0.0 --port=5656

# Debug mode with verbose logging
icy2-server --debug=4 --ip=127.0.0.1 --port=3334

# Test mode (validate config only)
icy2-server --test-mode
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ip=<address>` | Bind IP address | `0.0.0.0` |
| `--port=<port>` | HTTP port number | `3334` |
| `--debug=<level>` | Debug level (1-4) | `1` |
| `--test-mode` | Validate config only | `false` |
| `--config=<path>` | Configuration file | `/etc/icy2-server/mcaster1.yaml` |
| `--generate-ssl` | Generate SSL certificates | `false` |
| `--daemon` | Run as daemon | `false` |

## 🔌 API Endpoints

### Server Status API

```bash
# Get server information
curl http://localhost:3334/api/v1/status

# Response example:
{
  "server_id": "icy2-dnas-001",
  "version": "1.1.1",
  "build_date": "2025-07-16T12:00:00Z",
  "ip_address": "0.0.0.0",
  "port": 3334,
  "ssl_enabled": true,
  "uptime_seconds": 3600,
  "active_connections": 42,
  "system_info": {
    "os": "Linux",
    "kernel": "6.1.0-9-amd64",
    "architecture": "x86_64",
    "memory_mb": 8192,
    "cpu_cores": 4
  }
}
```

## 🔐 ICY 2.0 Protocol Support

This server implements the full ICY-META v2.1+ specification including:

- **Legacy ICY 1.x compatibility** for existing encoders
- **Advanced metadata support** with hashtags, emojis, social integration
- **Video streaming metadata** for multi-platform content
- **Token-based authentication** with JWT support
- **Certificate verification** system for trusted streams

### Example ICY 2.0 Headers

```http
icy-name: Future Beats FM
icy-meta-version: 2.1
icy-meta-hashtag-array: ["#electronica", "#ambient", "#chillout"]
icy-meta-emoji: 🎵🌙✨
icy-meta-social-twitter: @futurebeats
icy-auth-token-key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 🏗️ Development

### Building from Source

```bash
# Development build with debug symbols
./configure --enable-debug --prefix=/usr/local
make clean && make -j$(nproc)

# Library development
make lib  # Builds /usr/lib64/icy2-server.lib
make headers  # Installs /usr/include/icy2_server.h
```

### Running Tests

```bash
# Configuration validation
icy2-server --test-mode

# Integration tests
make test

# Memory leak detection
valgrind --leak-check=full ./icy2-server --debug=1
```

## 📦 Releases

Current stable release: **v1.1.1**

Download the latest release:
- [Source Code (tar.gz)](https://github.com/davestj/icy2-server/releases/latest/download/icy2-server-v1.1.1.tar.gz)
- [Binary Package (Debian)](https://github.com/davestj/icy2-server/releases/latest/download/icy2-server_1.1.1_amd64.deb)

### Release History

- **v1.1.1** - Initial stable release with full ICY2 protocol support
- **v1.1.0** - Beta release with SSL and authentication
- **v1.0.0** - Alpha release with basic HTTP server

## 🤝 Contributing

I welcome contributions to improve ICY2-SERVER! Here's how you can help:

1. **Fork** the repository
2. **Create** your feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow the C++17 standard
- Use first-person comments in code
- Maintain backwards compatibility
- Write comprehensive tests
- Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## 📞 Support & Contact

- **Website**: [mcaster1.com](https://mcaster1.com)
- **Email**: davestj@gmail.com
- **GitHub Issues**: [Report Issues](https://github.com/davestj/icy2-server/issues)
- **Documentation**: [Wiki](https://github.com/davestj/icy2-server/wiki)

## 🎯 Roadmap

### Upcoming Features

- **Windows 11 Pro native build** with Visual Studio 2022
- **Advanced load balancing** for high-traffic streams  
- **WebRTC integration** for real-time streaming
- **Machine learning metadata** enhancement
- **Docker containerization** for easy deployment
- **Kubernetes helm charts** for cloud deployment

### Current Development Status

- ✅ Core HTTP/ICY server implementation
- ✅ SSL/TLS support with certificate generation
- ✅ YAML configuration system
- ✅ Token-based authentication
- ✅ PHP-FPM integration
- 🔄 YP directory integration (in progress)
- 🔄 Advanced metadata processing (in progress)
- ⏳ Web admin interface (planned)
- ⏳ Client application (planned)

---

**Built with ❤️ by David St. John** | **Powered by ICY2 Protocol Specification**
