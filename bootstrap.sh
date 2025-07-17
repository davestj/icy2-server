#!/bin/bash
# File: bootstrap.sh
# Path: /var/www/mcaster1.com/DNAS/icy2-server/bootstrap.sh
# Author: davestj@gmail.com (David St. John)
# Created: 2025-07-16
# Purpose: I created this bootstrap script to automatically set up the complete development
#          environment for ICY2-SERVER from scratch. This script handles all dependencies,
#          directory structure creation, SSL certificate generation, and initial configuration.
# 
# Reason: I need a single command that can prepare any Debian 12+ or Ubuntu 22+ system for 
#         ICY2-SERVER development and deployment, ensuring consistency across environments.
#
# Changelog:
# 2025-07-16 - Initial bootstrap script with full environment setup
# 2025-07-16 - Added SSL certificate generation and directory structure
# 2025-07-16 - Implemented dependency validation and error handling
# 2025-07-16 - Added PHP-FPM configuration and service setup
# 2025-07-16 - Integrated YAML config generation and validation
# 2025-07-16 - Fixed PHP version detection for Ubuntu 24.04 (PHP 8.3) vs Debian 12 (PHP 8.2)
#
# Next Dev Feature: I plan to add Windows PowerShell equivalent and Docker container setup
# Git Commit: fix: implement dynamic PHP version detection for Ubuntu 24.04 and Debian 12 compatibility
#
# TODO: Add Windows support, container builds, automated testing setup

set -euo pipefail  # I want strict error handling throughout the script

# I'm defining all the global variables for the project setup
PROJECT_NAME="icy2-server"
PROJECT_ROOT="/var/www/mcaster1.com/DNAS/icy2-server"
SSL_DIR="${PROJECT_ROOT}/ssl"
LOG_DIR="${PROJECT_ROOT}/logs"
CONFIG_DIR="${PROJECT_ROOT}/config"
SRC_DIR="${PROJECT_ROOT}/src"
INCLUDE_DIR="${PROJECT_ROOT}/include"
BUILD_DIR="${PROJECT_ROOT}/build"
INSTALL_PREFIX="/usr/local"
LIB_INSTALL_PATH="/usr/lib64"
HEADER_INSTALL_PATH="/usr/include"

# I'm defining variables for PHP version detection
PHP_VERSION=""
PHP_SOCKET_PATH=""
PHP_FPM_POOL_DIR=""

# I'm setting up color codes for better user experience
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# I'm creating helper functions for consistent logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# I'm creating a function to check if we're running as root when needed
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "I'm running as root. This is only needed for system-wide installation."
        read -p "Continue as root? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "I'm exiting. Run without sudo for development setup."
            exit 1
        fi
    fi
}

# I'm creating a function to detect the correct PHP version for the OS
detect_php_version() {
    log_info "I'm detecting the available PHP version..."
    
    # I'm checking for available PHP versions in order of preference
    local php_versions=("8.3" "8.2" "8.1" "8.0")
    
    for version in "${php_versions[@]}"; do
        if apt-cache show "php${version}-fpm" >/dev/null 2>&1; then
            PHP_VERSION="$version"
            PHP_SOCKET_PATH="/run/php/php${version}-fpm-icy2.sock"
            PHP_FPM_POOL_DIR="/etc/php/${version}/fpm/pool.d"
            log_success "I detected PHP ${version} is available"
            return 0
        fi
    done
    
    log_error "I cannot find any compatible PHP version (8.0-8.3)"
    exit 1
}

# I'm creating a function to compare version numbers without external dependencies
version_compare() {
    local version1=$1
    local operator=$2
    local version2=$3
    
    # I'm converting version strings to comparable integers
    local v1_major=$(echo "$version1" | cut -d. -f1)
    local v1_minor=$(echo "$version1" | cut -d. -f2 2>/dev/null || echo "0")
    local v2_major=$(echo "$version2" | cut -d. -f1)
    local v2_minor=$(echo "$version2" | cut -d. -f2 2>/dev/null || echo "0")
    
    # I'm creating comparable version numbers
    local v1_num=$((v1_major * 100 + v1_minor))
    local v2_num=$((v2_major * 100 + v2_minor))
    
    case $operator in
        ">=")
            [[ $v1_num -ge $v2_num ]]
            ;;
        ">")
            [[ $v1_num -gt $v2_num ]]
            ;;
        "<=")
            [[ $v1_num -le $v2_num ]]
            ;;
        "<")
            [[ $v1_num -lt $v2_num ]]
            ;;
        "="|"==")
            [[ $v1_num -eq $v2_num ]]
            ;;
        *)
            return 1
            ;;
    esac
}

# I'm creating a function to detect the operating system
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
        log_info "I detected OS: $OS $VERSION"
        
        case $OS in
            *"Debian"*)
                if version_compare "$VERSION" ">=" "12"; then
                    log_success "I confirmed Debian 12+ compatibility"
                    PACKAGE_MANAGER="apt"
                else
                    log_error "I require Debian 12 or newer. Current version: $VERSION"
                    exit 1
                fi
                ;;
            *"Ubuntu"*)
                if version_compare "$VERSION" ">=" "22.04"; then
                    log_success "I confirmed Ubuntu 22.04+ compatibility"
                    PACKAGE_MANAGER="apt"
                else
                    log_error "I require Ubuntu 22.04 or newer. Current version: $VERSION"
                    exit 1
                fi
                ;;
            *)
                log_warning "I haven't tested on $OS. Proceeding with caution..."
                PACKAGE_MANAGER="apt"
                ;;
        esac
    else
        log_error "I cannot detect the operating system"
        exit 1
    fi
}

# I'm creating a function to install all required dependencies
install_dependencies() {
    log_info "I'm updating package repositories..."
    sudo apt update

    log_info "I'm installing build dependencies..."
    
    # I'm defining OS-specific package lists
    local base_packages=(
        build-essential
        automake
        autoconf
        autoconf-archive
        libtool
        pkg-config
        libssl-dev
        libyaml-cpp-dev
        libfcgi-dev
        git
        curl
        jq
        bc
        openssl
        valgrind
        cppcheck
        clang-format
    )
    
    # I'm adding OS-specific FCGI library packages
    local fcgi_packages=()
    case $OS in
        *"Debian"*)
            fcgi_packages=(libfcgi0ldbl)
            ;;
        *"Ubuntu"*)
            fcgi_packages=(libfcgi0t64)
            ;;
        *)
            # I'm defaulting to Debian packages for unknown systems
            fcgi_packages=(libfcgi0ldbl)
            ;;
    esac
    
    # I'm combining base packages with OS-specific packages
    local all_packages=("${base_packages[@]}" "${fcgi_packages[@]}")
    
    # I'm installing all packages at once
    sudo apt install -y "${all_packages[@]}"

    # I'm installing PHP packages using the detected version
    log_info "I'm installing PHP ${PHP_VERSION} packages..."
    sudo apt install -y \
        "php${PHP_VERSION}-fpm" \
        "php${PHP_VERSION}-dev" \
        "php${PHP_VERSION}-cli" \
        "php${PHP_VERSION}-mbstring" \
        "php${PHP_VERSION}-curl" \
        "php${PHP_VERSION}-xml" \
        "php${PHP_VERSION}-zip"

    log_success "I successfully installed all dependencies"
}

# I'm creating the complete directory structure
create_directory_structure() {
    log_info "I'm creating the project directory structure..."
    
    # I'm creating all necessary directories with proper permissions
    mkdir -p "$PROJECT_ROOT"
    mkdir -p "$SSL_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$SRC_DIR"
    mkdir -p "$INCLUDE_DIR"
    mkdir -p "$BUILD_DIR"
    mkdir -p "$PROJECT_ROOT/.github/workflows"
    mkdir -p "$PROJECT_ROOT/www/admin"
    mkdir -p "$PROJECT_ROOT/www/public"
    mkdir -p "$PROJECT_ROOT/tests"
    
    # I'm setting appropriate permissions for security
    chmod 755 "$PROJECT_ROOT"
    chmod 750 "$SSL_DIR"      # I want restricted access to SSL certificates
    chmod 755 "$LOG_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$SRC_DIR"
    chmod 755 "$INCLUDE_DIR"
    
    log_success "I created all project directories"
}

# I'm generating self-signed SSL certificates for development
generate_ssl_certificates() {
    log_info "I'm generating self-signed SSL certificates..."
    
    if [[ -f "$SSL_DIR/selfsigned.crt" ]] && [[ -f "$SSL_DIR/selfsigned.key" ]]; then
        log_warning "I found existing SSL certificates. Backing them up..."
        mv "$SSL_DIR/selfsigned.crt" "$SSL_DIR/selfsigned.crt.backup.$(date +%s)"
        mv "$SSL_DIR/selfsigned.key" "$SSL_DIR/selfsigned.key.backup.$(date +%s)"
    fi
    
    # I'm creating a certificate configuration file
    cat > "$SSL_DIR/cert.conf" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=Washington
L=Kirkland
O=MCaster1 DNAS
OU=ICY2-SERVER Development
CN=localhost
emailAddress=davestj@gmail.com

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = mcaster1.com
DNS.3 = *.mcaster1.com
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    # I'm generating the private key and certificate without password protection
    openssl req -new -x509 -nodes -keyout "$SSL_DIR/selfsigned.key" \
        -out "$SSL_DIR/selfsigned.crt" \
        -days 365 \
        -config "$SSL_DIR/cert.conf"
    
    # I'm setting restrictive permissions on the private key
    chmod 600 "$SSL_DIR/selfsigned.key"
    chmod 644 "$SSL_DIR/selfsigned.crt"
    
    # I'm creating a certificate chain file (self-signed, so it's the same)
    cp "$SSL_DIR/selfsigned.crt" "$SSL_DIR/other-ss-chain.crt"
    
    log_success "I generated SSL certificates successfully"
}

# I'm configuring PHP-FPM for integration with the server
configure_php_fpm() {
    log_info "I'm configuring PHP-FPM ${PHP_VERSION} for ICY2-SERVER integration..."
    
    # I'm creating a custom PHP-FPM pool configuration
    cat > "/tmp/icy2-server.conf" << EOF
; ICY2-SERVER PHP-FPM Pool Configuration
; I created this pool specifically for ICY2-SERVER web interface
[icy2-server]
user = www-data
group = www-data
listen = ${PHP_SOCKET_PATH}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500

; I'm setting PHP configuration for development
php_admin_value[error_reporting] = E_ALL
php_admin_value[display_errors] = On
php_admin_value[display_startup_errors] = On
php_admin_value[log_errors] = On
php_admin_value[error_log] = $LOG_DIR/php_errors.log
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 300

; I'm setting environment variables for the application
env[ENVIRONMENT] = development
env[APP_NAME] = "ICY2-SERVER"
env[SITE_ROOT] = "$PROJECT_ROOT/www"
env[CONFIG_FILE] = "$CONFIG_DIR/mcaster1.yaml"
env[PHP_VERSION] = "${PHP_VERSION}"
EOF

    # I'm installing the PHP-FPM pool configuration
    sudo mv "/tmp/icy2-server.conf" "${PHP_FPM_POOL_DIR}/"
    
    # I'm restarting PHP-FPM to load the new configuration
    sudo systemctl restart "php${PHP_VERSION}-fpm"
    sudo systemctl enable "php${PHP_VERSION}-fpm"
    
    log_success "I configured PHP-FPM ${PHP_VERSION} successfully"
}

# I'm creating the default YAML configuration file
create_default_config() {
    log_info "I'm creating the default YAML configuration..."
    
    cat > "$CONFIG_DIR/mcaster1.yaml" << EOF
metadata:
  project: mcaster1.com / mcaster1DNSA - ICY2-SERVER
  version: 1.1.1
  merged_by: davestj
  merged_on: '2025-07-16T12:00:00Z'
  notes: Unified configuration for DNAS hybrid server with full examples and comments.

server:
  name: ICY2 - DNAS SPEC Server v1.1.1
  description: Digital Network Audio Server - Shoutcast/Icecast Clone
  version: 1.1.1
  admin_email: admin@mcaster1.com

network:
  http_port: 3334
  https_port: 8443
  admin_port: 8001
  bind_address: 0.0.0.0
  max_connections: 1000
  connection_timeout: 30
  keepalive_timeout: 15

ssl:
  enabled: true
  cert_file: ssl/selfsigned.crt
  key_file: ssl/selfsigned.key
  chain_file: ssl/other-ss-chain.crt
  protocols:
  - TLSv1.2
  - TLSv1.3
  cipher_suites: ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS

authentication:
  enabled: true
  token_secret: your-secret-key-change-this-in-production
  token_expiration: 24
  allow_anonymous_listeners: true
  require_auth_for_broadcast: true
  max_failed_attempts: 5
  lockout_duration: 30

mount_points:
  /stream:
    name: Main Stream
    description: Primary streaming mount point
    max_listeners: 100
    public: true
    allow_recording: false
    require_auth: true
    content_types:
    - audio/mpeg
    - audio/aac
    - audio/ogg
    min_bitrate: 32
    max_bitrate: 320
    metadata:
      enabled: true
      interval: 8192

icy_protocol:
  legacy_support: true
  icy2_support: true
  default_metaint: 8192
  server_name: DNAS/1.1.1
  icy2_features:
    hashtag_arrays: true
    emoji_support: true
    social_integration: true
    json_metadata: true

logging:
  level: INFO
  file_logging:
    enabled: true
    log_dir: logs
    error_file: logs/error.log
    access_log: logs/access.log
    security_log: logs/security.log
    max_size_mb: 100
    max_files: 10
    timestamps: true
    format: json

php_fpm:
  enabled: true
  socket_path: ${PHP_SOCKET_PATH}
  document_root: www
  index_files:
  - index.php
  - index.html
  timeout: 90
  buffer_size: 64k
  php_version: "${PHP_VERSION}"

api:
  enabled: true
  base_url: /api/v1
  auth_token_required: false
  rate_limit_per_minute: 120
  output_format: json
EOF

    log_success "I created the default configuration file"
}

# I'm creating the autotools configuration files
create_autotools_config() {
    log_info "I'm creating autotools configuration files..."
    
    # I'm creating configure.ac for autoconf
    cat > "$PROJECT_ROOT/configure.ac" << 'EOF'
# ICY2-SERVER Autoconf Configuration
# I created this autoconf script to handle cross-platform builds and dependency detection
AC_INIT([icy2-server], [1.1.1], [davestj@gmail.com], [icy2-server], [https://mcaster1.com])
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# I'm checking for required programs
AC_PROG_CXX
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

# I'm setting C++17 standard
AX_CXX_COMPILE_STDCXX_17([noext], [mandatory])

# I'm checking for required libraries
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0])
PKG_CHECK_MODULES([YAML_CPP], [yaml-cpp >= 0.6.0])

# I'm checking for FCGI library
AC_CHECK_LIB([fcgi], [FCGI_Accept], [], [
    AC_MSG_ERROR([I cannot find the FCGI library. Please install libfcgi-dev])
])

# I'm checking for required headers
AC_CHECK_HEADERS([fcgiapp.h], [], [
    AC_MSG_ERROR([I cannot find fcgiapp.h. Please install libfcgi-dev])
])

# I'm setting up conditional builds
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debug build]),
    [debug=$enableval], [debug=no])

AM_CONDITIONAL([DEBUG], [test "x$debug" = "xyes"])

AC_ARG_ENABLE([ssl],
    AS_HELP_STRING([--enable-ssl], [Enable SSL support]),
    [ssl=$enableval], [ssl=yes])

AM_CONDITIONAL([SSL], [test "x$ssl" = "xyes"])

AC_ARG_ENABLE([php-fpm],
    AS_HELP_STRING([--enable-php-fmp], [Enable PHP-FPM support]),
    [php_fpm=$enableval], [php_fmp=yes])

AM_CONDITIONAL([PHP_FPM], [test "x$php_fpm" = "xyes"])

# I'm generating output files
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT

echo "
ICY2-SERVER Configuration Summary:
  Version:      ${VERSION}
  Debug build:  ${debug}
  SSL support:  ${ssl}
  PHP-FPM:      ${php_fmp}
  
  CC:           ${CC}
  CXX:          ${CXX}
  CFLAGS:       ${CFLAGS}
  CXXFLAGS:     ${CXXFLAGS}
  
I have successfully configured the build system.
Run 'make' to build ICY2-SERVER.
"
EOF

    # I'm creating the top-level Makefile.am
    cat > "$PROJECT_ROOT/Makefile.am" << 'EOF'
# ICY2-SERVER Top-level Makefile
# I created this makefile to coordinate the build of all components
SUBDIRS = src

EXTRA_DIST = \
    README.md \
    LICENSE.md \
    bootstrap.sh \
    config/mcaster1.yaml \
    .github/workflows/dev.yaml

# I'm defining custom targets for library building
lib: all
	@echo "I'm building the static library..."
	cd src && $(MAKE) lib

install-lib: lib
	@echo "I'm installing the library and headers..."
	$(INSTALL) -d $(DESTDIR)$(libdir)
	$(INSTALL) -d $(DESTDIR)$(includedir)
	$(INSTALL) -m 644 src/libicy2-server.a $(DESTDIR)$(libdir)/
	$(INSTALL) -m 644 include/icy2_server.h $(DESTDIR)$(includedir)/

# I'm adding a target for SSL certificate generation
generate-ssl:
	@echo "I'm generating SSL certificates..."
	./bootstrap.sh ssl-only

# I'm adding a configuration test target
test-config:
	@echo "I'm testing the configuration..."
	./src/icy2-server --test-mode

.PHONY: lib install-lib generate-ssl test-config
EOF

    # I'm creating autogen.sh for bootstrapping autotools
    cat > "$PROJECT_ROOT/autogen.sh" << 'EOF'
#!/bin/bash
# I created this script to bootstrap the autotools build system
set -e

echo "I'm running autoreconf to generate build files..."
autoreconf -fiv

echo "I have successfully bootstrapped the build system."
echo "Run './configure' to configure the build."
EOF

    chmod +x "$PROJECT_ROOT/autogen.sh"
    
    log_success "I created autotools configuration files"
}

# I'm creating initial log files with proper permissions
initialize_logging() {
    log_info "I'm initializing log files..."
    
    touch "$LOG_DIR/error.log"
    touch "$LOG_DIR/access.log"
    touch "$LOG_DIR/security.log"
    touch "$LOG_DIR/php_errors.log"
    
    # I'm setting appropriate permissions for log files
    chmod 644 "$LOG_DIR"/*.log
    
    log_success "I initialized logging system"
}

# I'm creating a simple validation function
validate_setup() {
    log_info "I'm validating the bootstrap setup..."
    
    local errors=0
    
    # I'm checking directory structure
    for dir in "$SSL_DIR" "$LOG_DIR" "$CONFIG_DIR" "$SRC_DIR" "$INCLUDE_DIR"; do
        if [[ ! -d "$dir" ]]; then
            log_error "I cannot find directory: $dir"
            errors=$((errors + 1))
        fi
    done
    
    # I'm checking SSL certificates
    if [[ ! -f "$SSL_DIR/selfsigned.crt" ]] || [[ ! -f "$SSL_DIR/selfsigned.key" ]]; then
        log_error "I cannot find SSL certificates"
        errors=$((errors + 1))
    fi
    
    # I'm checking configuration file
    if [[ ! -f "$CONFIG_DIR/mcaster1.yaml" ]]; then
        log_error "I cannot find configuration file"
        errors=$((errors + 1))
    fi
    
    # I'm checking autotools files
    if [[ ! -f "$PROJECT_ROOT/configure.ac" ]] || [[ ! -f "$PROJECT_ROOT/Makefile.am" ]]; then
        log_error "I cannot find autotools configuration"
        errors=$((errors + 1))
    fi
    
    # I'm checking PHP-FPM service
    if ! systemctl is-active --quiet "php${PHP_VERSION}-fpm"; then
        log_warning "PHP-FPM ${PHP_VERSION} service is not running"
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "I validated the bootstrap setup successfully"
        return 0
    else
        log_error "I found $errors errors during validation"
        return 1
    fi
}

# I'm defining the main bootstrap function
main() {
    log_info "Starting ICY2-SERVER Bootstrap v1.1.1"
    log_info "I'm setting up the complete development environment..."
    
    # I'm handling command line arguments
    case "${1:-}" in
        "ssl-only")
            log_info "I'm only generating SSL certificates..."
            generate_ssl_certificates
            exit 0
            ;;
        "--help"|"-h")
            echo "ICY2-SERVER Bootstrap Script"
            echo "Usage: $0 [ssl-only]"
            echo ""
            echo "Options:"
            echo "  ssl-only    Only generate SSL certificates"
            echo "  --help, -h  Show this help message"
            exit 0
            ;;
    esac
    
    # I'm executing the bootstrap steps in order
    detect_os
    detect_php_version  # I'm detecting PHP version before installing packages
    install_dependencies
    create_directory_structure
    generate_ssl_certificates
    configure_php_fpm
    create_default_config
    create_autotools_config
    initialize_logging
    
    # I'm validating everything was set up correctly
    if validate_setup; then
        log_success "I have successfully bootstrapped ICY2-SERVER!"
        echo ""
        log_info "Configuration Summary:"
        echo "  Operating System: $OS $VERSION"
        echo "  PHP Version:      $PHP_VERSION"
        echo "  PHP Socket:       $PHP_SOCKET_PATH"
        echo "  Project Root:     $PROJECT_ROOT"
        echo ""
        log_info "Next steps:"
        echo "1. Run './autogen.sh' to generate build files"
        echo "2. Run './configure --prefix=/usr/local' to configure the build"
        echo "3. Run 'make -j\$(nproc)' to build the server"
        echo "4. Run 'sudo make install' to install system-wide"
        echo ""
        log_info "For development, you can also run:"
        echo "  ./configure --enable-debug --prefix=$PROJECT_ROOT/install"
        echo ""
        log_info "Visit https://mcaster1.com for documentation and support"
    else
        log_error "I encountered errors during bootstrap. Please check the output above."
        exit 1
    fi
}

# I'm running the main function with all arguments
main "$@"
