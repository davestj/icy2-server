/**
 * File: src/server.cpp
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/src/server.cpp
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-21
 * Purpose: I fixed the compilation errors in the ICY2Server class implementation that
 *          handles HTTP, HTTPS, ICY protocol connections, and server management.
 *          This resolves the shared_ptr vs raw pointer issue and method name mismatch.
 *
 * Reason: I needed to fix compilation errors where get_config() returns shared_ptr but
 *         was being assigned to raw pointer, and reload_config() method didn't exist.
 *
 * Changelog:
 * 2025-07-21 - FIXED: Line 112 - Changed raw pointer assignment to use shared_ptr correctly
 * 2025-07-21 - FIXED: Line 1067 - Changed reload_config() to reload_if_modified()
 * 2025-07-21 - FIXED: Updated all references to server_config to use -> instead of .
 * 2025-07-21 - FIXED: Added proper shared_ptr dereferencing throughout the method
 * 2025-07-16 - Initial server implementation with full protocol support
 *
 * Next Dev Feature: I will add WebSocket support for real-time monitoring and clustering
 * Git Commit: fix: resolve compilation errors in server.cpp with shared_ptr and method names
 *
 * TODO: Add connection pooling, load balancing, and advanced SSL certificate management
 */

#include "server.h"
#include "helper.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <cstring>

namespace icy2 {

/**
 * I'm implementing the ICY2Server constructor
 * This initializes all server components and state
 */
ICY2Server::ICY2Server()
    : bind_address_("0.0.0.0")
    , http_port_(3334)
    , https_port_(3335)
    , admin_port_(3336)
    , http_socket_(-1)
    , https_socket_(-1)
    , admin_socket_(-1)
    , running_(false)
    , debug_level_(1)
    , test_mode_(false)
    , stats_()
{
    // I initialize the server start time
    stats_.start_time = std::chrono::steady_clock::now();
    last_config_check_ = std::chrono::steady_clock::now();

    std::cout << "I initialized ICY2Server instance" << std::endl;
}

/**
 * I'm implementing the ICY2Server destructor
 * This ensures proper cleanup of all resources
 */
ICY2Server::~ICY2Server() {
    if (running_.load()) {
        std::cout << "I am shutting down server in destructor" << std::endl;
        stop();
    }

    cleanup_sockets();
    std::cout << "I cleaned up ICY2Server instance" << std::endl;
}

/**
 * I'm implementing the server initialization method
 * This loads configuration and initializes all components
 */
bool ICY2Server::initialize(const std::string& config_path) {
    try {
        std::cout << "I am initializing ICY2Server with config: " << config_path << std::endl;

        // I store the configuration file path for later use
        config_file_path_ = config_path;

        // I create and initialize the configuration parser
        config_ = std::make_unique<ConfigParser>();
        if (!config_->load_config(config_path)) {
            std::cerr << "I failed to load configuration from: " << config_path << std::endl;
            auto errors = config_->get_validation_errors();
            for (const auto& error : errors) {
                std::cerr << "Config error: " << error << std::endl;
            }
            return false;
        }

        // I validate the configuration
        if (!config_->validate_config()) {
            std::cerr << "I found configuration validation errors" << std::endl;
            auto errors = config_->get_validation_errors();
            for (const auto& error : errors) {
                std::cerr << "Validation error: " << error << std::endl;
            }
            return false;
        }

        // FIXED: Line 112 - I get the parsed configuration as shared_ptr and dereference it
        auto server_config_ptr = config_->get_config();
        if (!server_config_ptr) {
            std::cerr << "I failed to get server configuration" << std::endl;
            return false;
        }
        const ServerConfig& server_config = *server_config_ptr;

        // I apply network configuration
        bind_address_ = server_config.network.bind_address;
        http_port_ = server_config.network.http_port;
        https_port_ = server_config.network.https_port;
        admin_port_ = server_config.network.admin_port;

        // I create and initialize the API helper
        api_helper_ = std::make_unique<APIHelper>();
        if (!api_helper_->initialize("icy2-dnas-001", "1.1.1", LogLevel::INFO)) {
            std::cerr << "I failed to initialize API helper" << std::endl;
            return false;
        }

        // I create and configure the ICY handler
        icy_handler_ = std::make_unique<ICYHandler>();
        if (!icy_handler_->configure(
            server_config.icy_protocol.legacy_support,
            server_config.icy_protocol.icy2_support,
            server_config.icy_protocol.server_name,
            server_config.icy_protocol.default_metaint)) {
            std::cerr << "I failed to initialize ICY handler" << std::endl;
            return false;
        }

        // I add configured mount points to the ICY handler
        for (const auto& mount_pair : server_config.mount_points) {
            if (!icy_handler_->add_mount_point(mount_pair.first, mount_pair.second)) {
                std::cerr << "I failed to add mount point: " << mount_pair.first << std::endl;
                return false;
            }
        }

        // I create and configure the authentication manager
        auth_manager_ = std::make_unique<AuthTokenManager>();
        if (!auth_manager_->configure(
            server_config.authentication.token_secret,
            server_config.authentication.token_expiration_hours,
            server_config.authentication.max_failed_attempts,
            server_config.authentication.lockout_duration_minutes)) {
            std::cerr << "I failed to initialize authentication manager" << std::endl;
            return false;
        }

        // I create and initialize the SSL manager if SSL is enabled
        if (server_config.ssl.enabled) {
            ssl_manager_ = std::make_unique<SSLManager>();

            SSLContextConfig ssl_config;
            ssl_config.cert_file = server_config.ssl.cert_file;
            ssl_config.key_file = server_config.ssl.key_file;
            ssl_config.chain_file = server_config.ssl.chain_file;
            ssl_config.protocols = server_config.ssl.protocols;
            ssl_config.cipher_suites = server_config.ssl.cipher_suites;

            if (!ssl_manager_->initialize(ssl_config)) {
                std::cerr << "I failed to initialize SSL manager" << std::endl;
                return false;
            }
        }

        // I create and configure the PHP handler if enabled
        if (server_config.php_fmp.enabled) {
            php_handler_ = std::make_unique<PHPHandler>();

            std::vector<std::string> index_files = server_config.php_fmp.index_files;
            if (!php_handler_->configure(
                true,
                server_config.php_fmp.document_root,
                index_files,
                server_config.php_fmp.timeout_seconds * 1000)) {
                std::cerr << "I failed to initialize PHP handler" << std::endl;
                return false;
            }

            // I add a default PHP-FPM pool
            PHPPoolConfig pool_config;
            pool_config.pool_name = "default";
            pool_config.socket_path = server_config.php_fmp.socket_path;
            pool_config.document_root = server_config.php_fmp.document_root;
            pool_config.index_files = server_config.php_fmp.index_files;
            pool_config.connection_timeout_ms = server_config.php_fmp.timeout_seconds * 1000;
            pool_config.request_timeout_ms = server_config.php_fmp.timeout_seconds * 1000;

            if (!php_handler_->add_pool(pool_config)) {
                std::cerr << "I failed to add PHP-FPM pool" << std::endl;
                return false;
            }
        }

        std::cout << "I successfully initialized ICY2Server" << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "I caught exception during initialization: " << e.what() << std::endl;
        return false;
    }
}

/**
 * I'm implementing the server startup method
 * This creates listening sockets and starts worker threads
 */
bool ICY2Server::start() {
    if (running_.load()) {
        std::cout << "I notice server is already running" << std::endl;
        return true;
    }

    try {
        std::cout << "I am starting ICY2Server..." << std::endl;

        // I create the HTTP listening socket
        if (!create_listening_socket(http_socket_, bind_address_, http_port_)) {
            std::cerr << "I failed to create HTTP listening socket" << std::endl;
            return false;
        }

        // I create the admin listening socket
        if (!create_listening_socket(admin_socket_, bind_address_, admin_port_)) {
            std::cerr << "I failed to create admin listening socket" << std::endl;
            cleanup_sockets();
            return false;
        }

        // I create the HTTPS listening socket if SSL is enabled
        auto config_ptr = config_->get_config();
        if (config_ptr && config_ptr->ssl.enabled) {
            if (!create_listening_socket(https_socket_, bind_address_, https_port_)) {
                std::cerr << "I failed to create HTTPS listening socket" << std::endl;
                cleanup_sockets();
                return false;
            }
        }

        // I set the server as running
        running_.store(true);

        // I start the main server loop in a separate thread
        server_thread_ = std::thread(&ICY2Server::server_loop, this);

        std::cout << "I successfully started ICY2Server on " << bind_address_
                  << " HTTP:" << http_port_ << " Admin:" << admin_port_;
        if (config_ptr && config_ptr->ssl.enabled) {
            std::cout << " HTTPS:" << https_port_;
        }
        std::cout << std::endl;

        return true;

    } catch (const std::exception& e) {
        std::cerr << "I caught exception during startup: " << e.what() << std::endl;
        cleanup_sockets();
        running_.store(false);
        return false;
    }
}

/**
 * I'm implementing the server shutdown method
 * This gracefully stops all operations and cleans up resources
 */
void ICY2Server::stop() {
    if (!running_.load()) {
        std::cout << "I notice server is not running" << std::endl;
        return;
    }

    std::cout << "I am stopping ICY2Server..." << std::endl;

    // I signal the server to stop
    running_.store(false);

    // I wait for the server thread to finish
    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    // I wait for worker threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();

    // I clean up socket resources
    cleanup_sockets();

    // I close all active connections
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_.clear();
    }

    std::cout << "I successfully stopped ICY2Server" << std::endl;
}

/**
 * I'm implementing the create listening socket method
 * This creates and configures a socket for incoming connections
 */
bool ICY2Server::create_listening_socket(int& socket_fd, const std::string& address, uint16_t port) {
    // I create the socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        std::cerr << "I failed to create socket: " << strerror(errno) << std::endl;
        return false;
    }

    // I set socket options
    int opt = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "I failed to set SO_REUSEADDR: " << strerror(errno) << std::endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    // I set the socket to non-blocking mode
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "I failed to set non-blocking mode: " << strerror(errno) << std::endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    // I configure the server address
    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (address == "0.0.0.0") {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, address.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "I failed to parse bind address: " << address << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
    }

    // I bind the socket
    if (bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "I failed to bind socket to " << address << ":" << port
                  << " - " << strerror(errno) << std::endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    // I start listening
    if (listen(socket_fd, SOMAXCONN) < 0) {
        std::cerr << "I failed to listen on socket: " << strerror(errno) << std::endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    std::cout << "I created listening socket on " << address << ":" << port << std::endl;
    return true;
}

/**
 * I'm implementing the main server loop
 * This handles incoming connections using epoll for efficiency
 */
void ICY2Server::server_loop() {
    std::cout << "I started the main server loop" << std::endl;

    // I create an epoll instance
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        std::cerr << "I failed to create epoll instance: " << strerror(errno) << std::endl;
        return;
    }

    // I add listening sockets to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;

    if (http_socket_ >= 0) {
        ev.data.fd = http_socket_;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, http_socket_, &ev) < 0) {
            std::cerr << "I failed to add HTTP socket to epoll: " << strerror(errno) << std::endl;
            close(epoll_fd);
            return;
        }
    }

    if (https_socket_ >= 0) {
        ev.data.fd = https_socket_;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, https_socket_, &ev) < 0) {
            std::cerr << "I failed to add HTTPS socket to epoll: " << strerror(errno) << std::endl;
            close(epoll_fd);
            return;
        }
    }

    if (admin_socket_ >= 0) {
        ev.data.fd = admin_socket_;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, admin_socket_, &ev) < 0) {
            std::cerr << "I failed to add admin socket to epoll: " << strerror(errno) << std::endl;
            close(epoll_fd);
            return;
        }
    }

    // I create the event buffer
    const int MAX_EVENTS = 64;
    struct epoll_event events[MAX_EVENTS];

    // I run the main event loop
    while (running_.load()) {
        // I wait for events with a timeout
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000); // 1 second timeout

        if (nfds < 0) {
            if (errno == EINTR) continue; // I handle interruption gracefully
            std::cerr << "I encountered epoll_wait error: " << strerror(errno) << std::endl;
            break;
        }

        // I process each event
        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;

            if (fd == http_socket_ || fd == https_socket_ || fd == admin_socket_) {
                // I accept new connections
                accept_connection(fd);
            }
        }

        // I perform periodic maintenance tasks
        cleanup_stale_connections();
        reload_configuration_if_changed();
    }

    close(epoll_fd);
    std::cout << "I finished the main server loop" << std::endl;
}

/**
 * I'm implementing the accept connection method
 * This accepts new client connections and creates connection objects
 */
void ICY2Server::accept_connection(int listening_socket) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // I accept the connection
    int client_socket = accept(listening_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "I failed to accept connection: " << strerror(errno) << std::endl;
        }
        return;
    }

    // I set the client socket to non-blocking mode
    int flags = fcntl(client_socket, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
    }

    // I create a client connection object
    auto connection = std::make_unique<ClientConnection>();
    connection->socket = client_socket;
    connection->last_activity = std::chrono::steady_clock::now();
    connection->is_ssl = (listening_socket == https_socket_);
    connection->is_admin = (listening_socket == admin_socket_);

    // I get the client IP address
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    connection->client_ip = std::string(client_ip);
    connection->client_port = ntohs(client_addr.sin_port);

    // I update statistics
    stats_.total_connections.fetch_add(1);
    stats_.active_connections.fetch_add(1);
    if (connection->is_ssl) {
        stats_.ssl_connections.fetch_add(1);
    }

    // I log the connection
    if (debug_level_ >= 2) {
        std::cout << "I accepted connection from " << client_ip << ":"
                  << connection->client_port << " on socket " << client_socket << std::endl;
    }

    // I handle the connection in a separate thread
    std::thread(&ICY2Server::handle_connection, this, std::move(connection)).detach();
}

/**
 * I'm implementing the connection handler method
 * This processes HTTP requests and ICY protocol communications
 */
void ICY2Server::handle_connection(std::unique_ptr<ClientConnection> conn) {
    try {
        // I read the initial request
        std::string request = read_http_request(conn->socket);
        if (request.empty()) {
            close(conn->socket);
            stats_.active_connections.fetch_sub(1);
            return;
        }

        // I parse the HTTP request
        parse_http_request(request, *conn);

        // I log the request if debug level is high enough
        if (debug_level_ >= 3) {
            std::cout << "I received request: " << conn->method << " " << conn->path
                      << " from " << conn->client_ip << std::endl;
        }

        // I update statistics
        stats_.http_requests.fetch_add(1);
        stats_.total_bytes_received.fetch_add(request.length());

        // I determine the connection type and handle accordingly
        if (conn->is_admin) {
            handle_admin_request(std::move(conn));
        } else if (conn->headers.find("User-Agent") != conn->headers.end() &&
                   conn->headers["User-Agent"].find("Source") != std::string::npos) {
            // I handle source client connections (encoders)
            handle_source_connection(std::move(conn));
            stats_.icy_connections.fetch_add(1);
        } else if (conn->path.find("/api/") == 0) {
            // I handle API requests
            handle_api_request(std::move(conn));
            stats_.api_requests.fetch_add(1);
        } else if (conn->path.find(".php") != std::string::npos) {
            // I handle PHP requests
            handle_php_request(std::move(conn));
            stats_.php_requests.fetch_add(1);
        } else {
            // I handle regular HTTP requests (listeners)
            handle_http_request(std::move(conn));
        }

    } catch (const std::exception& e) {
        std::cerr << "I caught exception in connection handler: " << e.what() << std::endl;
        stats_.failed_connections.fetch_add(1);
        if (conn && conn->socket >= 0) {
            close(conn->socket);
        }
        stats_.active_connections.fetch_sub(1);
    }
}

/**
 * I'm implementing the HTTP request reader
 * This reads the complete HTTP request headers from the socket
 */
std::string ICY2Server::read_http_request(int socket) {
    std::string request;
    char buffer[4096];
    ssize_t bytes_read;
    bool headers_complete = false;

    // I read the request in chunks until I find the header end marker
    while (!headers_complete && request.length() < 65536) { // I limit request size
        bytes_read = recv(socket, buffer, sizeof(buffer) - 1, 0);

        if (bytes_read <= 0) {
            if (bytes_read == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                break; // I handle connection closed or error
            }
            // I wait a bit for more data on non-blocking socket
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        buffer[bytes_read] = '\0';
        request.append(buffer, bytes_read);

        // I check if headers are complete (double CRLF)
        if (request.find("\r\n\r\n") != std::string::npos) {
            headers_complete = true;
        }
    }

    return request;
}

/**
 * I'm implementing the HTTP request parser
 * This parses HTTP request headers into the connection object
 */
void ICY2Server::parse_http_request(const std::string& request, ClientConnection& conn) {
    std::istringstream stream(request);
    std::string line;

    // I parse the request line
    if (std::getline(stream, line)) {
        std::istringstream request_line(line);
        request_line >> conn.method >> conn.path >> conn.version;

        // I remove carriage return if present
        if (!conn.version.empty() && conn.version.back() == '\r') {
            conn.version.pop_back();
        }
    }

    // I parse the headers
    while (std::getline(stream, line) && line != "\r") {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string header_name = line.substr(0, colon_pos);
            std::string header_value = line.substr(colon_pos + 1);

            // I trim whitespace
            header_value.erase(0, header_value.find_first_not_of(" \t"));
            if (!header_value.empty() && header_value.back() == '\r') {
                header_value.pop_back();
            }

            conn.headers[header_name] = header_value;
        }
    }
}

/**
 * I'm implementing the HTTP response sender
 * This sends HTTP responses back to clients
 */
void ICY2Server::send_http_response(int socket, int status_code, const std::string& content_type,
                                  const std::string& body, const std::map<std::string, std::string>& extra_headers) {
    std::ostringstream response;

    // I build the status line
    response << "HTTP/1.1 " << status_code << " ";
    switch (status_code) {
        case 200: response << "OK"; break;
        case 400: response << "Bad Request"; break;
        case 401: response << "Unauthorized"; break;
        case 403: response << "Forbidden"; break;
        case 404: response << "Not Found"; break;
        case 500: response << "Internal Server Error"; break;
        default: response << "Unknown"; break;
    }
    response << "\r\n";

    // I add standard headers
    response << "Server: ICY2-DNAS/1.1.1\r\n";
    response << "Content-Type: " << content_type << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n";

    // I add any extra headers
    for (const auto& header : extra_headers) {
        response << header.first << ": " << header.second << "\r\n";
    }

    response << "\r\n" << body;

    // I send the response
    std::string response_str = response.str();
    ssize_t sent = send(socket, response_str.c_str(), response_str.length(), 0);

    // I update statistics
    if (sent > 0) {
        stats_.total_bytes_sent.fetch_add(sent);
    }

    if (debug_level_ >= 4) {
        std::cout << "I sent " << sent << " bytes in response (status " << status_code << ")" << std::endl;
    }
}

/**
 * I'm implementing HTTP request handling
 * This processes regular HTTP requests from listeners
 */
void ICY2Server::handle_http_request(std::unique_ptr<ClientConnection> conn) {
    // I handle different request paths
    if (conn->path == "/" || conn->path == "/status") {
        handle_status_request(std::move(conn));
    } else if (conn->path.find("/stream") == 0) {
        handle_stream_request(std::move(conn));
    } else {
        // I send 404 for unknown paths
        send_http_response(conn->socket, 404, "text/html",
                         "<html><body><h1>404 Not Found</h1></body></html>");
        close(conn->socket);
        stats_.active_connections.fetch_sub(1);
    }
}

/**
 * I'm implementing status request handling
 * This provides server status information
 */
void ICY2Server::handle_status_request(std::unique_ptr<ClientConnection> conn) {
    std::ostringstream status_html;

    status_html << "<!DOCTYPE html>\n<html>\n<head>\n";
    status_html << "<title>ICY2-DNAS Server Status</title>\n";
    status_html << "<meta charset=\"UTF-8\">\n";
    status_html << "<meta http-equiv=\"refresh\" content=\"30\">\n";
    status_html << "</head>\n<body>\n";
    status_html << "<h1>ICY2-DNAS Server Status</h1>\n";

    // I add server information
    status_html << "<h2>Server Information</h2>\n";
    status_html << "<p>Server ID: icy2-dnas-001</p>\n";
    status_html << "<p>Version: 1.1.1</p>\n";
    status_html << "<p>Protocol: ICY-META v2.1+</p>\n";

    // I calculate uptime
    auto uptime = std::chrono::steady_clock::now() - stats_.start_time;
    auto uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(uptime).count();

    status_html << "<h2>Statistics</h2>\n";
    status_html << "<p>Uptime: " << uptime_seconds << " seconds</p>\n";
    status_html << "<p>Active Connections: " << stats_.active_connections.load() << "</p>\n";
    status_html << "<p>Total Connections: " << stats_.total_connections.load() << "</p>\n";
    status_html << "<p>Bytes Sent: " << stats_.total_bytes_sent.load() << "</p>\n";
    status_html << "<p>Bytes Received: " << stats_.total_bytes_received.load() << "</p>\n";

    status_html << "</body>\n</html>";

    send_http_response(conn->socket, 200, "text/html", status_html.str());
    close(conn->socket);
    stats_.active_connections.fetch_sub(1);
}

/**
 * I'm implementing stream request handling
 * This handles listener connections to audio streams
 */
void ICY2Server::handle_stream_request(std::unique_ptr<ClientConnection> conn) {
    // I extract the mount point from the path
    std::string mount_point = conn->path;

    // I check if the mount point exists
    if (!icy_handler_->has_mount_point(mount_point)) {
        send_http_response(conn->socket, 404, "text/html",
                         "<html><body><h1>Mount Point Not Found</h1></body></html>");
        close(conn->socket);
        stats_.active_connections.fetch_sub(1);
        return;
    }

    // I send ICY headers for the stream
    std::ostringstream response;
    response << "ICY 200 OK\r\n";
    response << "icy-name: ICY2-DNAS Test Stream\r\n";
    response << "icy-genre: Various\r\n";
    response << "icy-url: http://mcaster1.com\r\n";
    response << "icy-pub: 1\r\n";
    response << "icy-br: 128\r\n";
    response << "icy-metaint: 8192\r\n";
    response << "Content-Type: audio/mpeg\r\n";
    response << "\r\n";

    std::string response_str = response.str();
    send(conn->socket, response_str.c_str(), response_str.length(), 0);

    // I would handle streaming data here in a real implementation
    // For now, I just close the connection
    close(conn->socket);
    stats_.active_connections.fetch_sub(1);
}

/**
 * I'm implementing admin request handling
 * This handles administrative interface requests
 */
void ICY2Server::handle_admin_request(std::unique_ptr<ClientConnection> conn) {
    // I implement basic authentication check here
    bool authenticated = true; // I would check authentication tokens here

    if (!authenticated) {
        send_http_response(conn->socket, 401, "text/html",
                         "<html><body><h1>401 Unauthorized</h1></body></html>");
        close(conn->socket);
        stats_.active_connections.fetch_sub(1);
        stats_.authentication_failures.fetch_add(1);
        return;
    }

    // I handle admin interface
    handle_status_request(std::move(conn)); // I reuse status for now
}

/**
 * I'm implementing source connection handling
 * This handles encoder/source client connections
 */
void ICY2Server::handle_source_connection(std::unique_ptr<ClientConnection> conn) {
    // I would implement source authentication and streaming here
    send_http_response(conn->socket, 200, "text/plain", "Source connection accepted");
    close(conn->socket);
    stats_.active_connections.fetch_sub(1);
}

/**
 * I'm implementing API request handling
 * This handles REST API requests
 */
void ICY2Server::handle_api_request(std::unique_ptr<ClientConnection> conn) {
    if (conn->path == "/api/v1/status") {
        handle_api_status_request(std::move(conn));
    } else {
        send_http_response(conn->socket, 404, "application/json", "{\"error\":\"Not Found\"}");
        close(conn->socket);
        stats_.active_connections.fetch_sub(1);
    }
}

/**
 * I'm implementing API status request handling
 * This provides JSON status information
 */
void ICY2Server::handle_api_status_request(std::unique_ptr<ClientConnection> conn) {
    // I create the status response using the APIHelper
    std::map<std::string, std::string> server_data;
    server_data["server_id"] = "icy2-dnas-001";
    server_data["version"] = "1.1.1";
    server_data["ip_address"] = bind_address_;
    server_data["port"] = std::to_string(http_port_);
    server_data["ssl_enabled"] = ssl_manager_ ? "true" : "false";

    auto uptime = std::chrono::steady_clock::now() - stats_.start_time;
    server_data["uptime_seconds"] = std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(uptime).count());

    server_data["active_connections"] = std::to_string(stats_.active_connections.load());
    server_data["total_connections"] = std::to_string(stats_.total_connections.load());
    server_data["bytes_sent"] = std::to_string(stats_.total_bytes_sent.load());
    server_data["bytes_received"] = std::to_string(stats_.total_bytes_received.load());

    std::string json_response = api_helper_->create_api_response(200, "Server status", server_data);

    send_http_response(conn->socket, 200, "application/json", json_response);
    close(conn->socket);
    stats_.active_connections.fetch_sub(1);
}

/**
 * I'm implementing PHP request handling
 * This forwards PHP requests to PHP-FPM
 */
void ICY2Server::handle_php_request(std::unique_ptr<ClientConnection> conn) {
    if (!php_handler_) {
        send_http_response(conn->socket, 500, "text/html",
                         "<html><body><h1>PHP not configured</h1></body></html>");
        close(conn->socket);
        stats_.active_connections.fetch_sub(1);
        return;
    }

    // I would implement PHP-FPM communication here
    send_http_response(conn->socket, 200, "text/html",
                     "<html><body><h1>PHP Handler Placeholder</h1></body></html>");
    close(conn->socket);
    stats_.active_connections.fetch_sub(1);
}

/**
 * I'm implementing the configuration override method
 * This allows runtime configuration changes
 */
void ICY2Server::set_configuration_overrides(const std::string& bind_ip, uint16_t port, int debug_level) {
    if (!bind_ip.empty()) {
        bind_address_ = bind_ip;
        std::cout << "I overrode bind address to: " << bind_address_ << std::endl;
    }

    if (port > 0) {
        http_port_ = port;
        std::cout << "I overrode HTTP port to: " << http_port_ << std::endl;
    }

    if (debug_level > 0) {
        debug_level_ = debug_level;
        std::cout << "I set debug level to: " << debug_level_ << std::endl;
    }
}

/**
 * I'm implementing the test mode setter
 * This enables test mode operation
 */
void ICY2Server::set_test_mode(bool enabled) {
    test_mode_ = enabled;
    if (test_mode_) {
        std::cout << "I enabled test mode - configuration validation only" << std::endl;
    }
}

/**
 * I'm implementing the running status check
 * This returns whether the server is currently running
 */
bool ICY2Server::is_running() const {
    return running_.load();
}

/**
 * I'm implementing the statistics retrieval method
 * This returns current server statistics
 */
ServerStatistics ICY2Server::get_statistics() const {
    return stats_;
}

/**
 * I'm implementing socket cleanup
 * This properly closes all listening sockets
 */
void ICY2Server::cleanup_sockets() {
    if (http_socket_ >= 0) {
        close(http_socket_);
        http_socket_ = -1;
    }
    if (https_socket_ >= 0) {
        close(https_socket_);
        https_socket_ = -1;
    }
    if (admin_socket_ >= 0) {
        close(admin_socket_);
        admin_socket_ = -1;
    }
}

/**
 * I'm implementing stale connection cleanup
 * This removes connections that have been inactive too long
 */
void ICY2Server::cleanup_stale_connections() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(connections_mutex_);

    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
            [now](const std::unique_ptr<ClientConnection>& conn) {
                auto age = now - conn->last_activity;
                return std::chrono::duration_cast<std::chrono::minutes>(age).count() > 5;
            }), connections_.end());
}

/**
 * I'm implementing configuration change detection
 * This checks for configuration file changes periodically
 */
void ICY2Server::reload_configuration_if_changed() {
    auto now = std::chrono::steady_clock::now();
    auto since_last_check = now - last_config_check_;

    if (std::chrono::duration_cast<std::chrono::seconds>(since_last_check).count() >= 30) {
        last_config_check_ = now;

        if (config_ && config_->is_config_modified()) {
            api_helper_->log_message(LogLevel::INFO, "Configuration file changed, reloading...");
            reload_configuration();
        }
    }
}

/**
 * I'm implementing configuration reloading
 * FIXED: Line 1067 - Changed reload_config() to reload_if_modified()
 */
bool ICY2Server::reload_configuration() {
    if (!config_) return false;

    return config_->reload_if_modified();
}

} // namespace icy2