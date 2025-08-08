/**
 * File: src/server.cpp
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/src/server.cpp
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-21
 * Purpose: I corrected the ICY2Server implementation to align precisely with the actual
 *          header file interface definitions. This resolves all compilation errors by
 *          ensuring method signatures and struct member usage match exactly.
 *
 * Reason: I needed to align the implementation with the actual ClientConnection structure
 *         and method signatures defined in server.h, rather than implementing an
 *         imaginary interface that doesn't exist in the actual codebase.
 *
 * Changelog:
 * 2025-07-21 - FIXED: Aligned all method signatures with actual header declarations
 * 2025-07-21 - FIXED: Updated ClientConnection member usage to match actual struct
 * 2025-07-21 - FIXED: Corrected PHP handler add_pool call to provide both arguments
 * 2025-07-21 - FIXED: Removed duplicate is_running() method (already inline in header)
 * 2025-07-21 - FIXED: Updated start() method signature to match header parameters
 * 2025-07-21 - FIXED: Removed non-existent server_thread_ reference
 *
 * Next Dev Feature: I will implement the missing method bodies for complete functionality
 * Git Commit: fix: align server.cpp implementation with actual header interface
 *
 * TODO: Complete implementation of all declared methods with full functionality
 */

#include "server.h"
#include "helper.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
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
#include <cerrno>

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

        // FIXED: I get the parsed configuration as shared_ptr and dereference it properly
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

        // I create and initialize the PHP handler if enabled
        if (server_config.php_fpm.enabled) {
            php_handler_ = std::make_unique<PHPHandler>(
                server_config.php_fpm.socket_path,
                server_config.php_fpm.document_root,
                server_config.php_fpm);

            if (!php_handler_->initialize()) {
                std::cerr << "I failed to initialize PHP handler" << std::endl;
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
 * FIXED: I'm implementing the server startup method with correct signature
 * This matches the header declaration exactly
 */
bool ICY2Server::start(const std::string& bind_ip, uint16_t port,
                      int debug_level, bool test_mode) {
    if (running_.load()) {
        std::cout << "I notice server is already running" << std::endl;
        return true;
    }

    // I apply any command line overrides
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

    test_mode_ = test_mode;
    if (test_mode_) {
        std::cout << "I enabled test mode - configuration validation only" << std::endl;
        return true; // In test mode, I just validate configuration
    }

    try {
        std::cout << "I am starting ICY2Server..." << std::endl;

        // I initialize all listening sockets
        if (!initialize_sockets()) {
            std::cerr << "I failed to initialize listening sockets" << std::endl;
            return false;
        }

        // I set the server as running
        running_.store(true);

        // I start worker threads for handling connections
        size_t num_workers = std::thread::hardware_concurrency();
        if (num_workers == 0) num_workers = 4; // Default fallback

        for (size_t i = 0; i < num_workers; ++i) {
            worker_threads_.emplace_back(&ICY2Server::worker_thread_main, this);
        }

        // I start the main accept thread
        std::thread accept_thread(&ICY2Server::accept_connections, this);
        accept_thread.detach();

        std::cout << "I successfully started ICY2Server on " << bind_address_
                  << " HTTP:" << http_port_ << " Admin:" << admin_port_;
        auto config_ptr = config_->get_config();
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

    // I notify all waiting worker threads
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_cv_.notify_all();
    }

    // FIXED: I wait for worker threads to finish (not server_thread_)
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
 * I'm implementing the socket initialization method
 * This creates and configures all listening sockets
 */
bool ICY2Server::initialize_sockets() {
    // I create the HTTP listening socket
    if (!bind_and_listen(http_socket_, http_port_, false)) {
        std::cerr << "I failed to create HTTP listening socket" << std::endl;
        return false;
    }

    // I create the admin listening socket
    if (!bind_and_listen(admin_socket_, admin_port_, false)) {
        std::cerr << "I failed to create admin listening socket" << std::endl;
        cleanup_sockets();
        return false;
    }

    // I create the HTTPS listening socket if SSL is enabled
    auto config_ptr = config_->get_config();
    if (config_ptr && config_ptr->ssl.enabled) {
        if (!bind_and_listen(https_socket_, https_port_, true)) {
            std::cerr << "I failed to create HTTPS listening socket" << std::endl;
            cleanup_sockets();
            return false;
        }
    }

    return true;
}

/**
 * I'm implementing the bind and listen method
 * This creates and configures a socket for incoming connections
 */
bool ICY2Server::bind_and_listen(int& socket_fd, uint16_t port, bool ssl) {
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

    if (bind_address_ == "0.0.0.0") {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, bind_address_.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "I failed to parse bind address: " << bind_address_ << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
    }

    // I bind the socket
    if (bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "I failed to bind socket to " << bind_address_ << ":" << port
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

    std::cout << "I created " << (ssl ? "HTTPS" : "HTTP") << " listening socket on "
              << bind_address_ << ":" << port << std::endl;
    return true;
}

/**
 * I'm implementing the connection acceptance method
 * This runs in a separate thread to accept new connections
 */
void ICY2Server::accept_connections() {
    std::cout << "I started the connection acceptance thread" << std::endl;

    while (running_.load()) {
        // I use select to check for incoming connections
        fd_set read_fds;
        FD_ZERO(&read_fds);

        int max_fd = 0;
        if (http_socket_ >= 0) {
            FD_SET(http_socket_, &read_fds);
            max_fd = std::max(max_fd, http_socket_);
        }
        if (https_socket_ >= 0) {
            FD_SET(https_socket_, &read_fds);
            max_fd = std::max(max_fd, https_socket_);
        }
        if (admin_socket_ >= 0) {
            FD_SET(admin_socket_, &read_fds);
            max_fd = std::max(max_fd, admin_socket_);
        }

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);

        if (activity < 0) {
            if (errno == EINTR) continue;
            std::cerr << "I encountered select error: " << strerror(errno) << std::endl;
            break;
        }

        if (activity == 0) continue; // Timeout

        // I check each listening socket for new connections
        if (http_socket_ >= 0 && FD_ISSET(http_socket_, &read_fds)) {
            accept_new_connection(http_socket_, false, false);
        }
        if (https_socket_ >= 0 && FD_ISSET(https_socket_, &read_fds)) {
            accept_new_connection(https_socket_, true, false);
        }
        if (admin_socket_ >= 0 && FD_ISSET(admin_socket_, &read_fds)) {
            accept_new_connection(admin_socket_, false, true);
        }

        // I perform periodic maintenance
        cleanup_stale_connections();
        reload_configuration_if_changed();
    }

    std::cout << "I finished the connection acceptance thread" << std::endl;
}

/**
 * I'm implementing the new connection acceptance helper
 * This accepts a single connection and queues it for processing
 */
void ICY2Server::accept_new_connection(int listening_socket, bool is_ssl, bool is_admin) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

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

    // I create a client connection object with correct member names
    auto connection = std::make_unique<ClientConnection>();
    connection->socket_fd = client_socket;
    connection->state = ConnectionState::CONNECTING;
    connection->type = is_admin ? ConnectionType::ADMIN : ConnectionType::HTTP_LISTENER;
    connection->last_activity = std::chrono::steady_clock::now();
    connection->connected_at = std::chrono::steady_clock::now();
    connection->is_ssl = is_ssl;
    connection->ssl_handle = nullptr;
    connection->buffer_pos = 0;
    connection->authenticated = false;
    connection->bytes_sent = 0;
    connection->bytes_received = 0;
    connection->metadata_interval = 0;

    // I get the client IP address using correct member name
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    connection->remote_ip = std::string(client_ip);
    connection->remote_port = ntohs(client_addr.sin_port);

    // I update statistics
    stats_.total_connections.fetch_add(1);
    stats_.active_connections.fetch_add(1);
    if (is_ssl) {
        stats_.ssl_connections.fetch_add(1);
    }

    // I log the connection
    if (debug_level_ >= 2) {
        std::cout << "I accepted connection from " << client_ip << ":"
                  << connection->remote_port << " on socket " << client_socket << std::endl;
    }

    // I queue the connection for worker thread processing
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_connections_.push(client_socket);
    }
    pending_cv_.notify_one();

    // I store the connection in our active connections list
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_.push_back(std::move(connection));
    }
}

/**
 * I'm implementing the worker thread main loop
 * This processes queued connections
 */
void ICY2Server::worker_thread_main() {
    std::cout << "I started worker thread" << std::endl;

    while (running_.load()) {
        int client_socket = -1;

        // I wait for a pending connection
        {
            std::unique_lock<std::mutex> lock(pending_mutex_);
            pending_cv_.wait(lock, [this] {
                return !pending_connections_.empty() || !running_.load();
            });

            if (!running_.load()) break;

            if (!pending_connections_.empty()) {
                client_socket = pending_connections_.front();
                pending_connections_.pop();
            }
        }

        if (client_socket >= 0) {
            // I find the connection object for this socket
            std::unique_ptr<ClientConnection> conn;
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                auto it = std::find_if(connections_.begin(), connections_.end(),
                    [client_socket](const std::unique_ptr<ClientConnection>& c) {
                        return c->socket_fd == client_socket;
                    });

                if (it != connections_.end()) {
                    conn = std::move(*it);
                    connections_.erase(it);
                }
            }

            if (conn) {
                handle_connection(std::move(conn));
            }
        }
    }

    std::cout << "I finished worker thread" << std::endl;
}

/**
 * I'm implementing the connection handler method
 * This processes individual client connections
 */
void ICY2Server::handle_connection(std::unique_ptr<ClientConnection> conn) {
    try {
        // I determine connection type and delegate to appropriate handler
        if (conn->type == ConnectionType::ADMIN) {
            process_http_request(conn.get()); // Admin uses HTTP protocol
        } else if (conn->type == ConnectionType::HTTP_LISTENER) {
            process_http_request(conn.get());
        } else {
            process_icy_request(conn.get());
        }

    } catch (const std::exception& e) {
        std::cerr << "I caught exception in connection handler: " << e.what() << std::endl;
        stats_.failed_connections.fetch_add(1);
    }

    // I ensure the connection is properly closed
    if (conn && conn->socket_fd >= 0) {
        close(conn->socket_fd);
    }
    stats_.active_connections.fetch_sub(1);
}

/**
 * I'm implementing HTTP request processing
 * This handles standard HTTP requests
 */
void ICY2Server::process_http_request(ClientConnection* conn) {
    // I parse the HTTP headers first
    if (!parse_http_headers(conn)) {
        send_http_response(conn, 400, "text/plain", "Bad Request");
        return;
    }

    // I validate the request
    if (!validate_request(conn)) {
        send_http_response(conn, 403, "text/plain", "Forbidden");
        return;
    }

    // I route the request based on URI
    if (conn->request_uri == "/" || conn->request_uri == "/status") {
        handle_status_request(conn);
    } else if (conn->request_uri.find("/api/") == 0) {
        process_api_request(conn);
    } else if (conn->request_uri.find(".php") != std::string::npos) {
        process_php_request(conn);
    } else {
        send_http_response(conn, 404, "text/html",
                         "<html><body><h1>404 Not Found</h1></body></html>");
    }
}

/**
 * I'm implementing API request processing
 * This handles REST API requests
 */
void ICY2Server::process_api_request(ClientConnection* conn) {
    if (conn->request_uri == "/api/v1/status") {
        handle_api_status_request(conn);
    } else {
        send_http_response(conn, 404, "application/json", "{\"error\":\"Not Found\"}");
    }
}

/**
 * I'm implementing ICY request processing
 * This handles ICY protocol streaming requests
 */
void ICY2Server::process_icy_request(ClientConnection* conn) {
    // I would implement ICY protocol handling here
    send_icy_response(conn, "ICY 200 OK\r\nicy-name: Test Stream\r\n\r\n");
}

/**
 * I'm implementing PHP request processing
 * This forwards requests to PHP-FPM
 */
void ICY2Server::process_php_request(ClientConnection* conn) {
    if (!php_handler_) {
        send_http_response(conn, 500, "text/html",
                         "<html><body><h1>PHP not configured</h1></body></html>");
        return;
    }

    // I would implement PHP-FPM communication here
    send_http_response(conn, 200, "text/html",
                     "<html><body><h1>PHP Handler Placeholder</h1></body></html>");
}

/**
 * I'm implementing HTTP response sending
 * This sends HTTP responses back to clients
 */
void ICY2Server::send_http_response(ClientConnection* conn, int status_code,
                                  const std::string& content_type, const std::string& body) {
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
    response << "\r\n" << body;

    // I send the response ensuring all bytes are transmitted
    std::string response_str = response.str();
    const char* data = response_str.c_str();
    size_t total = response_str.length();
    size_t offset = 0;

    while (offset < total) {
        ssize_t sent = ::send(conn->socket_fd, data + offset, total - offset, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;  // I retry on interrupt
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;  // I retry on temporary unavailability
            }
            break;  // I stop on other errors
        }
        if (sent == 0) {
            break;  // I stop if connection is closed
        }

        // I update statistics for each successful send
        stats_.total_bytes_sent.fetch_add(static_cast<size_t>(sent));
        conn->bytes_sent += static_cast<size_t>(sent);
        offset += static_cast<size_t>(sent);
    }
}

/**
 * I'm implementing ICY response sending
 * This sends ICY protocol responses
 */
void ICY2Server::send_icy_response(ClientConnection* conn, const std::string& response) {
    // I ensure the entire ICY response is sent
    const char* data = response.c_str();
    size_t total = response.length();
    size_t offset = 0;

    while (offset < total) {
        ssize_t sent = ::send(conn->socket_fd, data + offset, total - offset, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;  // I retry on interrupt
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;  // I retry on temporary unavailability
            }
            break;  // I stop on other errors
        }
        if (sent == 0) {
            break;  // I stop if connection is closed
        }

        stats_.total_bytes_sent.fetch_add(static_cast<size_t>(sent));
        conn->bytes_sent += static_cast<size_t>(sent);
        offset += static_cast<size_t>(sent);
    }
}

/**
 * I'm implementing HTTP header parsing
 * This parses HTTP request headers
 */
bool ICY2Server::parse_http_headers(ClientConnection* conn) {
    // I convert the raw buffer into a string for easy parsing
    std::string raw_request(conn->read_buffer.begin(), conn->read_buffer.end());

    // I locate the end of the header section
    size_t header_end = raw_request.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return false; // I fail if headers are incomplete
    }

    std::istringstream stream(raw_request.substr(0, header_end));
    std::string line;

    // I parse the request line
    if (!std::getline(stream, line)) {
        return false;
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    std::istringstream request_line(line);
    if (!(request_line >> conn->http_method >> conn->request_uri >> conn->http_version)) {
        return false; // I require method, URI and version
    }

    // I parse each header line
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }

        auto colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            return false; // I require valid header lines
        }

        std::string name = line.substr(0, colon_pos);
        std::string value = line.substr(colon_pos + 1);

        auto trim = [](std::string& s) {
            s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
            s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
                return !std::isspace(ch);
            }).base(), s.end());
        };

        trim(name);
        trim(value);

        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
            return std::tolower(c);
        });

        conn->headers[name] = value;
    }

    return true;
}

/**
 * I'm implementing request validation
 * This validates incoming requests for security
 */
bool ICY2Server::validate_request(ClientConnection* conn) {
    if (!auth_manager_) {
        return false;
    }

    // I first look for an Authorization header
    auto auth_header = conn->headers.find("Authorization");
    if (auth_header == conn->headers.end()) {
        auth_header = conn->headers.find("authorization");
    }

    if (auth_header != conn->headers.end()) {
        const std::string& header_value = auth_header->second;

        // I handle bearer token authentication
        const std::string bearer_prefix = "Bearer ";
        if (header_value.rfind(bearer_prefix, 0) == 0) {
            std::string token = header_value.substr(bearer_prefix.length());
            auto session = auth_manager_->authenticate_token(token, conn->remote_ip);
            if (session) {
                conn->authenticated = true;
                conn->session_id = session->session_id;
                return true;
            }
            return false;
        }

        // I handle basic authentication with username and password
        const std::string basic_prefix = "Basic ";
        if (header_value.rfind(basic_prefix, 0) == 0 && api_helper_) {
            std::string encoded = header_value.substr(basic_prefix.length());
            std::vector<uint8_t> decoded_bytes = api_helper_->base64_decode(encoded);
            std::string decoded(decoded_bytes.begin(), decoded_bytes.end());
            auto sep = decoded.find(':');
            if (sep != std::string::npos) {
                std::string username = decoded.substr(0, sep);
                std::string password = decoded.substr(sep + 1);
                auto session = auth_manager_->authenticate_user(username, password,
                                                               conn->remote_ip,
                                                               conn->user_agent);
                if (session) {
                    conn->authenticated = true;
                    conn->session_id = session->session_id;
                    return true;
                }
            }
            return false;
        }
    }

    // I also check for API key authentication header
    auto api_key_header = conn->headers.find("X-API-Key");
    if (api_key_header == conn->headers.end()) {
        api_key_header = conn->headers.find("x-api-key");
    }

    if (api_key_header != conn->headers.end()) {
        auto session = auth_manager_->authenticate_api_key(api_key_header->second,
                                                           conn->remote_ip);
        if (session) {
            conn->authenticated = true;
            conn->session_id = session->session_id;
            return true;
        }
        return false;
    }

    // I deny requests with missing or invalid authentication
    return false;
}

/**
 * I'm implementing status request handling
 * This provides server status information
 */
void ICY2Server::handle_status_request(ClientConnection* conn) {
    std::ostringstream status_html;

    status_html << "<!DOCTYPE html>\n<html>\n<head>\n";
    status_html << "<title>ICY2-DNAS Server Status</title>\n";
    status_html << "</head>\n<body>\n";
    status_html << "<h1>ICY2-DNAS Server Status</h1>\n";
    status_html << "<p>Server running on " << bind_address_ << ":" << http_port_ << "</p>\n";
    status_html << "<p>Active connections: " << stats_.active_connections.load() << "</p>\n";
    status_html << "</body>\n</html>";

    send_http_response(conn, 200, "text/html", status_html.str());
}

/**
 * I'm implementing API status request handling
 * This provides JSON status information
 */
void ICY2Server::handle_api_status_request(ClientConnection* conn) {
    std::map<std::string, std::string> server_data;
    server_data["server_id"] = "icy2-dnas-001";
    server_data["version"] = "1.1.1";
    server_data["active_connections"] = std::to_string(stats_.active_connections.load());

    std::string json_response = api_helper_->create_api_response(200, "Server status", server_data);
    send_http_response(conn, 200, "application/json", json_response);
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
 * FIXED: Using correct method name from ConfigParser interface
 */
bool ICY2Server::reload_configuration() {
    if (!config_) return false;

    return config_->reload_if_modified();
}

/**
 * I'm implementing the get_statistics method
 * FIXED: Removed duplicate implementation (already inline in header)
 */
// Method is already defined inline in header file

} // namespace icy2