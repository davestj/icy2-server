/**
 * File: src/server.cpp
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/src/server.cpp
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this core server implementation that handles HTTP/HTTPS requests,
 *          ICY protocol streaming, SSL/TLS connections, and coordinates all server
 *          functionality. This is the main engine of the ICY2-SERVER.
 * 
 * Reason: I need a robust, high-performance server implementation that can handle
 *         multiple protocols, manage thousands of connections, provide secure
 *         streaming, and integrate with all other server components seamlessly.
 *
 * Changelog:
 * 2025-07-16 - Initial server implementation with HTTP/ICY protocol support
 * 2025-07-16 - Added SSL/TLS integration and secure connection handling
 * 2025-07-16 - Implemented multi-threaded connection management
 * 2025-07-16 - Added PHP-FPM integration and web interface support
 * 2025-07-16 - Integrated authentication, monitoring, and API endpoints
 *
 * Next Dev Feature: I plan to add load balancing, WebRTC support, and clustering
 * Git Commit: feat: implement core server with HTTP/ICY protocol and SSL support
 *
 * TODO: Add WebSocket support, HTTP/2 compliance, advanced caching, clustering
 */

#include "server.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <netinet/tcp.h>

namespace icy2 {

/**
 * I'm implementing the ICY2Server constructor
 * This initializes all server components and sets default values
 */
ICY2Server::ICY2Server() 
    : bind_address_("0.0.0.0")
    , http_port_(3334)
    , https_port_(8443)
    , admin_port_(8001)
    , http_socket_(-1)
    , https_socket_(-1)
    , admin_socket_(-1)
    , running_(false)
    , debug_level_(1)
    , test_mode_(false)
{
    // I'm initializing the statistics with current time
    stats_.start_time = std::chrono::steady_clock::now();
    
    // I'm setting up default configuration file path
    config_file_path_ = "/etc/icy2-server/mcaster1.yaml";
    
    // I'm initializing the last config check time
    last_config_check_ = std::chrono::steady_clock::now();
}

/**
 * I'm implementing the ICY2Server destructor
 * This ensures proper cleanup of all resources
 */
ICY2Server::~ICY2Server() {
    // I make sure the server is stopped before destruction
    if (running_.load()) {
        stop();
    }
    
    // I clean up all socket resources
    cleanup_sockets();
}

/**
 * I'm implementing the server initialization method
 * This sets up all server components and validates configuration
 */
bool ICY2Server::initialize(const std::string& config_path) {
    try {
        // I store the configuration file path
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
        
        // I get the parsed configuration
        const ServerConfig* server_config = config_->get_config();
        if (!server_config) {
            std::cerr << "I failed to get server configuration" << std::endl;
            return false;
        }
        
        // I apply network configuration
        bind_address_ = server_config->network.bind_address;
        http_port_ = server_config->network.http_port;
        https_port_ = server_config->network.https_port;
        admin_port_ = server_config->network.admin_port;
        
        // I create and initialize the API helper
        api_helper_ = std::make_unique<APIHelper>();
        if (!api_helper_->initialize("icy2-dnas-001", "1.1.1", LogLevel::INFO)) {
            std::cerr << "I failed to initialize API helper" << std::endl;
            return false;
        }
        
        // I create and configure the ICY handler
        icy_handler_ = std::make_unique<ICYHandler>();
        if (!icy_handler_->configure(
            server_config->icy_protocol.legacy_support,
            server_config->icy_protocol.icy2_support,
            server_config->icy_protocol.server_name,
            server_config->icy_protocol.default_metaint)) {
            std::cerr << "I failed to initialize ICY handler" << std::endl;
            return false;
        }
        
        // I add configured mount points to the ICY handler
        for (const auto& mount_pair : server_config->mount_points) {
            if (!icy_handler_->add_mount_point(mount_pair.first, mount_pair.second)) {
                std::cerr << "I failed to add mount point: " << mount_pair.first << std::endl;
                return false;
            }
        }
        
        // I create and configure the authentication manager
        auth_manager_ = std::make_unique<AuthTokenManager>();
        if (!auth_manager_->configure(
            server_config->authentication.token_secret,
            server_config->authentication.token_expiration_hours,
            server_config->authentication.max_failed_attempts,
            server_config->authentication.lockout_duration_minutes)) {
            std::cerr << "I failed to initialize authentication manager" << std::endl;
            return false;
        }
        
        // I create and initialize the SSL manager if SSL is enabled
        if (server_config->ssl.enabled) {
            ssl_manager_ = std::make_unique<SSLManager>();
            
            SSLContextConfig ssl_config;
            ssl_config.cert_file = server_config->ssl.cert_file;
            ssl_config.key_file = server_config->ssl.key_file;
            ssl_config.chain_file = server_config->ssl.chain_file;
            ssl_config.protocols = server_config->ssl.protocols;
            ssl_config.cipher_suites = server_config->ssl.cipher_suites;
            
            if (!ssl_manager_->initialize(ssl_config)) {
                std::cerr << "I failed to initialize SSL manager" << std::endl;
                return false;
            }
        }
        
        // I create and configure the PHP handler if enabled
        if (server_config->php_fmp.enabled) {
            php_handler_ = std::make_unique<PHPHandler>();
            
            std::vector<std::string> index_files = server_config->php_fmp.index_files;
            if (!php_handler_->configure(
                true,
                server_config->php_fmp.document_root,
                index_files,
                server_config->php_fmp.timeout_seconds * 1000)) {
                std::cerr << "I failed to initialize PHP handler" << std::endl;
                return false;
            }
            
            // I add a default PHP-FPM pool
            PHPPoolConfig pool_config;
            pool_config.pool_name = "default";
            pool_config.socket_path = server_config->php_fmp.socket_path;
            pool_config.document_root = server_config->php_fmp.document_root;
            pool_config.index_files = server_config->php_fmp.index_files;
            pool_config.connection_timeout_ms = server_config->php_fmp.timeout_seconds * 1000;
            pool_config.request_timeout_ms = server_config->php_fmp.timeout_seconds * 1000;
            
            if (!php_handler_->add_pool("default", pool_config)) {
                std::cerr << "I failed to add default PHP-FPM pool" << std::endl;
                return false;
            }
        }
        
        api_helper_->log_message(LogLevel::INFO, "Server initialization completed successfully");
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "I caught an exception during initialization: " << e.what() << std::endl;
        return false;
    }
}

/**
 * I'm implementing the server start method
 * This begins accepting connections and starts all worker threads
 */
bool ICY2Server::start(const std::string& bind_ip, uint16_t port, int debug_level, bool test_mode) {
    try {
        // I apply command line overrides
        if (!bind_ip.empty()) {
            bind_address_ = bind_ip;
        }
        if (port > 0) {
            http_port_ = port;
        }
        debug_level_ = debug_level;
        test_mode_ = test_mode;
        
        api_helper_->log_message(LogLevel::INFO, 
            "Starting ICY2-SERVER on " + bind_address_ + ":" + std::to_string(http_port_));
        
        // I initialize all network sockets
        if (!initialize_sockets()) {
            api_helper_->log_message(LogLevel::ERROR, "Failed to initialize network sockets");
            return false;
        }
        
        // I set the running flag
        running_.store(true);
        
        // I start worker threads for connection handling
        int worker_count = std::thread::hardware_concurrency();
        if (worker_count == 0) worker_count = 4; // I default to 4 threads
        
        api_helper_->log_message(LogLevel::INFO, 
            "Starting " + std::to_string(worker_count) + " worker threads");
        
        for (int i = 0; i < worker_count; ++i) {
            worker_threads_.emplace_back(&ICY2Server::worker_thread_main, this);
        }
        
        // I start the main connection acceptance thread
        std::thread accept_thread(&ICY2Server::accept_connections, this);
        
        if (test_mode_) {
            // I run a quick test and then stop
            api_helper_->log_message(LogLevel::INFO, "Running in test mode");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            stop();
            accept_thread.join();
            return true;
        }
        
        // I detach the accept thread to run independently
        accept_thread.detach();
        
        api_helper_->log_message(LogLevel::INFO, "ICY2-SERVER started successfully");
        return true;
        
    } catch (const std::exception& e) {
        api_helper_->log_message(LogLevel::ERROR, 
            "Exception during server start: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the server stop method
 * This gracefully shuts down all connections and threads
 */
void ICY2Server::stop() {
    if (!running_.load()) {
        return; // I'm already stopped
    }
    
    api_helper_->log_message(LogLevel::INFO, "Stopping ICY2-SERVER gracefully...");
    
    // I set the shutdown flag
    running_.store(false);
    
    // I close all listening sockets to stop accepting new connections
    cleanup_sockets();
    
    // I notify all worker threads to wake up and check the running flag
    pending_cv_.notify_all();
    
    // I wait for all worker threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    // I clean up all active connections
    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (auto& conn : connections_) {
        if (conn) {
            if (conn->is_ssl && conn->ssl_handle && ssl_manager_) {
                ssl_manager_->destroy_ssl_connection(conn->ssl_handle);
            }
            if (conn->socket_fd >= 0) {
                close(conn->socket_fd);
            }
        }
    }
    connections_.clear();
    
    api_helper_->log_message(LogLevel::INFO, "ICY2-SERVER stopped successfully");
}

/**
 * I'm implementing the socket initialization method
 * This sets up all listening sockets for HTTP, HTTPS, and admin interfaces
 */
bool ICY2Server::initialize_sockets() {
    // I initialize the HTTP socket
    if (!bind_and_listen(http_socket_, http_port_, false)) {
        std::cerr << "I failed to bind HTTP socket on port " << http_port_ << std::endl;
        return false;
    }
    
    // I initialize the HTTPS socket if SSL is enabled
    if (ssl_manager_ && !bind_and_listen(https_socket_, https_port_, true)) {
        std::cerr << "I failed to bind HTTPS socket on port " << https_port_ << std::endl;
        return false;
    }
    
    // I initialize the admin socket
    if (!bind_and_listen(admin_socket_, admin_port_, false)) {
        std::cerr << "I failed to bind admin socket on port " << admin_port_ << std::endl;
        return false;
    }
    
    api_helper_->log_message(LogLevel::INFO, "All sockets initialized successfully");
    return true;
}

/**
 * I'm implementing the bind and listen method
 * This creates and configures a socket for the specified port
 */
bool ICY2Server::bind_and_listen(int& socket_fd, uint16_t port, bool ssl) {
    // I create the socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        api_helper_->log_message(LogLevel::ERROR, 
            "Failed to create socket for port " + std::to_string(port));
        return false;
    }
    
    // I set socket options for address reuse
    int opt = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        api_helper_->log_message(LogLevel::WARNING, 
            "Failed to set SO_REUSEADDR for port " + std::to_string(port));
    }
    
    // I set socket to non-blocking mode
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    // I configure the socket address
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    
    if (bind_address_ == "0.0.0.0") {
        address.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, bind_address_.c_str(), &address.sin_addr) <= 0) {
            api_helper_->log_message(LogLevel::ERROR, 
                "Invalid bind address: " + bind_address_);
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
    }
    
    // I bind the socket to the address
    if (bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        api_helper_->log_message(LogLevel::ERROR, 
            "Failed to bind socket to " + bind_address_ + ":" + std::to_string(port));
        close(socket_fd);
        socket_fd = -1;
        return false;
    }
    
    // I start listening for connections
    if (listen(socket_fd, 1024) < 0) {
        api_helper_->log_message(LogLevel::ERROR, 
            "Failed to listen on port " + std::to_string(port));
        close(socket_fd);
        socket_fd = -1;
        return false;
    }
    
    std::string protocol = ssl ? "HTTPS" : "HTTP";
    api_helper_->log_message(LogLevel::INFO, 
        protocol + " socket listening on " + bind_address_ + ":" + std::to_string(port));
    
    return true;
}

/**
 * I'm implementing the connection acceptance method
 * This runs in a separate thread to accept incoming connections
 */
void ICY2Server::accept_connections() {
    // I create an epoll instance for efficient connection monitoring
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        api_helper_->log_message(LogLevel::ERROR, "Failed to create epoll instance");
        return;
    }
    
    // I add all listening sockets to epoll
    struct epoll_event event;
    event.events = EPOLLIN;
    
    if (http_socket_ >= 0) {
        event.data.fd = http_socket_;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, http_socket_, &event);
    }
    
    if (https_socket_ >= 0) {
        event.data.fd = https_socket_;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, https_socket_, &event);
    }
    
    if (admin_socket_ >= 0) {
        event.data.fd = admin_socket_;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, admin_socket_, &event);
    }
    
    api_helper_->log_message(LogLevel::DEBUG, "Connection acceptance thread started");
    
    struct epoll_event events[10];
    
    while (running_.load()) {
        // I wait for events on listening sockets
        int event_count = epoll_wait(epoll_fd, events, 10, 1000); // I timeout after 1 second
        
        if (event_count < 0) {
            if (errno == EINTR) continue; // I was interrupted, retry
            api_helper_->log_message(LogLevel::ERROR, "epoll_wait failed");
            break;
        }
        
        // I process each event
        for (int i = 0; i < event_count; ++i) {
            int listen_fd = events[i].data.fd;
            
            // I accept the new connection
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
            
            if (client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    api_helper_->log_message(LogLevel::WARNING, "Failed to accept connection");
                }
                continue;
            }
            
            // I create a connection object
            auto connection = std::make_unique<ClientConnection>();
            connection->socket_fd = client_fd;
            connection->state = ConnectionState::CONNECTING;
            connection->type = ConnectionType::HTTP; // I'll determine the actual type later
            connection->remote_ip = inet_ntoa(client_addr.sin_addr);
            connection->remote_port = ntohs(client_addr.sin_port);
            connection->connected_at = std::chrono::steady_clock::now();
            connection->last_activity = connection->connected_at;
            connection->is_ssl = (listen_fd == https_socket_);
            connection->ssl_handle = nullptr;
            connection->buffer_pos = 0;
            connection->authenticated = false;
            connection->bytes_sent = 0;
            connection->bytes_received = 0;
            connection->metadata_interval = 0;
            
            // I resize the buffer to a reasonable size
            connection->buffer.resize(8192);
            
            // I set the client socket to non-blocking
            int flags = fcntl(client_fd, F_GETFL, 0);
            if (flags >= 0) {
                fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
            }
            
            // I update statistics
            stats_.total_connections.fetch_add(1);
            stats_.active_connections.fetch_add(1);
            
            // I add the connection to the pending queue for worker threads
            {
                std::lock_guard<std::mutex> lock(pending_mutex_);
                pending_connections_.push(client_fd);
            }
            
            // I store the connection
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connections_.push_back(std::move(connection));
            }
            
            // I notify worker threads
            pending_cv_.notify_one();
            
            if (debug_level_ >= 3) {
                api_helper_->log_message(LogLevel::DEBUG, 
                    "Accepted connection from " + connection->remote_ip + ":" + 
                    std::to_string(connection->remote_port));
            }
        }
        
        // I periodically clean up stale connections
        cleanup_stale_connections();
        
        // I check for configuration file changes
        reload_configuration_if_changed();
    }
    
    close(epoll_fd);
    api_helper_->log_message(LogLevel::DEBUG, "Connection acceptance thread stopped");
}

/**
 * I'm implementing the worker thread main loop
 * This processes connections and handles requests
 */
void ICY2Server::worker_thread_main() {
    api_helper_->log_message(LogLevel::DEBUG, "Worker thread started");
    
    while (running_.load()) {
        int client_fd = -1;
        
        // I wait for a pending connection
        {
            std::unique_lock<std::mutex> lock(pending_mutex_);
            pending_cv_.wait_for(lock, std::chrono::seconds(1), [this] {
                return !pending_connections_.empty() || !running_.load();
            });
            
            if (!pending_connections_.empty()) {
                client_fd = pending_connections_.front();
                pending_connections_.pop();
            }
        }
        
        if (client_fd >= 0) {
            // I find the corresponding connection object
            std::unique_ptr<ClientConnection> connection;
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                for (auto it = connections_.begin(); it != connections_.end(); ++it) {
                    if ((*it)->socket_fd == client_fd) {
                        connection = std::move(*it);
                        connections_.erase(it);
                        break;
                    }
                }
            }
            
            if (connection) {
                handle_connection(std::move(connection));
            }
        }
    }
    
    api_helper_->log_message(LogLevel::DEBUG, "Worker thread stopped");
}

/**
 * I'm implementing the connection handler method
 * This processes individual client connections
 */
void ICY2Server::handle_connection(std::unique_ptr<ClientConnection> conn) {
    try {
        // I set up SSL if this is an HTTPS connection
        if (conn->is_ssl && ssl_manager_) {
            conn->ssl_handle = ssl_manager_->create_ssl_connection(conn->socket_fd, true);
            if (!conn->ssl_handle) {
                api_helper_->log_message(LogLevel::WARNING, 
                    "Failed to create SSL connection for " + conn->remote_ip);
                close(conn->socket_fd);
                stats_.active_connections.fetch_sub(1);
                return;
            }
            stats_.ssl_connections.fetch_add(1);
        }
        
        conn->state = ConnectionState::CONNECTED;
        
        // I read the initial request
        if (!parse_http_headers(conn.get())) {
            api_helper_->log_message(LogLevel::DEBUG, 
                "Failed to parse HTTP headers from " + conn->remote_ip);
            if (conn->ssl_handle && ssl_manager_) {
                ssl_manager_->destroy_ssl_connection(conn->ssl_handle);
            }
            close(conn->socket_fd);
            stats_.active_connections.fetch_sub(1);
            return;
        }
        
        // I validate the request
        if (!validate_request(conn.get())) {
            send_http_response(conn.get(), 400, "text/plain", "Bad Request");
            if (conn->ssl_handle && ssl_manager_) {
                ssl_manager_->destroy_ssl_connection(conn->ssl_handle);
            }
            close(conn->socket_fd);
            stats_.active_connections.fetch_sub(1);
            return;
        }
        
        // I determine the request type and process accordingly
        if (conn->request_uri.find("/api/") == 0) {
            conn->type = ConnectionType::API;
            process_api_request(conn.get());
            stats_.api_requests.fetch_add(1);
        } else if (php_handler_ && php_handler_->should_handle_request(conn->request_uri)) {
            conn->type = ConnectionType::PHP_FPM;
            process_php_request(conn.get());
            stats_.php_requests.fetch_add(1);
        } else if (conn->headers.find("icy-") != conn->headers.end() || 
                   conn->headers.find("User-Agent") != conn->headers.end() && 
                   conn->headers["User-Agent"].find("Source") != std::string::npos) {
            // I detect ICY protocol requests
            conn->type = ConnectionType::ICY_SOURCE;
            process_icy_request(conn.get());
            stats_.icy_connections.fetch_add(1);
        } else {
            // I handle as standard HTTP request
            conn->type = ConnectionType::HTTP;
            process_http_request(conn.get());
            stats_.http_requests.fetch_add(1);
        }
        
        // I clean up the connection
        if (conn->ssl_handle && ssl_manager_) {
            ssl_manager_->destroy_ssl_connection(conn->ssl_handle);
        }
        close(conn->socket_fd);
        stats_.active_connections.fetch_sub(1);
        
    } catch (const std::exception& e) {
        api_helper_->log_message(LogLevel::ERROR, 
            "Exception in connection handler: " + std::string(e.what()));
        
        if (conn->ssl_handle && ssl_manager_) {
            ssl_manager_->destroy_ssl_connection(conn->ssl_handle);
        }
        if (conn->socket_fd >= 0) {
            close(conn->socket_fd);
        }
        stats_.active_connections.fetch_sub(1);
    }
}

/**
 * I'm implementing the HTTP request processor
 * This handles standard HTTP requests and serves static content
 */
void ICY2Server::process_http_request(ClientConnection* conn) {
    if (debug_level_ >= 2) {
        api_helper_->log_message(LogLevel::DEBUG, 
            "Processing HTTP request: " + conn->http_method + " " + conn->request_uri);
    }
    
    // I handle different HTTP methods
    if (conn->http_method == "GET") {
        // I serve static content or directory listings
        if (conn->request_uri == "/" || conn->request_uri.empty()) {
            // I serve the default index page
            send_http_response(conn, 200, "text/html", 
                "<html><head><title>ICY2-SERVER</title></head>"
                "<body><h1>ICY2-SERVER v1.1.1</h1>"
                "<p>Digital Network Audio Server</p>"
                "<p><a href=\"/api/v1/status\">Server Status</a></p>"
                "</body></html>");
        } else {
            // I return a simple 404 for now
            send_http_response(conn, 404, "text/html", 
                "<html><head><title>404 Not Found</title></head>"
                "<body><h1>404 Not Found</h1>"
                "<p>The requested resource was not found.</p>"
                "</body></html>");
        }
    } else if (conn->http_method == "HEAD") {
        // I handle HEAD requests
        send_http_response(conn, 200, "text/html", "");
    } else {
        // I return method not allowed
        send_http_response(conn, 405, "text/plain", "Method Not Allowed");
    }
}

/**
 * I'm implementing the API request processor
 * This handles REST API endpoints
 */
void ICY2Server::process_api_request(ClientConnection* conn) {
    if (debug_level_ >= 2) {
        api_helper_->log_message(LogLevel::DEBUG, 
            "Processing API request: " + conn->request_uri);
    }
    
    // I handle the /api/v1/status endpoint
    if (conn->request_uri == "/api/v1/status" || conn->request_uri == "/api/v1/status/") {
        std::string status_json = get_server_info();
        send_http_response(conn, 200, "application/json", status_json);
        return;
    }
    
    // I handle mount point information
    if (conn->request_uri.find("/api/v1/mounts") == 0) {
        if (icy_handler_) {
            std::string mounts_json = icy_handler_->get_statistics_json();
            send_http_response(conn, 200, "application/json", mounts_json);
        } else {
            send_http_response(conn, 503, "application/json", 
                "{\"error\":\"ICY handler not available\"}");
        }
        return;
    }
    
    // I return API not found
    send_http_response(conn, 404, "application/json", 
        "{\"error\":\"API endpoint not found\"}");
}

/**
 * I'm implementing the ICY request processor
 * This handles ICY protocol streaming requests
 */
void ICY2Server::process_icy_request(ClientConnection* conn) {
    if (debug_level_ >= 2) {
        api_helper_->log_message(LogLevel::DEBUG, 
            "Processing ICY request: " + conn->request_uri);
    }
    
    if (!icy_handler_) {
        send_http_response(conn, 503, "text/plain", "ICY handler not available");
        return;
    }
    
    // I determine if this is a source or listener connection
    bool is_source = (conn->http_method == "SOURCE" || 
                     conn->headers.find("content-type") != conn->headers.end());
    
    if (is_source) {
        // I handle source connections
        if (icy_handler_->handle_source_connection(conn->request_uri, conn->headers, 
                                                  conn->remote_ip, conn->remote_port)) {
            conn->type = ConnectionType::ICY_SOURCE;
            send_icy_response(conn, "ICY 200 OK\r\n\r\n");
        } else {
            send_icy_response(conn, "ICY 401 Unauthorized\r\n\r\n");
        }
    } else {
        // I handle listener connections
        if (icy_handler_->handle_listener_connection(conn->request_uri, conn->headers,
                                                    conn->remote_ip, conn->remote_port)) {
            conn->type = ConnectionType::ICY_LISTENER;
            
            // I generate the ICY response headers
            std::string response = icy_handler_->generate_icy_response(
                conn->request_uri, ICYVersion::ICY_2_1, 8192);
            send_icy_response(conn, response);
        } else {
            send_icy_response(conn, "ICY 404 Not Found\r\n\r\n");
        }
    }
}

/**
 * I'm implementing the PHP request processor
 * This handles PHP-FPM requests via FastCGI
 */
void ICY2Server::process_php_request(ClientConnection* conn) {
    if (debug_level_ >= 2) {
        api_helper_->log_message(LogLevel::DEBUG, 
            "Processing PHP request: " + conn->request_uri);
    }
    
    if (!php_handler_) {
        send_http_response(conn, 503, "text/plain", "PHP handler not available");
        return;
    }
    
    // I prepare the PHP request
    PHPRequestType method = PHPRequestType::GET;
    if (conn->http_method == "POST") method = PHPRequestType::POST;
    else if (conn->http_method == "PUT") method = PHPRequestType::PUT;
    else if (conn->http_method == "DELETE") method = PHPRequestType::DELETE;
    
    // I process the request through PHP-FPM
    PHPResponse php_response;
    if (php_handler_->handle_http_request(method, conn->request_uri, conn->headers,
                                         std::vector<uint8_t>(), conn->remote_ip, php_response)) {
        // I send the PHP response
        std::string response_body(php_response.body_data.begin(), php_response.body_data.end());
        send_http_response(conn, php_response.http_status_code, 
                          php_response.content_type, response_body);
    } else {
        send_http_response(conn, 500, "text/plain", "PHP processing failed");
    }
}

/**
 * I'm implementing the HTTP response sender
 * This sends properly formatted HTTP responses
 */
void ICY2Server::send_http_response(ClientConnection* conn, int status_code, 
                                   const std::string& content_type, const std::string& body) {
    std::ostringstream response;
    
    // I build the HTTP response
    response << "HTTP/1.1 " << status_code;
    switch (status_code) {
        case 200: response << " OK"; break;
        case 404: response << " Not Found"; break;
        case 405: response << " Method Not Allowed"; break;
        case 500: response << " Internal Server Error"; break;
        case 503: response << " Service Unavailable"; break;
        default: response << " Unknown"; break;
    }
    response << "\r\n";
    
    // I add headers
    response << "Server: ICY2-SERVER/1.1.1\r\n";
    response << "Content-Type: " << content_type << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "Date: " << api_helper_->get_current_timestamp("%a, %d %b %Y %H:%M:%S GMT") << "\r\n";
    response << "\r\n";
    response << body;
    
    std::string response_str = response.str();
    
    // I send the response
    ssize_t sent = 0;
    if (conn->is_ssl && conn->ssl_handle) {
        sent = SSL_write(conn->ssl_handle, response_str.c_str(), response_str.length());
    } else {
        sent = write(conn->socket_fd, response_str.c_str(), response_str.length());
    }
    
    if (sent > 0) {
        conn->bytes_sent += sent;
        stats_.total_bytes_sent.fetch_add(sent);
    }
}

/**
 * I'm implementing the ICY response sender
 * This sends ICY protocol responses
 */
void ICY2Server::send_icy_response(ClientConnection* conn, const std::string& response) {
    ssize_t sent = 0;
    if (conn->is_ssl && conn->ssl_handle) {
        sent = SSL_write(conn->ssl_handle, response.c_str(), response.length());
    } else {
        sent = write(conn->socket_fd, response.c_str(), response.length());
    }
    
    if (sent > 0) {
        conn->bytes_sent += sent;
        stats_.total_bytes_sent.fetch_add(sent);
    }
}

/**
 * I'm implementing the HTTP header parser
 * This parses incoming HTTP requests and extracts headers
 */
bool ICY2Server::parse_http_headers(ClientConnection* conn) {
    // I read data from the connection
    char buffer[4096];
    ssize_t bytes_read = 0;
    
    if (conn->is_ssl && conn->ssl_handle) {
        bytes_read = SSL_read(conn->ssl_handle, buffer, sizeof(buffer) - 1);
    } else {
        bytes_read = read(conn->socket_fd, buffer, sizeof(buffer) - 1);
    }
    
    if (bytes_read <= 0) {
        return false;
    }
    
    buffer[bytes_read] = '\0';
    conn->bytes_received += bytes_read;
    stats_.total_bytes_received.fetch_add(bytes_read);
    
    std::string request_data(buffer, bytes_read);
    std::istringstream stream(request_data);
    std::string line;
    
    // I parse the request line
    if (!std::getline(stream, line)) {
        return false;
    }
    
    // I remove carriage return if present
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    
    std::istringstream request_line(line);
    request_line >> conn->http_method >> conn->request_uri >> conn->http_version;
    
    // I parse headers
    while (std::getline(stream, line) && !line.empty()) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line.empty()) break; // I reached the end of headers
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string header_name = line.substr(0, colon_pos);
            std::string header_value = line.substr(colon_pos + 1);
            
            // I trim whitespace
            header_value = api_helper_->trim_string(header_value);
            
            conn->headers[header_name] = header_value;
        }
    }
    
    // I extract user agent
    auto user_agent_it = conn->headers.find("User-Agent");
    if (user_agent_it != conn->headers.end()) {
        conn->user_agent = user_agent_it->second;
    }
    
    return true;
}

/**
 * I'm implementing request validation
 * This performs security checks on incoming requests
 */
bool ICY2Server::validate_request(ClientConnection* conn) {
    // I check for valid HTTP method
    if (conn->http_method != "GET" && conn->http_method != "POST" && 
        conn->http_method != "HEAD" && conn->http_method != "PUT" && 
        conn->http_method != "DELETE" && conn->http_method != "SOURCE") {
        return false;
    }
    
    // I check for valid URI
    if (conn->request_uri.empty() || conn->request_uri.length() > 2048) {
        return false;
    }
    
    // I check for path traversal attempts
    if (conn->request_uri.find("..") != std::string::npos) {
        return false;
    }
    
    // I update the last activity time
    conn->last_activity = std::chrono::steady_clock::now();
    
    return true;
}

/**
 * I'm implementing the get server info method
 * This generates JSON with comprehensive server information
 */
std::string ICY2Server::get_server_info() const {
    if (!api_helper_) {
        return "{\"error\":\"API helper not available\"}";
    }
    
    std::map<std::string, std::string> server_data;
    server_data["server_id"] = "icy2-dnas-001";
    server_data["version"] = "1.1.1";
    server_data["build_date"] = __DATE__;
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
    
    return api_helper_->create_api_response(200, "Server status", server_data);
}

/**
 * I'm implementing other required methods with basic implementations
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

void ICY2Server::cleanup_stale_connections() {
    // I implement basic cleanup - remove connections older than 5 minutes
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
            [now](const std::unique_ptr<ClientConnection>& conn) {
                auto age = now - conn->last_activity;
                return std::chrono::duration_cast<std::chrono::minutes>(age).count() > 5;
            }), connections_.end());
}

void ICY2Server::reload_configuration_if_changed() {
    // I check for config file changes every 30 seconds
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

bool ICY2Server::reload_configuration() {
    if (!config_) return false;
    
    return config_->reload_config();
}

ServerStatistics ICY2Server::get_statistics() const {
    return stats_;
}

bool ICY2Server::validate_configuration() const {
    if (!config_) return false;
    
    return config_->validate_config();
}

bool ICY2Server::generate_ssl_certificates() {
    if (!ssl_manager_) {
        ssl_manager_ = std::make_unique<SSLManager>();
    }
    
    CertificateGenerationParams params;
    params.type = CertificateType::SELF_SIGNED;
    params.key_size = 2048;
    params.validity_days = 365;
    params.country = "US";
    params.state = "Washington";
    params.locality = "Kirkland";
    params.organization = "MCaster1 DNAS";
    params.organizational_unit = "ICY2-SERVER Development";
    params.common_name = "localhost";
    params.email = "davestj@gmail.com";
    params.subject_alt_names = {"localhost", "127.0.0.1", "::1"};
    
    return ssl_manager_->generate_self_signed_certificate(params, 
        "ssl/selfsigned.crt", "ssl/selfsigned.key");
}

// I implement placeholder methods for interface compliance
bool ICY2Server::add_mount_point(const std::string& mount_path, const MountPointConfig& config) {
    return icy_handler_ ? icy_handler_->add_mount_point(mount_path, config) : false;
}

bool ICY2Server::remove_mount_point(const std::string& mount_path) {
    return icy_handler_ ? icy_handler_->remove_mount_point(mount_path) : false;
}

bool ICY2Server::broadcast_metadata(const std::string& mount_path, const ICYMetadata& metadata) {
    return icy_handler_ ? icy_handler_->update_metadata(mount_path, metadata) : false;
}

size_t ICY2Server::get_mount_point_listeners(const std::string& mount_path) const {
    return icy_handler_ ? icy_handler_->get_listener_count(mount_path) : 0;
}

} // namespace icy2
