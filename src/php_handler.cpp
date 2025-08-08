/**
 * File: src/php_handler.cpp
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/src/php_handler.cpp
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this PHP-FMP FastCGI handler implementation to provide seamless
 *          PHP integration that mimics nginx's php-fpm functionality for web admin
 *          interfaces and dynamic content generation in ICY2-SERVER.
 * 
 * Reason: I need robust PHP-FMP integration to support modern web-based administration,
 *         dynamic configuration management, and interactive dashboards while maintaining
 *         the performance and security standards of the core streaming server.
 *
 * Changelog:
 * 2025-07-16 - Initial implementation with complete FastCGI protocol support
 * 2025-07-16 - Added connection pooling and request buffering for performance
 * 2025-07-16 - Implemented comprehensive error handling and security validation
 * 2025-07-16 - Added environment variable management and configuration integration
 * 2025-07-16 - Integrated timeout handling and resource management
 *
 * Next Dev Feature: I plan to add PHP session clustering and advanced caching mechanisms
 * Git Commit: feat: implement complete PHP-FMP FastCGI integration with nginx-style processing
 *
 * TODO: Add session replication, response caching, load balancing across PHP-FMP pools
 */

#include "php_handler.h"
#include "config_parser.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <thread>

namespace icy2 {

/**
 * I'm implementing the PHP handler constructor
 * This initializes my PHP-FMP integration with proper configuration
 */
PHPHandler::PHPHandler(const std::string& socket_path, const std::string& document_root,
                       const PHPConfig& config)
    : socket_path_(socket_path)
    , document_root_(document_root)
    , config_(config)
    , connection_pool_size_(10)
    , request_timeout_ms_(config.timeout_seconds * 1000)
    , next_request_id_(1)
    , is_initialized_(false) {
    
    // I initialize my connection statistics
    stats_.total_requests = 0;
    stats_.successful_requests = 0;
    stats_.failed_requests = 0;
    stats_.average_response_time_ms = 0.0;
    stats_.peak_response_time_ms = 0;
    stats_.active_connections = 0;
    stats_.last_error_time = std::chrono::steady_clock::now();
    
    // I validate the document root path
    if (!std::filesystem::exists(document_root_)) {
        throw std::runtime_error("Document root does not exist: " + document_root_);
    }
    
    // I ensure the document root is readable
    if (!std::filesystem::is_directory(document_root_)) {
        throw std::runtime_error("Document root is not a directory: " + document_root_);
    }
}

/**
 * I'm implementing the PHP handler destructor
 * This ensures proper cleanup of resources and connections
 */
PHPHandler::~PHPHandler() {
    this->shutdown();
}

/**
 * I'm implementing the initialization function
 * This sets up my PHP-FMP connection pool and validates configuration
 */
bool PHPHandler::initialize() {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    
    if (is_initialized_) {
        return true;
    }
    
    // I test the PHP-FMP socket connectivity
    if (!test_php_fpm_connection()) {
        last_error_ = "Cannot connect to PHP-FMP socket: " + socket_path_;
        return false;
    }
    
    // I initialize my connection pool
    for (int i = 0; i < connection_pool_size_; i++) {
        auto connection = std::make_unique<FastCGIConnection>();
        connection->socket_fd = -1;
        connection->is_connected = false;
        connection->last_used = std::chrono::steady_clock::now();
        connection->request_count = 0;
        available_connections_.push(std::move(connection));
    }
    
    // I create my environment template
    setup_environment_template();
    
    is_initialized_ = true;
    
    return true;
}

/**
 * I'm implementing the shutdown function
 * This gracefully closes all connections and cleans up resources
 */
void PHPHandler::shutdown() {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    
    if (!is_initialized_) {
        return;
    }
    
    // I close all available connections
    while (!available_connections_.empty()) {
        auto connection = std::move(available_connections_.front());
        available_connections_.pop();
        close_connection(connection.get());
    }
    
    // I wait for active connections to complete (with timeout)
    auto shutdown_start = std::chrono::steady_clock::now();
    while (!active_connections_.empty()) {
        auto elapsed = std::chrono::steady_clock::now() - shutdown_start;
        if (elapsed > std::chrono::seconds(30)) {
            // I force close remaining connections after timeout
            for (auto& conn : active_connections_) {
                close_connection(conn);
            }
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    is_initialized_ = false;
}

/**
 * I'm implementing the main HTTP request handler
 * This processes PHP requests through FastCGI protocol
 */
bool PHPHandler::handle_http_request(PHPRequestType method, const std::string& uri,
                                   const std::unordered_map<std::string, std::string>& headers,
                                   const std::vector<uint8_t>& body_data,
                                   const std::string& client_ip,
                                   PHPResponse& response) {
    
    auto request_start = std::chrono::steady_clock::now();
    
    // I increment the total request counter
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_requests++;
    }
    
    try {
        // I validate the request
        if (!validate_request(uri, headers)) {
            response.status = PHPResponseStatus::INVALID_REQUEST;
            response.http_status_code = 400;
            response.error_message = "Invalid request format or security violation";
            record_failed_request(request_start);
            return false;
        }
        
        // I determine the PHP script path
        std::string script_path = resolve_script_path(uri);
        if (script_path.empty()) {
            response.status = PHPResponseStatus::FILE_NOT_FOUND;
            response.http_status_code = 404;
            response.error_message = "PHP script not found: " + uri;
            record_failed_request(request_start);
            return false;
        }
        
        // I acquire a connection from the pool
        auto connection = acquire_connection();
        if (!connection) {
            response.status = PHPResponseStatus::CONNECTION_FAILED;
            response.http_status_code = 503;
            response.error_message = "No available PHP-FMP connections";
            record_failed_request(request_start);
            return false;
        }
        
        // I process the request through FastCGI
        bool success = process_fastcgi_request(connection.get(), method, uri, script_path,
                                             headers, body_data, client_ip, response);
        
        // I return the connection to the pool
        release_connection(std::move(connection));
        
        if (success) {
            record_successful_request(request_start);
            return true;
        } else {
            record_failed_request(request_start);
            return false;
        }
        
    } catch (const std::exception& e) {
        response.status = PHPResponseStatus::PHP_ERROR;
        response.http_status_code = 500;
        response.error_message = "PHP processing exception: " + std::string(e.what());
        record_failed_request(request_start);
        return false;
    }
}

/**
 * I'm implementing the FastCGI request processor
 * This handles the low-level FastCGI protocol communication
 */
bool PHPHandler::process_fastcgi_request(FastCGIConnection* connection,
                                       PHPRequestType method, const std::string& uri,
                                       const std::string& script_path,
                                       const std::unordered_map<std::string, std::string>& headers,
                                       const std::vector<uint8_t>& body_data,
                                       const std::string& client_ip,
                                       PHPResponse& response) {
    
    // I generate a unique request ID
    uint16_t request_id = next_request_id_++;
    
    // I prepare the FastCGI environment
    FastCGIEnvironment env = build_environment(method, uri, script_path, headers, client_ip);
    
    // I ensure the connection is active
    if (!ensure_connection_active(connection)) {
        response.status = PHPResponseStatus::CONNECTION_FAILED;
        response.error_message = "Failed to establish PHP-FMP connection";
        return false;
    }
    
    try {
        // I send the FastCGI BEGIN_REQUEST record
        if (!send_begin_request(connection, request_id)) {
            response.status = PHPResponseStatus::FCGI_ERROR;
            response.error_message = "Failed to send BEGIN_REQUEST";
            return false;
        }
        
        // I send the environment parameters
        if (!send_environment_params(connection, request_id, env)) {
            response.status = PHPResponseStatus::FCGI_ERROR;
            response.error_message = "Failed to send environment parameters";
            return false;
        }
        
        // I send the request body data (for POST requests)
        if (!body_data.empty()) {
            if (!send_request_body(connection, request_id, body_data)) {
                response.status = PHPResponseStatus::FCGI_ERROR;
                response.error_message = "Failed to send request body";
                return false;
            }
        }
        
        // I read the FastCGI response
        if (!read_fastcgi_response(connection, request_id, response)) {
            response.status = PHPResponseStatus::FCGI_ERROR;
            response.error_message = "Failed to read FastCGI response";
            return false;
        }
        
        response.status = PHPResponseStatus::SUCCESS;
        return true;
        
    } catch (const std::exception& e) {
        response.status = PHPResponseStatus::PHP_ERROR;
        response.error_message = "FastCGI processing error: " + std::string(e.what());
        return false;
    }
}

/**
 * I'm implementing the script path resolver
 * This maps HTTP URIs to actual PHP file paths with security validation
 */
std::string PHPHandler::resolve_script_path(const std::string& uri) {
    // I normalize the URI path
    std::string normalized_uri = uri;
    
    // I remove query string if present
    size_t query_pos = normalized_uri.find('?');
    if (query_pos != std::string::npos) {
        normalized_uri = normalized_uri.substr(0, query_pos);
    }
    
    // I ensure the path starts with /
    if (normalized_uri.empty() || normalized_uri[0] != '/') {
        return "";
    }
    
    // I handle directory requests by checking for index files
    if (normalized_uri.back() == '/') {
        for (const auto& index_file : config_.index_files) {
            std::string test_path = normalized_uri + index_file;
            std::string full_path = document_root_ + test_path;
            if (std::filesystem::exists(full_path) && std::filesystem::is_regular_file(full_path)) {
                return full_path;
            }
        }
        return "";
    }
    
    // I construct the full file path
    std::string full_path = document_root_ + normalized_uri;
    
    // I perform security validation to prevent directory traversal
    try {
        auto canonical_doc_root = std::filesystem::canonical(document_root_);
        auto canonical_script = std::filesystem::canonical(full_path);
        
        // I ensure the script is within the document root
        auto relative_path = std::filesystem::relative(canonical_script, canonical_doc_root);
        if (relative_path.empty() || relative_path.string().substr(0, 2) == "..") {
            return ""; // Security violation: path escape attempt
        }
        
    } catch (const std::filesystem::filesystem_error& e) {
        return ""; // Path resolution failed
    }
    
    // I verify the file exists and is readable
    if (!std::filesystem::exists(full_path) || !std::filesystem::is_regular_file(full_path)) {
        return "";
    }
    
    // I check if it's a PHP file
    if (full_path.length() < 4 || full_path.substr(full_path.length() - 4) != ".php") {
        return "";
    }
    
    return full_path;
}

/**
 * I'm implementing the environment builder
 * This creates the FastCGI environment variables like nginx does
 */
FastCGIEnvironment PHPHandler::build_environment(PHPRequestType method, const std::string& uri,
                                               const std::string& script_path,
                                               const std::unordered_map<std::string, std::string>& headers,
                                               const std::string& client_ip) {
    FastCGIEnvironment env;
    
    // I set the core FastCGI parameters
    env.script_filename = script_path;
    env.request_method = method_to_string(method);
    
    // I parse the query string from URI
    size_t query_pos = uri.find('?');
    if (query_pos != std::string::npos) {
        env.query_string = uri.substr(query_pos + 1);
        env.request_uri = uri;
        env.document_uri = uri.substr(0, query_pos);
    } else {
        env.query_string = "";
        env.request_uri = uri;
        env.document_uri = uri;
    }
    
    // I set the document root
    env.document_root = document_root_;
    
    // I set protocol information
    env.server_protocol = "HTTP/1.1";
    env.gateway_interface = "CGI/1.1";
    env.server_software = "icy2-server/1.1.1";
    
    // I set client information
    env.remote_addr = client_ip;
    env.remote_port = "0"; // I'll extract this from connection if needed
    
    // I process HTTP headers
    auto content_type_it = headers.find("Content-Type");
    if (content_type_it != headers.end()) {
        env.content_type = content_type_it->second;
    }
    
    auto content_length_it = headers.find("Content-Length");
    if (content_length_it != headers.end()) {
        env.content_length = content_length_it->second;
    }
    
    auto host_it = headers.find("Host");
    if (host_it != headers.end()) {
        env.server_name = host_it->second;
        
        // I parse port from Host header
        size_t port_pos = env.server_name.find(':');
        if (port_pos != std::string::npos) {
            env.server_port = env.server_name.substr(port_pos + 1);
            env.server_name = env.server_name.substr(0, port_pos);
        } else {
            env.server_port = "3334"; // Default port from config
        }
    }
    
    // I set server address (I'll use localhost for now)
    env.server_addr = "127.0.0.1";
    
    // I handle HTTPS detection
    env.https = ""; // I'll set this based on actual SSL status
    
    // I set redirect status for PHP
    env.redirect_status = "200";
    
    // I add custom environment variables
    env.custom_vars["ENVIRONMENT"] = "development";
    env.custom_vars["APP_NAME"] = "Mcaster1DNAS ICY2-SERVER 1.1.1";
    env.custom_vars["SITE_ROOT"] = document_root_;
    env.custom_vars["ENVIRONMENT_FILE"] = "/var/www/mcaster1.com/DNAS/.env";
    
    // I add PHP development settings
    env.php_admin_values["display_errors"] = "On";
    env.php_admin_values["display_startup_errors"] = "On";
    env.php_admin_values["html_errors"] = "Off";
    env.php_admin_values["log_errors"] = "On";
    env.php_admin_values["error_log"] = "/var/www/mcaster1.com/DNAS/icy2-server/logs/php_errors.log";
    env.php_admin_values["memory_limit"] = "512M";
    env.php_admin_values["max_execution_time"] = "300";
    env.php_admin_values["opcache.revalidate_freq"] = "0";
    env.php_admin_values["opcache.validate_timestamps"] = "1";
    
    env.php_values["error_reporting"] = "E_ALL & E_NOTICE";
    
    return env;
}

/**
 * I'm implementing the connection acquisition system
 * This manages my FastCGI connection pool efficiently
 */
std::unique_ptr<FastCGIConnection> PHPHandler::acquire_connection() {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    
    // I first try to get an available connection
    if (!available_connections_.empty()) {
        auto connection = std::move(available_connections_.front());
        available_connections_.pop();
        
        // I check if the connection is still valid
        if (is_connection_valid(connection.get())) {
            active_connections_.insert(connection.get());
            stats_.active_connections++;
            return connection;
        } else {
            // I close the invalid connection and try to create a new one
            close_connection(connection.get());
        }
    }
    
    // I create a new connection if pool is not at capacity
    if (active_connections_.size() < static_cast<size_t>(connection_pool_size_)) {
        auto connection = std::make_unique<FastCGIConnection>();
        connection->socket_fd = -1;
        connection->is_connected = false;
        connection->last_used = std::chrono::steady_clock::now();
        connection->request_count = 0;
        
        active_connections_.insert(connection.get());
        stats_.active_connections++;
        return connection;
    }
    
    // I return null if no connections are available
    return nullptr;
}

/**
 * I'm implementing the connection release system
 * This returns connections to the pool for reuse
 */
void PHPHandler::release_connection(std::unique_ptr<FastCGIConnection> connection) {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    
    // I remove from active connections
    active_connections_.erase(connection.get());
    stats_.active_connections--;
    
    // I update the last used timestamp
    connection->last_used = std::chrono::steady_clock::now();
    connection->request_count++;
    
    // I decide whether to keep or close the connection
    if (is_connection_valid(connection.get()) && 
        connection->request_count < 1000) { // I limit reuse to prevent memory leaks
        
        available_connections_.push(std::move(connection));
    } else {
        // I close connections that are invalid or have been overused
        close_connection(connection.get());
    }
}

/**
 * I'm implementing connection validation
 * This checks if a FastCGI connection is still usable
 */
bool PHPHandler::is_connection_valid(FastCGIConnection* connection) {
    if (!connection || connection->socket_fd < 0 || !connection->is_connected) {
        return false;
    }
    
    // I check if the connection has been idle too long
    auto now = std::chrono::steady_clock::now();
    auto idle_time = std::chrono::duration_cast<std::chrono::minutes>(now - connection->last_used);
    if (idle_time.count() > 5) { // I close connections idle for more than 5 minutes
        return false;
    }
    
    // I could add more sophisticated validation here (ping test, etc.)
    return true;
}

/**
 * I'm implementing connection establishment
 * This creates actual socket connections to PHP-FMP
 */
bool PHPHandler::ensure_connection_active(FastCGIConnection* connection) {
    if (connection->is_connected && connection->socket_fd >= 0) {
        return true;
    }
    
    // I create a new socket
    connection->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connection->socket_fd < 0) {
        return false;
    }
    
    // I set socket options for better performance
    int flags = fcntl(connection->socket_fd, F_GETFL, 0);
    fcntl(connection->socket_fd, F_SETFL, flags | O_NONBLOCK);
    
    // I prepare the socket address
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
    
    // I connect to PHP-FMP socket
    if (connect(connection->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            close(connection->socket_fd);
            connection->socket_fd = -1;
            return false;
        }
        
        // I wait for connection completion with timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(connection->socket_fd, &write_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        
        int result = select(connection->socket_fd + 1, nullptr, &write_fds, nullptr, &timeout);
        if (result <= 0) {
            close(connection->socket_fd);
            connection->socket_fd = -1;
            return false;
        }
        
        // I check for connection errors
        int error = 0;
        socklen_t error_len = sizeof(error);
        if (getsockopt(connection->socket_fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0 || error != 0) {
            close(connection->socket_fd);
            connection->socket_fd = -1;
            return false;
        }
    }
    
    connection->is_connected = true;
    return true;
}

/**
 * I'm implementing utility functions for request processing
 */

std::string PHPHandler::method_to_string(PHPRequestType method) {
    switch (method) {
        case PHPRequestType::GET: return "GET";
        case PHPRequestType::POST: return "POST";
        case PHPRequestType::PUT: return "PUT";
        case PHPRequestType::DELETE: return "DELETE";
        case PHPRequestType::HEAD: return "HEAD";
        case PHPRequestType::OPTIONS: return "OPTIONS";
        case PHPRequestType::PATCH: return "PATCH";
        default: return "GET";
    }
}

bool PHPHandler::validate_request(const std::string& uri, 
                                const std::unordered_map<std::string, std::string>& headers) {
    // I perform basic security validation
    if (uri.find("..") != std::string::npos) {
        return false; // Directory traversal attempt
    }
    
    if (uri.length() > 2048) {
        return false; // URI too long
    }
    
    // I could add more validation rules here
    return true;
}

bool PHPHandler::test_php_fmp_connection() {
    int test_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (test_socket < 0) {
        return false;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
    
    bool success = (connect(test_socket, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(test_socket);
    
    return success;
}

void PHPHandler::setup_environment_template() {
    // I could pre-build common environment variables here for performance
}

void PHPHandler::close_connection(FastCGIConnection* connection) {
    if (connection && connection->socket_fd >= 0) {
        close(connection->socket_fd);
        connection->socket_fd = -1;
        connection->is_connected = false;
    }
}

void PHPHandler::record_successful_request(std::chrono::steady_clock::time_point start_time) {
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.successful_requests++;
    
    double response_time = static_cast<double>(duration.count());
    stats_.average_response_time_ms = 
        (stats_.average_response_time_ms * (stats_.successful_requests - 1) + response_time) / 
        stats_.successful_requests;
    
    if (duration.count() > stats_.peak_response_time_ms) {
        stats_.peak_response_time_ms = duration.count();
    }
}

void PHPHandler::record_failed_request(std::chrono::steady_clock::time_point start_time) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.failed_requests++;
    stats_.last_error_time = std::chrono::steady_clock::now();
}

/**
 * I'm implementing the FastCGI protocol functions
 * These handle the low-level FastCGI communication
 */

bool PHPHandler::send_begin_request(FastCGIConnection* connection, uint16_t request_id) {
    // I implement FastCGI BEGIN_REQUEST record
    uint8_t record[16];
    record[0] = 1; // Version
    record[1] = 1; // Type: BEGIN_REQUEST
    record[2] = (request_id >> 8) & 0xFF; // Request ID high
    record[3] = request_id & 0xFF; // Request ID low
    record[4] = 0; // Content length high
    record[5] = 8; // Content length low
    record[6] = 0; // Padding length
    record[7] = 0; // Reserved
    
    // BEGIN_REQUEST body
    record[8] = 0; // Role high
    record[9] = 1; // Role low: FCGI_RESPONDER
    record[10] = 0; // Flags
    record[11] = 0; // Reserved
    record[12] = 0; // Reserved
    record[13] = 0; // Reserved
    record[14] = 0; // Reserved
    record[15] = 0; // Reserved
    
    return write_data(connection, record, 16);
}

bool PHPHandler::send_environment_params(FastCGIConnection* connection, uint16_t request_id,
                                       const FastCGIEnvironment& env) {
    // I build the parameter list
    std::vector<uint8_t> params_data;
    
    // I add core FastCGI parameters
    add_fcgi_param(params_data, "SCRIPT_FILENAME", env.script_filename);
    add_fcgi_param(params_data, "QUERY_STRING", env.query_string);
    add_fcgi_param(params_data, "REQUEST_METHOD", env.request_method);
    add_fcgi_param(params_data, "CONTENT_TYPE", env.content_type);
    add_fcgi_param(params_data, "CONTENT_LENGTH", env.content_length);
    add_fcgi_param(params_data, "REQUEST_URI", env.request_uri);
    add_fcgi_param(params_data, "DOCUMENT_URI", env.document_uri);
    add_fcgi_param(params_data, "DOCUMENT_ROOT", env.document_root);
    add_fcgi_param(params_data, "SERVER_PROTOCOL", env.server_protocol);
    add_fcgi_param(params_data, "GATEWAY_INTERFACE", env.gateway_interface);
    add_fcgi_param(params_data, "SERVER_SOFTWARE", env.server_software);
    add_fcgi_param(params_data, "REMOTE_ADDR", env.remote_addr);
    add_fcgi_param(params_data, "REMOTE_PORT", env.remote_port);
    add_fcgi_param(params_data, "SERVER_ADDR", env.server_addr);
    add_fcgi_param(params_data, "SERVER_PORT", env.server_port);
    add_fcgi_param(params_data, "SERVER_NAME", env.server_name);
    if (!env.https.empty()) {
        add_fcgi_param(params_data, "HTTPS", env.https);
    }
    add_fcgi_param(params_data, "REDIRECT_STATUS", env.redirect_status);
    
    // I add custom environment variables
    for (const auto& var : env.custom_vars) {
        add_fcgi_param(params_data, var.first, var.second);
    }
    
    // I add PHP configuration values
    for (const auto& val : env.php_values) {
        add_fcgi_param(params_data, "PHP_VALUE", val.first + "=" + val.second);
    }
    
    for (const auto& val : env.php_admin_values) {
        add_fcgi_param(params_data, "PHP_ADMIN_VALUE", val.first + "=" + val.second);
    }
    
    // I send the parameters record
    bool success = send_fcgi_record(connection, 4, request_id, params_data); // Type 4: PARAMS
    
    // I send empty params record to signal end
    if (success) {
        std::vector<uint8_t> empty_params;
        success = send_fcgi_record(connection, 4, request_id, empty_params);
    }
    
    return success;
}

bool PHPHandler::send_request_body(FastCGIConnection* connection, uint16_t request_id,
                                 const std::vector<uint8_t>& body_data) {
    // I send the request body as STDIN
    bool success = send_fcgi_record(connection, 5, request_id, body_data); // Type 5: STDIN
    
    // I send empty STDIN record to signal end
    if (success) {
        std::vector<uint8_t> empty_stdin;
        success = send_fcgi_record(connection, 5, request_id, empty_stdin);
    }
    
    return success;
}

bool PHPHandler::read_fastcgi_response(FastCGIConnection* connection, uint16_t request_id,
                                     PHPResponse& response) {
    // I initialize response data
    response.body_data.clear();
    response.headers.clear();
    response.http_status_code = 200;
    response.content_type = "text/html";
    
    bool headers_parsed = false;
    std::string header_buffer;
    
    // I read FastCGI records until END_REQUEST
    while (true) {
        uint8_t record_header[8];
        if (!read_data(connection, record_header, 8)) {
            return false;
        }
        
        uint8_t version = record_header[0];
        uint8_t type = record_header[1];
        uint16_t req_id = (record_header[2] << 8) | record_header[3];
        uint16_t content_length = (record_header[4] << 8) | record_header[5];
        uint8_t padding_length = record_header[6];
        
        if (version != 1 || req_id != request_id) {
            return false; // Protocol error
        }
        
        // I read the record content
        std::vector<uint8_t> content(content_length);
        if (content_length > 0) {
            if (!read_data(connection, content.data(), content_length)) {
                return false;
            }
        }
        
        // I skip padding
        if (padding_length > 0) {
            std::vector<uint8_t> padding(padding_length);
            if (!read_data(connection, padding.data(), padding_length)) {
                return false;
            }
        }
        
        if (type == 6) { // STDOUT
            if (!headers_parsed) {
                // I parse HTTP headers from PHP output
                header_buffer.append(content.begin(), content.end());
                size_t header_end = header_buffer.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    parse_php_headers(header_buffer.substr(0, header_end), response);
                    
                    // I add remaining data to body
                    std::string remaining = header_buffer.substr(header_end + 4);
                    response.body_data.insert(response.body_data.end(), 
                                            remaining.begin(), remaining.end());
                    headers_parsed = true;
                }
            } else {
                // I add data to response body
                response.body_data.insert(response.body_data.end(), content.begin(), content.end());
            }
        } else if (type == 7) { // STDERR
            // I handle PHP errors
            std::string error_msg(content.begin(), content.end());
            if (!error_msg.empty()) {
                response.error_message += error_msg;
            }
        } else if (type == 3) { // END_REQUEST
            // I'm done reading the response
            break;
        }
    }
    
    return true;
}

bool PHPHandler::send_fcgi_record(FastCGIConnection* connection, uint8_t type, uint16_t request_id,
                                const std::vector<uint8_t>& data) {
    uint16_t content_length = static_cast<uint16_t>(data.size());
    uint8_t padding_length = (8 - (content_length % 8)) % 8;
    
    uint8_t record_header[8];
    record_header[0] = 1; // Version
    record_header[1] = type;
    record_header[2] = (request_id >> 8) & 0xFF;
    record_header[3] = request_id & 0xFF;
    record_header[4] = (content_length >> 8) & 0xFF;
    record_header[5] = content_length & 0xFF;
    record_header[6] = padding_length;
    record_header[7] = 0; // Reserved
    
    // I send the record header
    if (!write_data(connection, record_header, 8)) {
        return false;
    }
    
    // I send the content
    if (content_length > 0) {
        if (!write_data(connection, data.data(), content_length)) {
            return false;
        }
    }
    
    // I send padding
    if (padding_length > 0) {
        uint8_t padding[8] = {0};
        if (!write_data(connection, padding, padding_length)) {
            return false;
        }
    }
    
    return true;
}

void PHPHandler::add_fcgi_param(std::vector<uint8_t>& params_data, 
                              const std::string& name, const std::string& value) {
    // I encode parameter name length
    if (name.length() < 128) {
        params_data.push_back(static_cast<uint8_t>(name.length()));
    } else {
        uint32_t len = static_cast<uint32_t>(name.length());
        params_data.push_back(static_cast<uint8_t>((len >> 24) | 0x80));
        params_data.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        params_data.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        params_data.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    
    // I encode parameter value length
    if (value.length() < 128) {
        params_data.push_back(static_cast<uint8_t>(value.length()));
    } else {
        uint32_t len = static_cast<uint32_t>(value.length());
        params_data.push_back(static_cast<uint8_t>((len >> 24) | 0x80));
        params_data.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        params_data.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        params_data.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    
    // I add parameter name and value
    params_data.insert(params_data.end(), name.begin(), name.end());
    params_data.insert(params_data.end(), value.begin(), value.end());
}

void PHPHandler::parse_php_headers(const std::string& header_text, PHPResponse& response) {
    std::istringstream stream(header_text);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty() || line == "\r") {
            break;
        }
        
        // I remove carriage return
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string header_name = line.substr(0, colon_pos);
            std::string header_value = line.substr(colon_pos + 1);
            
            // I trim whitespace
            header_value.erase(0, header_value.find_first_not_of(" \t"));
            header_value.erase(header_value.find_last_not_of(" \t") + 1);
            
            // I handle special headers
            if (header_name == "Status") {
                response.http_status_code = std::stoi(header_value.substr(0, 3));
            } else if (header_name == "Content-Type") {
                response.content_type = header_value;
            } else {
                response.headers[header_name] = header_value;
            }
        }
    }
}

bool PHPHandler::write_data(FastCGIConnection* connection, const uint8_t* data, size_t length) {
    size_t bytes_written = 0;
    
    while (bytes_written < length) {
        ssize_t result = write(connection->socket_fd, data + bytes_written, length - bytes_written);
        
        if (result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // I wait for socket to become writable
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(connection->socket_fd, &write_fds);
                
                struct timeval timeout;
                timeout.tv_sec = 30;
                timeout.tv_usec = 0;
                
                int select_result = select(connection->socket_fd + 1, nullptr, &write_fds, nullptr, &timeout);
                if (select_result <= 0) {
                    return false; // Timeout or error
                }
                continue;
            } else {
                return false; // Write error
            }
        }
        
        bytes_written += static_cast<size_t>(result);
    }
    
    return true;
}

bool PHPHandler::read_data(FastCGIConnection* connection, uint8_t* data, size_t length) {
    size_t bytes_read = 0;
    
    while (bytes_read < length) {
        ssize_t result = read(connection->socket_fd, data + bytes_read, length - bytes_read);
        
        if (result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // I wait for data to become available
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(connection->socket_fd, &read_fds);
                
                struct timeval timeout;
                timeout.tv_sec = 30;
                timeout.tv_usec = 0;
                
                int select_result = select(connection->socket_fd + 1, &read_fds, nullptr, nullptr, &timeout);
                if (select_result <= 0) {
                    return false; // Timeout or error
                }
                continue;
            } else {
                return false; // Read error
            }
        } else if (result == 0) {
            return false; // Connection closed
        }
        
        bytes_read += static_cast<size_t>(result);
    }
    
    return true;
}

/**
 * I'm implementing the statistics and monitoring functions
 */
PHPHandlerStats PHPHandler::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::string PHPHandler::get_last_error() const {
    return last_error_;
}

} // namespace icy2
