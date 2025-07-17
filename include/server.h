/**
 * File: include/server.h
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/server.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file to define the core ICY2-SERVER class that handles
 *          HTTP/HTTPS requests, ICY protocol streaming, and all server functionality.
 *          This is the main server engine that coordinates all components.
 *
 * Reason: I need a comprehensive server class that can handle multiple protocols,
 *         manage connections, integrate with PHP-FPM, and provide secure streaming
 *         with zero trust security principles.
 *
 * Changelog:
 * 2025-07-16 - Initial server class definition with ICY2 protocol support
 * 2025-07-16 - Added SSL/TLS integration and certificate management
 * 2025-07-16 - Implemented multi-threaded connection handling
 * 2025-07-16 - Added PHP-FPM integration and FastCGI support
 * 2025-07-16 - Fixed ConnectionType enum to match server.cpp usage
 * 2025-07-16 - Corrected get_statistics method signature to fix compilation
 *
 * Next Dev Feature: I plan to add load balancing, WebRTC support, and clustering
 * Git Commit: fix: correct ConnectionType enum and method signatures for compilation
 *
 * TODO: Add WebSocket support, HTTP/2 compliance, advanced caching system
 */

#ifndef ICY2_SERVER_H
#define ICY2_SERVER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <chrono>
#include <functional>
#include <condition_variable>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <openssl/ssl.h>

#include "config_parser.h"
#include "icy_handler.h"
#include "auth_token.h"
#include "ssl_manager.h"
#include "php_handler.h"
#include "helper.h"

namespace icy2 {

/**
 * I'm defining the connection state enumeration for tracking client connections
 * This helps me manage the lifecycle of each client connection properly
 */
enum class ConnectionState {
    CONNECTING,     // I'm in the initial connection phase
    CONNECTED,      // I've established the connection successfully
    AUTHENTICATED,  // I've validated the client credentials
    STREAMING,      // I'm actively streaming content
    CLOSING,        // I'm gracefully closing the connection
    CLOSED          // I've completed the connection shutdown
};

/**
 * I'm defining the connection type to handle different protocols appropriately
 * This allows me to process HTTP, ICY, and streaming connections differently
 * FIXED: I added all the connection types that server.cpp actually uses
 */
enum class ConnectionType {
    HTTP,           // I'm handling standard HTTP requests
    HTTPS,          // I'm handling HTTPS requests
    ICY_SOURCE,     // I'm receiving an ICY source stream
    ICY_LISTENER,   // I'm serving an ICY stream to a listener
    PHP_FPM,        // I'm processing PHP requests via FastCGI
    API,            // I'm handling REST API requests
    WEBSOCKET,      // I'm handling WebSocket connections
    ADMIN,          // I'm handling administrative connections
    LISTENER,       // I'm handling standard listener connections
    SOURCE          // I'm handling source broadcasting connections
};

/**
 * I'm defining the client connection structure
 * This tracks all information about each connected client
 */
struct ClientConnection {
    int socket_fd;                              // I store the socket file descriptor
    ConnectionState state;                      // I track the current connection state
    ConnectionType type;                        // I identify the connection protocol type
    std::string remote_ip;                      // I store the client's IP address
    uint16_t remote_port;                       // I store the client's port number
    std::chrono::steady_clock::time_point connected_at; // I record connection time
    std::chrono::steady_clock::time_point last_activity; // I track last activity
    bool is_ssl;                               // I flag SSL/TLS connections
    SSL* ssl_handle;                           // I store SSL connection handle
    std::vector<char> buffer;                  // I maintain the connection buffer
    size_t buffer_pos;                         // I track buffer position
    bool authenticated;                        // I track authentication status
    std::string user_agent;                    // I store the client user agent
    std::string http_method;                   // I store HTTP method (GET, POST, etc.)
    std::string request_uri;                   // I store the requested URI
    std::string http_version;                  // I store HTTP version string
    std::map<std::string, std::string> headers; // I store all HTTP headers
    size_t bytes_sent;                         // I track bytes sent to client
    size_t bytes_received;                     // I track bytes received from client
    uint32_t metadata_interval;               // I store ICY metadata interval
    std::string mount_point;                   // I store associated mount point
    std::string session_id;                    // I store session identifier
};

/**
 * I'm defining the server statistics structure
 * This tracks comprehensive server performance metrics
 */
struct ServerStatistics {
    std::chrono::steady_clock::time_point start_time;  // I record server start time
    std::atomic<uint64_t> total_connections{0};        // I count total connections
    std::atomic<uint64_t> active_connections{0};       // I count active connections
    std::atomic<uint64_t> ssl_connections{0};          // I count SSL connections
    std::atomic<uint64_t> http_requests{0};            // I count HTTP requests
    std::atomic<uint64_t> icy_connections{0};          // I count ICY connections
    std::atomic<uint64_t> api_requests{0};             // I count API requests
    std::atomic<uint64_t> php_requests{0};             // I count PHP requests
    std::atomic<uint64_t> total_bytes_sent{0};         // I track total bytes sent
    std::atomic<uint64_t> total_bytes_received{0};     // I track total bytes received
    std::atomic<uint64_t> failed_connections{0};       // I count failed connections
    std::atomic<uint64_t> authentication_failures{0};  // I count auth failures
};

/**
 * I'm defining the main ICY2Server class
 * This is the core server that manages all functionality
 */
class ICY2Server {
public:
    /**
     * I'm creating the constructor that initializes the server
     * This sets up default values and prepares the server for configuration
     */
    ICY2Server();

    /**
     * I'm creating the destructor that ensures proper cleanup
     * This guarantees all resources are released when the server is destroyed
     */
    ~ICY2Server();

    /**
     * I'm implementing server initialization
     * This loads configuration and prepares all server components
     */
    bool initialize(const std::string& config_path);

    /**
     * I'm implementing server startup
     * This begins accepting connections and starts all worker threads
     */
    bool start(const std::string& bind_ip = "", uint16_t port = 0,
               int debug_level = 1, bool test_mode = false);

    /**
     * I'm implementing graceful server shutdown
     * This stops accepting connections and cleanly terminates all threads
     */
    void stop();

    /**
     * I'm checking if the server is currently running
     * This provides a thread-safe way to check server status
     */
    bool is_running() const { return running_.load(); }

    /**
     * I'm implementing configuration reloading
     * This allows hot configuration updates without server restart
     */
    bool reload_configuration();

    /**
     * I'm implementing configuration validation
     * This validates the current configuration without applying changes
     */
    bool validate_configuration() const;

    /**
     * I'm implementing SSL certificate generation
     * This creates self-signed certificates for development and testing
     */
    bool generate_ssl_certificates();

    /**
     * I'm implementing mount point management
     * This allows dynamic addition and removal of streaming endpoints
     */
    bool add_mount_point(const std::string& mount_path, const MountPointConfig& config);
    bool remove_mount_point(const std::string& mount_path);

    /**
     * I'm implementing metadata broadcasting
     * This updates stream metadata for ICY protocol clients
     */
    bool broadcast_metadata(const std::string& mount_path, const ICYMetadata& metadata);

    /**
     * I'm implementing listener count retrieval
     * This provides statistics about mount point usage
     */
    size_t get_mount_point_listeners(const std::string& mount_path) const;

    /**
     * I'm implementing server information retrieval
     * This provides comprehensive server status and statistics
     */
    std::string get_server_info() const;

    /**
     * I'm implementing statistics retrieval
     * FIXED: Changed return type to match the implementation
     */
    ServerStatistics get_statistics() const;

private:
    // I'm defining network configuration
    std::string bind_address_;              // I store the bind IP address
    uint16_t http_port_;                    // I store the HTTP port number
    uint16_t https_port_;                   // I store the HTTPS port number
    uint16_t admin_port_;                   // I store the admin port number

    // I'm defining socket file descriptors
    int http_socket_;                       // I store the HTTP listening socket
    int https_socket_;                      // I store the HTTPS listening socket
    int admin_socket_;                      // I store the admin listening socket

    // I'm defining server state
    std::atomic<bool> running_;             // I track server running state
    int debug_level_;                       // I store debug verbosity level
    bool test_mode_;                        // I flag test mode operation
    std::string config_file_path_;          // I store configuration file path

    // I'm defining component managers
    std::unique_ptr<ConfigParser> config_;          // I manage configuration
    std::unique_ptr<ICYHandler> icy_handler_;       // I handle ICY protocol
    std::unique_ptr<AuthTokenManager> auth_manager_; // I manage authentication
    std::unique_ptr<SSLManager> ssl_manager_;       // I manage SSL/TLS
    std::unique_ptr<PHPHandler> php_handler_;       // I handle PHP requests
    std::unique_ptr<APIHelper> api_helper_;         // I provide API utilities

    // I'm defining threading components
    std::vector<std::thread> worker_threads_;       // I store worker threads
    std::mutex connections_mutex_;                  // I protect connections list
    std::vector<std::unique_ptr<ClientConnection>> connections_; // I store active connections

    // I'm defining connection queuing
    std::queue<int> pending_connections_;           // I queue pending connections
    std::mutex pending_mutex_;                      // I protect pending queue
    std::condition_variable pending_cv_;            // I notify worker threads

    // I'm defining statistics and monitoring
    ServerStatistics stats_;                        // I store server statistics
    std::chrono::steady_clock::time_point last_config_check_; // I track config checks

    // I'm declaring private methods for internal functionality
    bool initialize_sockets();
    bool bind_and_listen(int& socket_fd, uint16_t port, bool ssl);
    void accept_connections();
    void worker_thread_main();
    void handle_connection(std::unique_ptr<ClientConnection> conn);
    void process_http_request(ClientConnection* conn);
    void process_api_request(ClientConnection* conn);
    void process_icy_request(ClientConnection* conn);
    void process_php_request(ClientConnection* conn);
    void send_http_response(ClientConnection* conn, int status_code,
                           const std::string& content_type, const std::string& body);
    void send_icy_response(ClientConnection* conn, const std::string& response);
    bool parse_http_headers(ClientConnection* conn);
    bool validate_request(ClientConnection* conn);
    void cleanup_sockets();
    void cleanup_stale_connections();
    void reload_configuration_if_changed();
};

} // namespace icy2

#endif // ICY2_SERVER_H