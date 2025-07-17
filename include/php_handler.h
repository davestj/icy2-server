/**
 * File: include/php_handler.h
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/php_handler.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file to define the PHP-FPM integration handler that
 *          allows ICY2-SERVER to process PHP files just like nginx does with FastCGI.
 *          This enables web admin interfaces and dynamic content generation.
 * 
 * Reason: I need seamless PHP integration to support web-based administration,
 *         dynamic configuration management, and modern web interfaces while
 *         maintaining the performance and security of the core streaming server.
 *
 * Changelog:
 * 2025-07-16 - Initial PHP handler with FastCGI protocol implementation
 * 2025-07-16 - Added PHP-FPM socket communication and request processing
 * 2025-07-16 - Implemented environment variable passing and configuration
 * 2025-07-16 - Added error handling and debugging capabilities
 * 2025-07-16 - Integrated security features and request validation
 *
 * Next Dev Feature: I plan to add PHP session management and advanced caching
 * Git Commit: feat: implement PHP-FPM integration with FastCGI protocol support
 *
 * TODO: Add PHP session handling, response caching, load balancing across PHP pools
 */

#ifndef PHP_HANDLER_H
#define PHP_HANDLER_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <fcgiapp.h>

namespace icy2 {

/**
 * I'm defining PHP request types that I can handle
 * This helps me process different types of PHP requests appropriately
 */
enum class PHPRequestType {
    GET,                // I handle HTTP GET requests
    POST,               // I handle HTTP POST requests
    PUT,                // I handle HTTP PUT requests
    DELETE,             // I handle HTTP DELETE requests
    HEAD,               // I handle HTTP HEAD requests
    OPTIONS,            // I handle HTTP OPTIONS requests
    PATCH               // I handle HTTP PATCH requests
};

/**
 * I'm defining PHP response status codes
 * This tracks the outcome of PHP request processing
 */
enum class PHPResponseStatus {
    SUCCESS,            // I successfully processed the PHP request
    PHP_ERROR,          // I encountered a PHP runtime error
    FCGI_ERROR,         // I encountered a FastCGI protocol error
    TIMEOUT,            // I exceeded the request timeout
    FILE_NOT_FOUND,     // I couldn't find the requested PHP file
    PERMISSION_DENIED,  // I don't have permission to access the file
    INVALID_REQUEST,    // I received an invalid or malformed request
    CONNECTION_FAILED,  // I couldn't connect to PHP-FPM
    BUFFER_OVERFLOW,    // I exceeded buffer limits
    SECURITY_VIOLATION  // I detected a security issue
};

/**
 * I'm creating a structure for FastCGI environment parameters
 * This defines all the environment variables I pass to PHP-FPM
 */
struct FastCGIEnvironment {
    std::string script_filename;        // I set SCRIPT_FILENAME for the PHP file
    std::string query_string;           // I pass QUERY_STRING from the URL
    std::string request_method;         // I set REQUEST_METHOD (GET, POST, etc.)
    std::string content_type;           // I pass CONTENT_TYPE header
    std::string content_length;         // I set CONTENT_LENGTH for POST data
    std::string request_uri;            // I pass REQUEST_URI from the client
    std::string document_uri;           // I set DOCUMENT_URI for the script
    std::string document_root;          // I define DOCUMENT_ROOT for PHP
    std::string server_protocol;        // I set SERVER_PROTOCOL (HTTP/1.1)
    std::string gateway_interface;      // I set GATEWAY_INTERFACE (CGI/1.1)
    std::string server_software;        // I identify SERVER_SOFTWARE
    std::string remote_addr;            // I pass REMOTE_ADDR client IP
    std::string remote_port;            // I pass REMOTE_PORT client port
    std::string server_addr;            // I set SERVER_ADDR server IP
    std::string server_port;            // I set SERVER_PORT server port
    std::string server_name;            // I set SERVER_NAME hostname
    std::string https;                  // I flag HTTPS if SSL connection
    std::string redirect_status;        // I set REDIRECT_STATUS (200)
    std::string path_info;              // I set PATH_INFO if present
    std::string path_translated;        // I set PATH_TRANSLATED if needed
    std::string script_name;            // I set SCRIPT_NAME for the script
    std::map<std::string, std::string> http_headers; // I pass all HTTP headers
    std::map<std::string, std::string> custom_env;   // I allow custom environment variables
};

/**
 * I'm creating a structure for PHP request information
 * This contains all details about a PHP request I'm processing
 */
struct PHPRequest {
    std::string request_id;             // I assign unique request identifier
    PHPRequestType method;              // I identify the HTTP method
    std::string uri;                    // I store the request URI
    std::string script_path;            // I determine the PHP script path
    std::string query_string;           // I extract query parameters
    std::map<std::string, std::string> headers; // I store all request headers
    std::vector<uint8_t> body_data;     // I store POST/PUT request body
    std::string client_ip;              // I track client IP address
    uint16_t client_port;               // I track client port
    FastCGIEnvironment environment;     // I prepare FastCGI environment
    std::chrono::steady_clock::time_point start_time; // I track request start time
    int timeout_seconds;                // I set request timeout
    bool is_ssl;                        // I flag SSL connections
    std::string user_agent;             // I store client user agent
    std::string referer;                // I store HTTP referer
    std::string session_id;             // I track PHP session ID
};

/**
 * I'm creating a structure for PHP response information
 * This contains the response data from PHP-FPM processing
 */
struct PHPResponse {
    PHPResponseStatus status;           // I track response status
    int http_status_code;               // I store HTTP status code
    std::map<std::string, std::string> headers; // I store response headers
    std::vector<uint8_t> body_data;     // I store response body
    std::string content_type;           // I identify response content type
    size_t content_length;              // I track response size
    std::chrono::steady_clock::time_point completion_time; // I track completion time
    std::chrono::milliseconds processing_time; // I measure processing duration
    std::string error_message;          // I store error details if any
    std::string php_error_log;          // I capture PHP error output
    bool connection_keep_alive;         // I flag keep-alive connections
    std::string set_cookie;             // I handle cookie setting
    std::string location_redirect;      // I handle location redirects
};

/**
 * I'm creating a structure for PHP-FPM pool configuration
 * This defines how I connect to and manage PHP-FPM processes
 */
struct PHPPoolConfig {
    std::string pool_name;              // I identify the PHP-FPM pool
    std::string socket_path;            // I connect via Unix socket
    std::string tcp_address;            // I connect via TCP (alternative)
    uint16_t tcp_port;                  // I specify TCP port
    int max_connections;                // I limit concurrent connections
    int connection_timeout_ms;          // I set connection timeout
    int request_timeout_ms;             // I set request timeout
    int idle_timeout_ms;                // I set idle connection timeout
    bool connection_pooling;            // I enable connection pooling
    int pool_size;                      // I set connection pool size
    std::string document_root;          // I define document root for this pool
    std::vector<std::string> index_files; // I list index file names
    std::map<std::string, std::string> default_env; // I set default environment
    std::map<std::string, std::string> php_admin_values; // I set PHP admin values
    bool error_reporting;               // I control PHP error reporting
    std::string error_log_path;         // I specify PHP error log
    int memory_limit_mb;                // I set PHP memory limit
    int max_execution_time;             // I set PHP execution time limit
    bool opcache_enabled;               // I control OPcache
    bool development_mode;              // I flag development configuration
};

/**
 * I'm creating a structure for FastCGI connection management
 * This tracks active connections to PHP-FPM
 */
struct FastCGIConnection {
    int socket_fd;                      // I store socket file descriptor
    std::string pool_name;              // I identify associated pool
    std::chrono::steady_clock::time_point created_at; // I track connection creation
    std::chrono::steady_clock::time_point last_used;  // I track last usage
    bool is_busy;                       // I flag if connection is processing request
    std::string current_request_id;     // I link to current request
    int request_count;                  // I count requests on this connection
    std::vector<uint8_t> read_buffer;   // I buffer incoming data
    std::vector<uint8_t> write_buffer;  // I buffer outgoing data
    size_t read_pos;                    // I track read buffer position
    size_t write_pos;                   // I track write buffer position
};

/**
 * I'm creating a structure for PHP handler statistics
 * This tracks performance and usage metrics
 */
struct PHPHandlerStats {
    std::atomic<uint64_t> total_requests{0};     // I count total PHP requests
    std::atomic<uint64_t> successful_requests{0}; // I count successful requests
    std::atomic<uint64_t> failed_requests{0};    // I count failed requests
    std::atomic<uint64_t> timeout_requests{0};   // I count timeout requests
    std::atomic<uint64_t> bytes_sent{0};         // I count bytes sent to PHP-FPM
    std::atomic<uint64_t> bytes_received{0};     // I count bytes received from PHP-FPM
    std::atomic<uint64_t> active_connections{0}; // I track active FastCGI connections
    std::atomic<uint64_t> total_connections{0};  // I count total connections created
    std::atomic<uint64_t> connection_errors{0};  // I count connection failures
    std::chrono::steady_clock::time_point start_time; // I track handler start time
    std::map<std::string, uint64_t> pool_request_counts; // I count requests per pool
    std::map<int, uint64_t> status_code_counts; // I count HTTP status codes
    double average_response_time_ms;             // I calculate average response time
    uint64_t max_response_time_ms;               // I track maximum response time
    uint64_t min_response_time_ms;               // I track minimum response time
};

/**
 * I'm defining the main PHP handler class
 * This orchestrates all PHP-FPM integration and request processing
 */
class PHPHandler {
private:
    // I'm defining pool configuration and management
    std::map<std::string, PHPPoolConfig> pools_;        // I store pool configurations
    std::map<std::string, std::vector<FastCGIConnection>> connections_; // I manage connections per pool
    std::mutex pools_mutex_;                            // I protect pool data
    std::mutex connections_mutex_;                      // I protect connection data

    // I'm defining request processing
    std::unordered_map<std::string, PHPRequest> active_requests_; // I track active requests
    std::mutex requests_mutex_;                         // I protect request data
    std::atomic<uint64_t> request_counter_;             // I generate unique request IDs

    // I'm defining configuration and state
    bool enabled_;                                      // I control PHP handler functionality
    std::string default_pool_;                          // I identify default pool
    std::string document_root_;                         // I set global document root
    std::vector<std::string> index_files_;              // I list default index files
    int global_timeout_ms_;                             // I set global timeout
    bool security_checks_enabled_;                      // I control security validation

    // I'm defining statistics and monitoring
    PHPHandlerStats stats_;                             // I track handler statistics
    std::mutex stats_mutex_;                            // I protect statistics data

    // I'm defining helper methods
    bool connect_to_pool(const std::string& pool_name, FastCGIConnection& conn); // I connect to PHP-FPM
    void disconnect_from_pool(FastCGIConnection& conn); // I close FastCGI connections
    FastCGIConnection* get_available_connection(const std::string& pool_name); // I get pooled connections
    void return_connection(const std::string& pool_name, FastCGIConnection* conn); // I return connections to pool
    bool send_fastcgi_request(FastCGIConnection& conn, const PHPRequest& request); // I send FastCGI requests
    bool receive_fastcgi_response(FastCGIConnection& conn, PHPResponse& response); // I receive FastCGI responses
    void build_fastcgi_environment(const PHPRequest& request, FastCGIEnvironment& env); // I build environment
    bool validate_php_file_path(const std::string& file_path); // I validate PHP file security
    bool validate_request_security(const PHPRequest& request); // I validate request security
    std::string resolve_script_path(const std::string& uri, const std::string& document_root); // I resolve PHP scripts
    void parse_fastcgi_response_headers(const std::vector<uint8_t>& data, PHPResponse& response); // I parse headers
    void cleanup_expired_connections(); // I remove stale connections
    void update_statistics(const PHPRequest& request, const PHPResponse& response); // I update metrics
    void log_php_request(const PHPRequest& request, const PHPResponse& response); // I log requests
    std::string get_mime_type_for_php_response(const std::string& file_path); // I determine MIME types
    bool is_php_file(const std::string& file_path); // I identify PHP files
    void sanitize_environment_variables(FastCGIEnvironment& env); // I sanitize environment

public:
    /**
     * I'm creating the constructor to initialize the PHP handler
     */
    PHPHandler();

    /**
     * I'm creating the destructor to clean up resources
     */
    virtual ~PHPHandler();

    /**
     * I'm creating the method to configure the PHP handler
     * @param enabled Whether PHP processing is enabled
     * @param document_root Default document root directory
     * @param index_files List of index file names
     * @param timeout_ms Global request timeout in milliseconds
     * @return true if configuration succeeded
     */
    bool configure(bool enabled, const std::string& document_root,
                  const std::vector<std::string>& index_files, int timeout_ms);

    /**
     * I'm creating the method to add a PHP-FPM pool
     * @param pool_name Unique pool identifier
     * @param config Pool configuration
     * @return true if pool was added successfully
     */
    bool add_pool(const std::string& pool_name, const PHPPoolConfig& config);

    /**
     * I'm creating the method to remove a PHP-FPM pool
     * @param pool_name Pool identifier to remove
     * @return true if pool was removed successfully
     */
    bool remove_pool(const std::string& pool_name);

    /**
     * I'm creating the method to process a PHP request
     * @param request PHP request to process
     * @param response Response structure to populate
     * @return true if request was processed successfully
     */
    bool process_request(const PHPRequest& request, PHPResponse& response);

    /**
     * I'm creating the method to handle HTTP request for PHP processing
     * @param method HTTP method
     * @param uri Request URI
     * @param headers HTTP headers
     * @param body Request body data
     * @param client_ip Client IP address
     * @param response Response structure to populate
     * @return true if request was handled successfully
     */
    bool handle_http_request(PHPRequestType method, const std::string& uri,
                           const std::map<std::string, std::string>& headers,
                           const std::vector<uint8_t>& body,
                           const std::string& client_ip,
                           PHPResponse& response);

    /**
     * I'm creating the method to check if a URI should be handled by PHP
     * @param uri Request URI to check
     * @return true if URI should be processed by PHP
     */
    bool should_handle_request(const std::string& uri);

    /**
     * I'm creating the method to get available pools
     * @return Vector of pool names
     */
    std::vector<std::string> get_available_pools() const;

    /**
     * I'm creating the method to get pool statistics
     * @param pool_name Pool to query (empty for all pools)
     * @return JSON string with pool statistics
     */
    std::string get_pool_statistics(const std::string& pool_name = "") const;

    /**
     * I'm creating the method to test PHP-FPM connectivity
     * @param pool_name Pool to test
     * @return true if connection test succeeded
     */
    bool test_pool_connection(const std::string& pool_name);

    /**
     * I'm creating the method to reload PHP pool configuration
     * @param pool_name Pool to reload
     * @return true if reload succeeded
     */
    bool reload_pool_configuration(const std::string& pool_name);

    /**
     * I'm creating the method to set default pool
     * @param pool_name Pool to use as default
     * @return true if default pool was set
     */
    bool set_default_pool(const std::string& pool_name);

    /**
     * I'm creating the method to enable or disable security checks
     * @param enabled Whether to enable security validation
     */
    void set_security_checks(bool enabled) { security_checks_enabled_ = enabled; }

    /**
     * I'm creating the method to get handler statistics
     * @return JSON string with handler statistics
     */
    std::string get_handler_statistics() const;

    /**
     * I'm creating the method to clear connection pools
     * @param pool_name Pool to clear (empty for all pools)
     */
    void clear_connection_pools(const std::string& pool_name = "");

    /**
     * I'm creating the method to set custom environment variables
     * @param pool_name Pool to configure
     * @param env_vars Environment variables to set
     * @return true if environment was configured
     */
    bool set_pool_environment(const std::string& pool_name,
                             const std::map<std::string, std::string>& env_vars);

    /**
     * I'm creating the method to get active request count
     * @return Number of currently processing requests
     */
    size_t get_active_request_count() const;

    /**
     * I'm creating the method to cancel a request
     * @param request_id Request identifier to cancel
     * @return true if request was cancelled
     */
    bool cancel_request(const std::string& request_id);

    /**
     * I'm creating the method to check if PHP handler is enabled
     * @return true if PHP processing is enabled
     */
    bool is_enabled() const { return enabled_; }
};

} // namespace icy2

#endif // PHP_HANDLER_H
