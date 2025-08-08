#ifndef PHP_HANDLER_H
#define PHP_HANDLER_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>

#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>
#include <functional>
#include <fcgiapp.h>
#include "common_types.h"

// Configuration is handled entirely via the constructor.  Legacy
// configure/add_pool/remove_pool methods have been removed from the
// public interface.

namespace icy2 {

enum class PHPRequestType {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH
};

enum class PHPResponseStatus {
    SUCCESS,
    PHP_ERROR,
    FCGI_ERROR,
    TIMEOUT,
    FILE_NOT_FOUND,
    PERMISSION_DENIED,
    INVALID_REQUEST,
    CONNECTION_FAILED,
    BUFFER_OVERFLOW,
    SECURITY_VIOLATION
};


struct FastCGIEnvironment {
    std::string script_filename;
    std::string query_string;
    std::string request_method;
    std::string content_type;
    std::string content_length;
    std::string request_uri;
    std::string document_uri;
    std::string document_root;
    std::string server_protocol;
    std::string gateway_interface;
    std::string server_software;
    std::string remote_addr;
    std::string remote_port;
    std::string server_addr;
    std::string server_port;
    std::string server_name;
    std::string https;
    std::string redirect_status;
    std::unordered_map<std::string, std::string> custom_vars;
    std::unordered_map<std::string, std::string> php_values;
    std::unordered_map<std::string, std::string> php_admin_values;
};

struct PHPResponse {
    PHPResponseStatus status;
    int http_status_code;
    std::unordered_map<std::string, std::string> headers;
    std::vector<uint8_t> body_data;
    std::string content_type;
    std::string error_message;
};

struct FastCGIConnection {
    int socket_fd;
    bool is_connected;
    std::chrono::steady_clock::time_point last_used;
    int request_count;
};

struct PHPHandlerStats {
    std::atomic<uint64_t> total_requests{0};
    std::atomic<uint64_t> successful_requests{0};
    std::atomic<uint64_t> failed_requests{0};
    double average_response_time_ms{0.0};
    uint64_t peak_response_time_ms{0};
    std::atomic<uint64_t> active_connections{0};
    std::chrono::steady_clock::time_point last_error_time;
};

class PHPHandler {
public:
    /**
     * I'm creating the constructor to initialize the PHP handler
     */
    PHPHandler(const std::string& socket_path, const std::string& document_root,
               const PHPConfig& config);

    /**
     * I'm creating the destructor to clean up resources
     */
    virtual ~PHPHandler();

    bool initialize();
    void shutdown();

    bool handle_http_request(PHPRequestType method, const std::string& uri,
                             const std::unordered_map<std::string, std::string>& headers,
                             const std::vector<uint8_t>& body_data,
                             const std::string& client_ip,
                             PHPResponse& response);

    PHPHandlerStats get_statistics() const;
    std::string get_last_error() const;

private:
    bool process_fastcgi_request(FastCGIConnection* connection, PHPRequestType method,
                                 const std::string& uri, const std::string& script_path,
                                 const std::unordered_map<std::string, std::string>& headers,
                                 const std::vector<uint8_t>& body_data,
                                 const std::string& client_ip,
                                 PHPResponse& response);
    std::string resolve_script_path(const std::string& uri);
    FastCGIEnvironment build_environment(PHPRequestType method, const std::string& uri,
                                         const std::string& script_path,
                                         const std::unordered_map<std::string, std::string>& headers,
                                         const std::string& client_ip);

    std::unique_ptr<FastCGIConnection> acquire_connection();
    void release_connection(std::unique_ptr<FastCGIConnection> connection);
    bool is_connection_valid(FastCGIConnection* connection);
    bool ensure_connection_active(FastCGIConnection* connection);
    std::string method_to_string(PHPRequestType method);
    bool validate_request(const std::string& uri,
                          const std::unordered_map<std::string, std::string>& headers);
    bool test_php_fmp_connection();
    void setup_environment_template();
    void close_connection(FastCGIConnection* connection);
    void record_successful_request(std::chrono::steady_clock::time_point start_time);
    void record_failed_request(std::chrono::steady_clock::time_point start_time);

    bool send_begin_request(FastCGIConnection* connection, uint16_t request_id);
    bool send_environment_params(FastCGIConnection* connection, uint16_t request_id,
                                 const FastCGIEnvironment& env);
    bool send_request_body(FastCGIConnection* connection, uint16_t request_id,
                           const std::vector<uint8_t>& body_data);
    bool read_fastcgi_response(FastCGIConnection* connection, uint16_t request_id,
                               PHPResponse& response);
    bool send_fcgi_record(FastCGIConnection* connection, uint8_t type, uint16_t request_id,
                          const std::vector<uint8_t>& data);
    void add_fcgi_param(std::vector<uint8_t>& params_data, const std::string& name,
                        const std::string& value);
    void parse_php_headers(const std::string& header_text, PHPResponse& response);
    bool write_data(FastCGIConnection* connection, const uint8_t* data, size_t length);
    bool read_data(FastCGIConnection* connection, uint8_t* data, size_t length);

    std::string socket_path_;
    std::string document_root_;
    PHPConfig config_;
    int connection_pool_size_;
    int request_timeout_ms_;
    uint16_t next_request_id_;
    bool is_initialized_;
    std::queue<std::unique_ptr<FastCGIConnection>> available_connections_;
    std::set<FastCGIConnection*> active_connections_;
    std::mutex connection_mutex_;

    PHPHandlerStats stats_;
    mutable std::mutex stats_mutex_;
    std::string last_error_;
};

} // namespace icy2

#endif // PHP_HANDLER_H

