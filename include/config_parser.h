/**
 * File: include/config_parser.h  
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/config_parser.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file to define the configuration parser that handles
 *          YAML configuration loading, validation, and hot-reloading for ICY2-SERVER.
 *          This version uses common types to avoid struct redefinition conflicts.
 * 
 * Reason: I need a robust configuration system that can parse complex YAML files,
 *         validate all settings, provide helpful error messages, and support
 *         hot-reloading of configuration changes during runtime while sharing
 *         data structures with other components through common_types.h.
 *
 * Changelog:
 * 2025-07-16 - Updated to use common_types.h to resolve struct redefinition errors
 * 2025-07-16 - Removed duplicate MountPointConfig definition
 * 2025-07-16 - Fixed C++17 compatibility with proper time handling
 * 2025-07-16 - Added comprehensive configuration validation and error reporting
 * 2025-07-16 - Implemented hot-reload functionality with file modification tracking
 *
 * Next Dev Feature: I plan to add configuration schema validation and auto-completion
 * Git Commit: refactor: use common types to resolve struct redefinition conflicts
 *
 * TODO: Add configuration schema validation, auto-completion hints, configuration migrations
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

// I'm including the common types header to access shared data structures
#include "common_types.h"

// I'm including necessary headers for configuration parsing
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <mutex>
#include <functional>
#include <fstream>
#include <sstream>

// I'm including YAML parsing library
#include <yaml-cpp/yaml.h>

// I'm including system headers for file operations
#include <sys/stat.h>
#include <sys/types.h>

namespace icy2 {

/**
 * I'm defining configuration structures that are specific to the config parser
 * These complement the common types but are only used for configuration management
 */

/**
 * I'm defining the metadata configuration structure
 * This contains project and build metadata
 */
struct MetadataConfig {
    std::string project;            // I store the project name
    std::string version;            // I store the version string
    std::string merged_by;          // I store who merged the configuration
    std::string merged_on;          // I store when it was merged
    std::string notes;              // I store additional notes
};

/**
 * I'm defining the network configuration structure
 * This contains all network-related settings
 */
struct NetworkConfig {
    int http_port;                  // I store the HTTP port
    int https_port;                 // I store the HTTPS port
    int admin_port;                 // I store the admin interface port
    std::string bind_address;       // I store the bind IP address
    int max_connections;            // I store the maximum connection limit
    int connection_timeout;         // I store connection timeout in seconds
    int keepalive_timeout;          // I store keepalive timeout in seconds
};

/**
 * I'm defining the SSL configuration structure
 * This contains SSL/TLS settings
 */
struct SSLConfig {
    bool enabled;                   // I indicate if SSL is enabled
    std::string cert_file;          // I store the certificate file path
    std::string key_file;           // I store the private key file path
    std::string chain_file;         // I store the certificate chain file path
    std::vector<std::string> protocols; // I store supported TLS protocols
    std::string cipher_suites;      // I store allowed cipher suites
};

/**
 * I'm defining the authentication configuration structure
 * This contains authentication and security settings
 */
struct AuthenticationConfig {
    bool enabled;                   // I indicate if authentication is enabled
    std::string token_secret;       // I store the JWT token secret
    int token_expiration;           // I store token expiration time in hours
    bool allow_anonymous_listeners; // I indicate if anonymous listeners are allowed
    bool require_auth_for_broadcast; // I indicate if broadcasters need authentication
    int max_failed_attempts;       // I store maximum failed login attempts
    int lockout_duration;           // I store lockout duration in minutes
};

/**
 * I'm defining the ICY protocol configuration structure
 * This contains settings for ICY protocol handling
 */
struct ICYProtocolConfig {
    bool legacy_support;            // I indicate if ICY 1.x support is enabled
    bool icy2_support;              // I indicate if ICY 2.0+ support is enabled
    int default_metaint;            // I store default metadata interval
    std::string server_name;        // I store the server identification string
    
    struct {
        bool hashtag_arrays;        // I indicate if hashtag arrays are supported
        bool emoji_support;         // I indicate if emoji metadata is supported
        bool social_integration;    // I indicate if social media integration is enabled
        bool json_metadata;         // I indicate if JSON metadata format is supported
    } icy2_features;
};

/**
 * I'm defining the logging configuration structure
 * This contains all logging-related settings
 */
struct LoggingConfig {
    std::string level;              // I store the log level (DEBUG, INFO, etc.)
    
    struct {
        bool enabled;               // I indicate if file logging is enabled
        std::string log_dir;        // I store the log directory path
        std::string error_file;     // I store the error log file path
        std::string access_log;     // I store the access log file path
        std::string security_log;   // I store the security log file path
        int max_size_mb;            // I store maximum log file size in MB
        int max_files;              // I store maximum number of log files to keep
        bool timestamps;            // I indicate if timestamps should be included
        std::string format;         // I store the log format (text, json)
    } file_logging;
    
    struct {
        bool enabled;               // I indicate if syslog is enabled
        std::string protocol;       // I store the syslog protocol (udp, tcp)
        std::string host;           // I store the syslog server host
        int port;                   // I store the syslog server port
        std::string facility;       // I store the syslog facility
        std::string tag;            // I store the syslog tag
        bool include_level;         // I indicate if log level should be included
        bool include_source;        // I indicate if source info should be included
    } syslog;
};

/**
 * I'm defining the YP directory configuration structure
 * This contains settings for directory server integration
 */
struct YPDirectoryConfig {
    bool enabled;                   // I indicate if YP directory listing is enabled
    
    struct {
        std::string name;           // I store the directory server name
        std::string url;            // I store the directory server URL
        std::string protocol;       // I store the protocol type
        bool enabled;               // I indicate if this directory is enabled
        int update_interval;        // I store update interval in seconds
    } servers[3];                   // I support up to 3 directory servers
    
    struct {
        std::string genre;          // I store the default genre
        std::string description;    // I store the default description
        std::string url;            // I store the default URL
        bool public_listing;        // I indicate default public listing preference
    } default_info;
};

/**
 * I'm defining the PHP configuration structure
 * This contains PHP-FPM integration settings
 */
struct PHPConfig {
    bool enabled;                   // I indicate if PHP-FPM is enabled
    std::string socket_path;        // I store the PHP-FPM socket path
    std::string document_root;      // I store the web document root
    std::vector<std::string> index_files; // I store index file names
    int timeout;                    // I store request timeout in seconds
    std::string buffer_size;        // I store buffer size
    std::string php_version;        // I store PHP version requirement
};

/**
 * I'm defining the API configuration structure
 * This contains REST API settings
 */
struct APIConfig {
    bool enabled;                   // I indicate if the API is enabled
    std::string base_url;           // I store the API base URL path
    bool auth_token_required;       // I indicate if API requires authentication
    int rate_limit_per_minute;      // I store rate limiting setting
    std::string output_format;      // I store default output format
};

/**
 * I'm defining the performance configuration structure
 * This contains performance tuning settings
 */
struct PerformanceConfig {
    int worker_threads;             // I store number of worker threads
    int buffer_size;                // I store buffer size in bytes
    int max_memory_per_connection;  // I store memory limit per connection in KB
    bool connection_pooling;        // I indicate if connection pooling is enabled
    int thread_pool_size;           // I store thread pool size
    bool enable_compression;        // I indicate if compression is enabled
};

/**
 * I'm defining the development configuration structure
 * This contains development and debugging settings
 */
struct DevelopmentConfig {
    bool debug_mode;                // I indicate if debug mode is enabled
    bool enable_cors;               // I indicate if CORS is enabled
    std::vector<std::string> cors_origins; // I store allowed CORS origins
    bool log_requests;              // I indicate if request logging is enabled
    bool mock_mode;                 // I indicate if mock mode is enabled
};

/**
 * I'm defining the main server configuration structure
 * This contains all configuration sections
 * Note: MountPointConfig comes from common_types.h to avoid redefinition
 */
struct ServerConfig {
    MetadataConfig metadata;        // I store project metadata
    NetworkConfig network;          // I store network settings
    SSLConfig ssl;                  // I store SSL settings
    AuthenticationConfig authentication; // I store authentication settings
    MountPointMap mount_points;     // I store mount point configs (using common type)
    ICYProtocolConfig icy_protocol; // I store ICY protocol settings
    LoggingConfig logging;          // I store logging settings
    YPDirectoryConfig yp_directories; // I store YP directory settings
    PHPConfig php_fmp;              // I store PHP-FPM settings
    APIConfig api;                  // I store API settings
    PerformanceConfig performance;  // I store performance settings
    DevelopmentConfig development;  // I store development settings
};

/**
 * I'm defining the configuration metadata structure
 * This tracks configuration file state and validation
 */
struct ConfigurationMetadata {
    std::string file_path;          // I store the configuration file path
    std::chrono::system_clock::time_point last_modified; // I track file modification time (C++17 compatible)
    std::string config_hash;        // I store configuration checksum
    bool validation_passed;         // I flag validation status
    std::vector<std::string> validation_errors; // I store validation error messages
};

/**
 * I'm defining the main configuration parser class
 * This handles all configuration loading, parsing, and validation
 */
class ConfigParser {
public:
    /**
     * I'm creating the constructor
     * This initializes the parser with default settings
     */
    ConfigParser();

    /**
     * I'm creating the destructor
     * This ensures proper cleanup of resources
     */
    ~ConfigParser();

    /**
     * I'm creating the configuration loading method
     * This loads and parses a YAML configuration file
     */
    bool load_config(const std::string& file_path);

    /**
     * I'm creating the configuration reloading method
     * This reloads the current configuration file
     */
    bool reload_config();

    /**
     * I'm creating the configuration validation method
     * This validates all configuration settings
     */
    bool validate_config();

    /**
     * I'm creating the configuration getter method
     * This returns the current configuration (thread-safe)
     */
    const ServerConfig* get_config() const;

    /**
     * I'm creating the configuration modification check method
     * This checks if the configuration file has been modified (C++17 compatible)
     */
    bool is_config_modified() const;

    /**
     * I'm creating the validation error getter method
     * This returns any validation errors found
     */
    std::vector<std::string> get_validation_errors() const;

    /**
     * I'm creating the configuration metadata getter method
     * This returns metadata about the configuration state
     */
    ConfigurationMetadata get_metadata() const;

    /**
     * I'm creating the reload callback setter method
     * This sets a callback to be called when configuration reloads
     */
    void set_reload_callback(std::function<void()> callback);

    /**
     * I'm creating the default configuration generation method
     * This generates a default configuration file
     */
    bool generate_default_config(const std::string& file_path);

    /**
     * I'm creating the configuration merging method
     * This merges configuration from multiple sources
     */
    bool merge_config(const std::string& additional_config_path);

private:
    // I'm defining configuration state
    std::unique_ptr<ServerConfig> config_;  // I store the parsed configuration
    std::string config_file_path_;          // I track the configuration file path
    mutable std::mutex config_mutex_;       // I protect configuration access
    std::chrono::system_clock::time_point last_file_time_; // I track file modification time (C++17 compatible)
    
    // I'm defining validation and error handling
    std::vector<std::string> validation_errors_; // I collect validation errors
    std::function<void()> reload_callback_;  // I call this when config reloads
    
    // I'm defining helper methods for parsing different configuration sections
    bool load_yaml_file(const std::string& file_path, YAML::Node& root);
    bool parse_metadata(const YAML::Node& node, MetadataConfig& config);
    bool parse_network_config(const YAML::Node& node, NetworkConfig& config);
    bool parse_ssl_config(const YAML::Node& node, SSLConfig& config);
    bool parse_authentication_config(const YAML::Node& node, AuthenticationConfig& config);
    bool parse_mount_points(const YAML::Node& node, MountPointMap& mounts);
    bool parse_icy_protocol_config(const YAML::Node& node, ICYProtocolConfig& config);
    bool parse_logging_config(const YAML::Node& node, LoggingConfig& config);
    bool parse_yp_directories_config(const YAML::Node& node, YPDirectoryConfig& config);
    bool parse_php_config(const YAML::Node& node, PHPConfig& config);
    bool parse_api_config(const YAML::Node& node, APIConfig& config);
    bool parse_performance_config(const YAML::Node& node, PerformanceConfig& config);
    bool parse_development_config(const YAML::Node& node, DevelopmentConfig& config);

    // I'm defining validation helper methods
    bool validate_network_config(const NetworkConfig& config);
    bool validate_ssl_config(const SSLConfig& config);
    bool validate_mount_points(const MountPointMap& mounts);
    bool validate_file_paths();
    bool validate_port_ranges();

    // I'm defining utility methods
    void add_validation_error(const std::string& error);
    void clear_validation_errors();
    std::string calculate_config_hash();
    std::string expand_environment_variables(const std::string& input);
    bool create_directories_if_needed();
};

} // namespace icy2

#endif // CONFIG_PARSER_H
