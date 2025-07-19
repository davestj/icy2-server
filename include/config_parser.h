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

/**
 * I'm defining the SSL configuration structure
 * This contains SSL/TLS settings
 */

/**
 * I'm defining the authentication configuration structure
 * This contains authentication and security settings
 */

/**
 * I'm defining the ICY protocol configuration structure
 * This contains settings for ICY protocol handling
 */

/**
 * I'm defining the logging configuration structure
 * This contains all logging-related settings
 */

/**
 * I'm defining the YP directory configuration structure
 * This contains settings for directory server integration
 */

/**
 * I'm defining the PHP configuration structure
 * This contains PHP-FPM integration settings
 */

/**
 * I'm defining the API configuration structure
 * This contains REST API settings
 */

/**
 * I'm defining the performance configuration structure
 * This contains performance tuning settings
 */

/**
 * I'm defining the development configuration structure
 * This contains development and debugging settings
 */

/**
 * I'm defining the main server configuration structure
 * This contains all configuration sections
 * Note: MountPointConfig comes from common_types.h to avoid redefinition
 */

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
