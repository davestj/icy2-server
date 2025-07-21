// File: /var/www/mcaster1.com/DNAS/icy2-server/include/config_parser.h
// Author: davestj@gmail.com (David St. John)
// Created: 2025-07-16
// Title: Configuration Parser Header - Corrected for Actual Common Types
// Purpose: I created this header file to define the configuration parser that handles
//          YAML configuration loading, validation, and hot-reloading for ICY2-SERVER.
//          This version is aligned with the actual struct definitions in common_types.h.
//
// Reason: I need a configuration system that works with the actual struct members
//         defined in common_types.h, not imaginary extended versions that don't exist.
//
// Changelog:
// 2025-07-21 - Corrected to match actual struct definitions from common_types.h
// 2025-07-21 - Fixed method signatures and removed non-existent members
// 2025-07-21 - Added missing method declarations for validation functions
// 2025-07-21 - Fixed C++17 compatibility issues with time handling
// 2025-07-16 - Initial implementation with YAML configuration support
//
// Next Dev Feature: I plan to add configuration schema validation and auto-completion
// Git Commit: fix: align config parser with actual common_types.h struct definitions

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
     * I'm providing the main configuration loading method
     * This loads and parses a YAML configuration file
     */
    bool load_config(const std::string& file_path);

    /**
     * I'm providing configuration access methods
     * These allow other components to access the loaded configuration
     */
    std::shared_ptr<ServerConfig> get_config() const;
    bool is_config_loaded() const;
    std::string get_config_file_path() const;

    /**
     * I'm providing configuration validation methods
     * These validate the loaded configuration for correctness
     */
    bool validate_config();
    std::vector<std::string> get_validation_errors() const;
    bool has_validation_errors() const;

    /**
     * I'm providing hot-reload functionality
     * This detects and reloads changed configuration files
     */
    bool is_config_modified() const;
    bool reload_if_modified();
    void set_reload_callback(std::function<void()> callback);

    /**
     * I'm providing configuration file path management
     * These handle configuration file location and access
     */
    void set_config_file_path(const std::string& path);

private:
    // I'm defining core configuration state
    std::shared_ptr<ServerConfig> config_;      // I store the loaded configuration
    std::string config_file_path_;              // I track the config file path
    mutable std::mutex config_mutex_;           // I ensure thread-safe access
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

    // I'm defining validation helper methods - FIXED: Added missing method declarations
    bool validate_network_config(const NetworkConfig& config);
    bool validate_ssl_config(const SSLConfig& config);
    bool validate_authentication_config(const AuthenticationConfig& config);
    bool validate_mount_point_config(const MountPointConfig& config);
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