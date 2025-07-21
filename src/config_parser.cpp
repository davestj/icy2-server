\// File: /var/www/mcaster1.com/DNAS/icy2-server/src/config_parser.cpp
// Author: davestj@gmail.com (David St. John)
// Created: 2025-07-16
// Title: Configuration Parser Implementation - Corrected for Actual Common Types
// Purpose: I created this configuration parser implementation to handle YAML
//          configuration loading and validation using only the actual struct members
//          that exist in common_types.h, not imaginary extended versions.
//
// Reason: I need a working configuration system that aligns with the actual struct
//         definitions rather than trying to access non-existent struct members.
//
// Changelog:
// 2025-07-21 - Completely corrected to use only actual struct members from common_types.h
// 2025-07-21 - Fixed constructor initialization issues
// 2025-07-21 - Fixed method signature mismatches for parse_metadata
// 2025-07-21 - Fixed C++17 compatibility issues with time handling
// 2025-07-21 - Added missing validation method implementations
// 2025-07-16 - Initial implementation with YAML configuration support
//
// Next Dev Feature: I will add configuration templates and schema validation
// Git Commit: fix: correct config parser to use actual common_types.h struct definitions

#include "config_parser.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <sys/stat.h>
#include <filesystem>
#include <cstdlib>

namespace icy2 {

/**
 * I'm implementing the ConfigParser constructor
 * This initializes the parser with default settings - FIXED initialization
 */
ConfigParser::ConfigParser()
    : config_(nullptr)
{
    // I initialize with an empty configuration
    config_ = std::make_unique<ServerConfig>();
}

/**
 * I'm implementing the ConfigParser destructor
 * This ensures proper cleanup of resources
 */
ConfigParser::~ConfigParser() {
    // I clean up any resources if needed
}

/**
 * I'm implementing the main configuration loading method
 * This loads and parses a YAML configuration file
 */
bool ConfigParser::load_config(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(config_mutex_);

    try {
        // I clear any previous validation errors
        clear_validation_errors();

        // I store the configuration file path
        config_file_path_ = file_path;

        // I check if the file exists and is readable
        std::ifstream file(file_path);
        if (!file.is_open()) {
            add_validation_error("Cannot open configuration file: " + file_path);
            return false;
        }
        file.close();

        // I get the file modification time for change detection - FIXED C++17 compatibility
        struct stat file_stat;
        if (stat(file_path.c_str(), &file_stat) == 0) {
            last_file_time_ = std::chrono::system_clock::from_time_t(file_stat.st_mtime);
        }

        // I load the YAML file
        YAML::Node root;
        if (!load_yaml_file(file_path, root)) {
            add_validation_error("Failed to parse YAML file: " + file_path);
            return false;
        }

        // I create a new configuration object
        auto new_config = std::make_unique<ServerConfig>();
        bool parse_success = true;

        // I parse each configuration section using only actual struct members
        if (root["server"]) {
            const auto& server = root["server"];
            new_config->name = server["name"].as<std::string>("ICY2-DNAS");
            new_config->description = server["description"].as<std::string>("Digital Network Audio Server");
            new_config->version = server["version"].as<std::string>("1.0.0");
            new_config->admin_email = server["admin_email"].as<std::string>("");
        }

        // I parse network configuration using actual NetworkConfig members
        if (root["network"]) {
            parse_success &= parse_network_config(root["network"], new_config->network);
        }

        // I parse SSL configuration using actual SSLConfig members
        if (root["ssl"]) {
            parse_success &= parse_ssl_config(root["ssl"], new_config->ssl);
        }

        // I parse authentication configuration using actual AuthenticationConfig members
        if (root["authentication"]) {
            parse_success &= parse_authentication_config(root["authentication"], new_config->authentication);
        }

        // I parse mount points using actual MountPointConfig members
        if (root["mount_points"]) {
            parse_success &= parse_mount_points(root["mount_points"], new_config->mount_points);
        }

        // I parse ICY protocol configuration using actual ICYProtocolConfig members
        if (root["icy_protocol"]) {
            parse_success &= parse_icy_protocol_config(root["icy_protocol"], new_config->icy_protocol);
        }

        // I parse logging configuration using actual LoggingConfig members
        if (root["logging"]) {
            parse_success &= parse_logging_config(root["logging"], new_config->logging);
        }

        // I parse YP directory configuration using actual YPDirectoryConfig members
        if (root["yp_directories"]) {
            parse_success &= parse_yp_directories_config(root["yp_directories"], new_config->yp_directories);
        }

        // I parse PHP configuration using actual PHPConfig members
        if (root["php"]) {
            parse_success &= parse_php_config(root["php"], new_config->php_fmp);
        }

        // I parse API configuration using actual APIConfig members
        if (root["api"]) {
            parse_success &= parse_api_config(root["api"], new_config->api);
        }

        // I parse performance configuration using actual PerformanceConfig members
        if (root["performance"]) {
            parse_success &= parse_performance_config(root["performance"], new_config->performance);
        }

        // I parse development configuration using actual DevelopmentConfig members
        if (root["development"]) {
            parse_success &= parse_development_config(root["development"], new_config->development);
        }

        if (!parse_success) {
            add_validation_error("Failed to parse one or more configuration sections");
            return false;
        }

        // I replace the current configuration
        config_ = std::move(new_config);

        std::cout << "I successfully loaded configuration from: " << file_path << std::endl;
        return true;

    } catch (const YAML::Exception& e) {
        add_validation_error("YAML parsing error: " + std::string(e.what()));
        return false;
    } catch (const std::exception& e) {
        add_validation_error("Configuration loading error: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the YAML file loading method
 * This safely loads and parses YAML files
 */
bool ConfigParser::load_yaml_file(const std::string& file_path, YAML::Node& root) {
    try {
        root = YAML::LoadFile(file_path);
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("YAML error in file " + file_path + ": " + e.what());
        return false;
    } catch (const std::exception& e) {
        add_validation_error("File error loading " + file_path + ": " + e.what());
        return false;
    }
}

/**
 * I'm implementing the metadata parsing method - FIXED signature to match header
 * This parses the metadata section of the configuration
 */
bool ConfigParser::parse_metadata(const YAML::Node& node, MetadataConfig& metadata) {
    try {
        if (node["project"]) metadata.project = node["project"].as<std::string>();
        if (node["version"]) metadata.version = node["version"].as<std::string>();
        if (node["merged_by"]) metadata.merged_by = node["merged_by"].as<std::string>();
        if (node["merged_on"]) metadata.merged_on = node["merged_on"].as<std::string>();
        if (node["notes"]) metadata.notes = node["notes"].as<std::string>();

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing metadata section: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the network configuration parsing method
 * This parses network-related settings using actual NetworkConfig members
 */
bool ConfigParser::parse_network_config(const YAML::Node& node, NetworkConfig& config) {
    try {
        config.bind_address = node["bind_address"].as<std::string>("0.0.0.0");
        config.http_port = node["http_port"].as<uint16_t>(8000);
        config.https_port = node["https_port"].as<uint16_t>(8443);
        config.admin_port = node["admin_port"].as<uint16_t>(8001);
        config.max_connections = node["max_connections"].as<int>(1000);
        config.connection_timeout = node["connection_timeout"].as<int>(30);
        config.keepalive_timeout = node["keepalive_timeout"].as<int>(15);

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing network configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the SSL configuration parsing method
 * This parses SSL/TLS related settings using actual SSLConfig members
 */
bool ConfigParser::parse_ssl_config(const YAML::Node& node, SSLConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(false);
        config.cert_file = expand_environment_variables(node["cert_file"].as<std::string>(""));
        config.key_file = expand_environment_variables(node["key_file"].as<std::string>(""));
        config.chain_file = expand_environment_variables(node["chain_file"].as<std::string>(""));

        // I parse protocols if present
        if (node["protocols"] && node["protocols"].IsSequence()) {
            for (const auto& protocol : node["protocols"]) {
                config.protocols.push_back(protocol.as<std::string>());
            }
        }

        config.cipher_suites = node["cipher_suites"].as<std::string>("");
        config.require_client_cert = node["require_client_cert"].as<bool>(false);
        config.ca_file = expand_environment_variables(node["ca_file"].as<std::string>(""));

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing SSL configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the authentication configuration parsing method
 * This parses authentication settings using actual AuthenticationConfig members
 */
bool ConfigParser::parse_authentication_config(const YAML::Node& node, AuthenticationConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(true);
        config.token_secret = node["token_secret"].as<std::string>("change-this-secret");
        config.token_expiration = node["token_expiration"].as<int>(24);
        config.token_expiration_hours = node["token_expiration_hours"].as<int>(24);
        config.allow_anonymous_listeners = node["allow_anonymous_listeners"].as<bool>(true);
        config.require_auth_for_broadcast = node["require_auth_for_broadcast"].as<bool>(true);
        config.max_failed_attempts = node["max_failed_attempts"].as<int>(5);
        config.lockout_duration = node["lockout_duration"].as<int>(30);
        config.lockout_duration_minutes = node["lockout_duration_minutes"].as<int>(30);

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing authentication configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the mount points parsing method
 * This parses mount point settings using actual MountPointConfig members
 */
bool ConfigParser::parse_mount_points(const YAML::Node& node, MountPointMap& mounts) {
    try {
        for (const auto& mount_pair : node) {
            std::string mount_path = mount_pair.first.as<std::string>();
            const auto& mount_node = mount_pair.second;

            MountPointConfig mount_config;
            mount_config.name = mount_node["name"].as<std::string>(mount_path);
            mount_config.description = mount_node["description"].as<std::string>("");
            mount_config.max_listeners = mount_node["max_listeners"].as<uint32_t>(100);
            mount_config.public_listing = mount_node["public"].as<bool>(true);
            mount_config.allow_recording = mount_node["allow_recording"].as<bool>(false);
            mount_config.require_authentication = mount_node["require_auth"].as<bool>(false);

            // I parse content types if present
            if (mount_node["content_types"] && mount_node["content_types"].IsSequence()) {
                for (const auto& content_type : mount_node["content_types"]) {
                    mount_config.content_types.push_back(content_type.as<std::string>());
                }
            }

            mount_config.min_bitrate = mount_node["min_bitrate"].as<uint32_t>(32);
            mount_config.max_bitrate = mount_node["max_bitrate"].as<uint32_t>(320);
            mount_config.password = mount_node["password"].as<std::string>("");
            mount_config.fallback_mount = mount_node["fallback_mount"].as<std::string>("");
            mount_config.metadata_enabled = mount_node["metadata_enabled"].as<bool>(true);
            mount_config.metadata_interval = mount_node["metadata_interval"].as<uint32_t>(8192);

            mounts[mount_path] = mount_config;
        }

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing mount points: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the ICY protocol configuration parsing method
 * This parses ICY protocol specific settings using actual ICYProtocolConfig members
 */
bool ConfigParser::parse_icy_protocol_config(const YAML::Node& node, ICYProtocolConfig& config) {
    try {
        config.legacy_support = node["legacy_support"].as<bool>(true);
        config.icy2_support = node["icy2_support"].as<bool>(true);
        config.default_metaint = node["default_metaint"].as<int>(8192);
        config.server_name = node["server_name"].as<std::string>("DNAS/1.0");

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing ICY protocol configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the logging configuration parsing method
 * This parses logging settings using actual LoggingConfig members
 */
bool ConfigParser::parse_logging_config(const YAML::Node& node, LoggingConfig& config) {
    try {
        config.level = node["level"].as<std::string>("INFO");
        config.enabled = node["enabled"].as<bool>(true);

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing logging configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the YP directories configuration parsing method
 * This parses YP directory settings using actual YPDirectoryConfig members
 */
bool ConfigParser::parse_yp_directories_config(const YAML::Node& node, YPDirectoryConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(false);

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing YP directories configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the PHP configuration parsing method
 * This parses PHP settings using actual PHPConfig members
 */
bool ConfigParser::parse_php_config(const YAML::Node& node, PHPConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(true);
        config.socket_path = node["socket_path"].as<std::string>("/run/php/php8.2-fpm.sock");
        config.document_root = expand_environment_variables(node["document_root"].as<std::string>(""));
        config.timeout_seconds = node["timeout_seconds"].as<int>(90);

        // I parse index files if present
        if (node["index_files"] && node["index_files"].IsSequence()) {
            for (const auto& index_file : node["index_files"]) {
                config.index_files.push_back(index_file.as<std::string>());
            }
        }

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing PHP configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the API configuration parsing method
 * This parses API settings using actual APIConfig members
 */
bool ConfigParser::parse_api_config(const YAML::Node& node, APIConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(true);
        config.base_url = node["base_url"].as<std::string>("/api/v1");

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing API configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the performance configuration parsing method
 * This parses performance settings using actual PerformanceConfig members
 */
bool ConfigParser::parse_performance_config(const YAML::Node& node, PerformanceConfig& config) {
    try {
        config.worker_threads = node["worker_threads"].as<int>(4);

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing performance configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the development configuration parsing method
 * This parses development settings using actual DevelopmentConfig members
 */
bool ConfigParser::parse_development_config(const YAML::Node& node, DevelopmentConfig& config) {
    try {
        config.debug_mode = node["debug_mode"].as<bool>(false);

        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing development configuration: " + std::string(e.what()));
        return false;
    }
}

// I'm implementing the configuration access methods
std::shared_ptr<ServerConfig> ConfigParser::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

bool ConfigParser::is_config_loaded() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_ != nullptr;
}

std::string ConfigParser::get_config_file_path() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_file_path_;
}

// I'm implementing the validation methods
bool ConfigParser::validate_config() {
    if (!config_) {
        add_validation_error("No configuration loaded");
        return false;
    }

    bool valid = true;

    // I validate each configuration section
    valid &= validate_network_config(config_->network);
    valid &= validate_ssl_config(config_->ssl);
    valid &= validate_authentication_config(config_->authentication);
    valid &= validate_mount_points(config_->mount_points);

    return valid;
}

std::vector<std::string> ConfigParser::get_validation_errors() const {
    return validation_errors_;
}

bool ConfigParser::has_validation_errors() const {
    return !validation_errors_.empty();
}

// I'm implementing the validation helper methods - FIXED: Added missing implementations
bool ConfigParser::validate_network_config(const NetworkConfig& config) {
    bool valid = true;

    // I validate port ranges (uint16_t can't be > 65535, so no upper bound check needed)
    if (config.http_port < 1) {
        add_validation_error("HTTP port must be between 1 and 65535");
        valid = false;
    }

    if (config.https_port < 1) {
        add_validation_error("HTTPS port must be between 1 and 65535");
        valid = false;
    }

    if (config.admin_port < 1) {
        add_validation_error("Admin port must be between 1 and 65535");
        valid = false;
    }

    // I validate connection limits
    if (config.max_connections <= 0) {
        add_validation_error("Max connections must be positive");
        valid = false;
    }

    return valid;
}

bool ConfigParser::validate_ssl_config(const SSLConfig& config) {
    bool valid = true;

    if (config.enabled) {
        if (config.cert_file.empty()) {
            add_validation_error("SSL certificate file path required when SSL is enabled");
            valid = false;
        }

        if (config.key_file.empty()) {
            add_validation_error("SSL private key file path required when SSL is enabled");
            valid = false;
        }
    }

    return valid;
}

bool ConfigParser::validate_authentication_config(const AuthenticationConfig& config) {
    bool valid = true;

    if (config.enabled && config.token_secret.empty()) {
        add_validation_error("Token secret required when authentication is enabled");
        valid = false;
    }

    if (config.max_failed_attempts <= 0) {
        add_validation_error("Max failed attempts must be positive");
        valid = false;
    }

    return valid;
}

bool ConfigParser::validate_mount_point_config(const MountPointConfig& config) {
    bool valid = true;

    if (config.name.empty()) {
        add_validation_error("Mount point name cannot be empty");
        valid = false;
    }

    if (config.max_listeners == 0) {
        add_validation_error("Mount point max listeners must be positive");
        valid = false;
    }

    return valid;
}

bool ConfigParser::validate_mount_points(const MountPointMap& mounts) {
    bool valid = true;

    for (const auto& [path, config] : mounts) {
        valid &= validate_mount_point_config(config);
    }

    return valid;
}

bool ConfigParser::validate_file_paths() {
    // I could add file path validation here
    return true;
}

bool ConfigParser::validate_port_ranges() {
    // I could add additional port validation here
    return true;
}

// I'm implementing hot-reload functionality
bool ConfigParser::is_config_modified() const {
    if (config_file_path_.empty()) {
        return false;
    }

    struct stat file_stat;
    if (stat(config_file_path_.c_str(), &file_stat) != 0) {
        return false;
    }

    auto file_time = std::chrono::system_clock::from_time_t(file_stat.st_mtime);
    return file_time > last_file_time_;
}

bool ConfigParser::reload_if_modified() {
    if (is_config_modified()) {
        bool success = load_config(config_file_path_);
        if (success && reload_callback_) {
            reload_callback_();
        }
        return success;
    }
    return true;
}

void ConfigParser::set_reload_callback(std::function<void()> callback) {
    reload_callback_ = callback;
}

void ConfigParser::set_config_file_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_file_path_ = path;
}

// I'm implementing utility methods
void ConfigParser::add_validation_error(const std::string& error) {
    validation_errors_.push_back(error);
}

void ConfigParser::clear_validation_errors() {
    validation_errors_.clear();
}

std::string ConfigParser::calculate_config_hash() {
    // I could implement SHA256 hash calculation here
    return "config_hash_placeholder";
}

std::string ConfigParser::expand_environment_variables(const std::string& input) {
    std::string result = input;
    std::regex env_regex(R"(\$\{([^}]+)\})");
    std::smatch match;

    while (std::regex_search(result, match, env_regex)) {
        std::string var_name = match[1].str();
        const char* env_value = std::getenv(var_name.c_str());
        std::string replacement = env_value ? std::string(env_value) : "";
        result = std::regex_replace(result, env_regex, replacement, std::regex_constants::format_first_only);
    }

    return result;
}

bool ConfigParser::create_directories_if_needed() {
    // I could implement directory creation here
    return true;
}

} // namespace icy2