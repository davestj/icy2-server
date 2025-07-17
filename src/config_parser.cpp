/**
 * File: src/config_parser.cpp
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/src/config_parser.cpp
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this configuration parser implementation to handle YAML
 *          configuration loading, validation, and hot reloading for ICY2-SERVER.
 *          This provides comprehensive configuration management with error handling.
 * 
 * Reason: I need a robust configuration system that can parse complex YAML files,
 *         validate all settings, detect file changes for hot reloading, and provide
 *         detailed error reporting for configuration issues.
 *
 * Changelog:
 * 2025-07-16 - Initial config parser with YAML-CPP integration
 * 2025-07-16 - Added comprehensive validation and error handling
 * 2025-07-16 - Implemented hot reload and file change detection
 * 2025-07-16 - Added all configuration sections parsing
 * 2025-07-16 - Integrated environment variable expansion and validation
 *
 * Next Dev Feature: I plan to add remote config loading and config encryption
 * Git Commit: feat: implement comprehensive YAML configuration parser
 *
 * TODO: Add config encryption, remote loading, configuration templates, schema validation
 */

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
 * This initializes the parser with default settings
 */
ConfigParser::ConfigParser() 
    : config_(nullptr)
    , validation_cache_ttl_minutes_(5)
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
        
        // I get the file modification time for change detection
        struct stat file_stat;
        if (stat(file_path.c_str(), &file_stat) == 0) {
            last_file_time_ = std::chrono::file_time_type::clock::from_time_t(file_stat.st_mtime);
        }
        
        // I load the YAML file
        YAML::Node root;
        if (!load_yaml_file(file_path, root)) {
            add_validation_error("Failed to parse YAML file: " + file_path);
            return false;
        }
        
        // I create a new configuration object
        auto new_config = std::make_unique<ServerConfig>();
        new_config->config_file_path = file_path;
        new_config->last_modified = std::chrono::system_clock::now();
        
        // I parse all configuration sections
        bool parse_success = true;
        
        // I parse metadata section
        if (root["metadata"]) {
            parse_success &= parse_metadata(root["metadata"], new_config->metadata);
        }
        
        // I parse server section
        if (root["server"]) {
            auto server_node = root["server"];
            new_config->name = server_node["name"].as<std::string>("ICY2-SERVER");
            new_config->description = server_node["description"].as<std::string>("Digital Network Audio Server");
            new_config->version = server_node["version"].as<std::string>("1.1.1");
            new_config->admin_email = server_node["admin_email"].as<std::string>("admin@localhost");
        }
        
        // I parse network configuration
        if (root["network"]) {
            parse_success &= parse_network_config(root["network"], new_config->network);
        } else {
            add_validation_error("Missing required 'network' configuration section");
            parse_success = false;
        }
        
        // I parse SSL configuration
        if (root["ssl"]) {
            parse_success &= parse_ssl_config(root["ssl"], new_config->ssl);
        }
        
        // I parse authentication configuration
        if (root["authentication"]) {
            parse_success &= parse_authentication_config(root["authentication"], new_config->authentication);
        }
        
        // I parse mount points
        if (root["mount_points"]) {
            parse_success &= parse_mount_points(root["mount_points"], new_config->mount_points);
        }
        
        // I parse ICY protocol configuration
        if (root["icy_protocol"]) {
            parse_success &= parse_icy_protocol_config(root["icy_protocol"], new_config->icy_protocol);
        }
        
        // I parse logging configuration
        if (root["logging"]) {
            parse_success &= parse_logging_config(root["logging"], new_config->logging);
        }
        
        // I parse YP directories configuration
        if (root["yp_directories"]) {
            parse_success &= parse_yp_directories_config(root["yp_directories"], new_config->yp_directories);
        }
        
        // I parse PHP-FPM configuration
        if (root["php_fmp"]) {
            parse_success &= parse_php_config(root["php_fmp"], new_config->php_fmp);
        }
        
        // I parse API configuration
        if (root["api"]) {
            parse_success &= parse_api_config(root["api"], new_config->api);
        }
        
        // I parse performance configuration
        if (root["performance"]) {
            parse_success &= parse_performance_config(root["performance"], new_config->performance);
        }
        
        // I parse development configuration
        if (root["development"]) {
            parse_success &= parse_development_config(root["development"], new_config->development);
        }
        
        if (!parse_success) {
            add_validation_error("Failed to parse one or more configuration sections");
            return false;
        }
        
        // I calculate configuration hash
        new_config->config_hash = calculate_config_hash();
        
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
 * I'm implementing the metadata parsing method
 * This parses the metadata section of the configuration
 */
bool ConfigParser::parse_metadata(const YAML::Node& node, std::map<std::string, std::string>& metadata) {
    try {
        if (node["project"]) metadata["project"] = node["project"].as<std::string>();
        if (node["version"]) metadata["version"] = node["version"].as<std::string>();
        if (node["merged_by"]) metadata["merged_by"] = node["merged_by"].as<std::string>();
        if (node["merged_on"]) metadata["merged_on"] = node["merged_on"].as<std::string>();
        if (node["notes"]) metadata["notes"] = node["notes"].as<std::string>();
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing metadata section: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the network configuration parsing method
 * This parses network-related settings
 */
bool ConfigParser::parse_network_config(const YAML::Node& node, NetworkConfig& config) {
    try {
        config.http_port = node["http_port"].as<int>(3334);
        config.https_port = node["https_port"].as<int>(8443);
        config.admin_port = node["admin_port"].as<int>(8001);
        config.bind_address = node["bind_address"].as<std::string>("0.0.0.0");
        config.max_connections = node["max_connections"].as<int>(1000);
        config.connection_timeout = node["connection_timeout"].as<int>(30);
        config.keepalive_timeout = node["keepalive_timeout"].as<int>(15);
        config.buffer_size = node["buffer_size"].as<int>(65536);
        config.enable_compression = node["enable_compression"].as<bool>(true);
        config.worker_threads = node["worker_threads"].as<int>(4);
        config.connection_pooling = node["connection_pooling"].as<bool>(true);
        config.thread_pool_size = node["thread_pool_size"].as<int>(8);
        config.max_memory_per_connection = node["max_memory_per_connection"].as<int>(1024);
        config.enable_cors = node["enable_cors"].as<bool>(false);
        
        // I parse CORS origins if present
        if (node["cors_origins"] && node["cors_origins"].IsSequence()) {
            for (const auto& origin : node["cors_origins"]) {
                config.cors_origins.push_back(origin.as<std::string>());
            }
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing network configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the SSL configuration parsing method
 * This parses SSL/TLS related settings
 */
bool ConfigParser::parse_ssl_config(const YAML::Node& node, SSLConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(false);
        config.cert_file = expand_environment_variables(node["cert_file"].as<std::string>(""));
        config.key_file = expand_environment_variables(node["key_file"].as<std::string>(""));
        config.chain_file = expand_environment_variables(node["chain_file"].as<std::string>(""));
        config.cipher_suites = node["cipher_suites"].as<std::string>("");
        config.require_client_cert = node["require_client_cert"].as<bool>(false);
        config.verify_client = node["verify_client"].as<bool>(false);
        config.session_timeout = node["session_timeout"].as<int>(300);
        config.session_cache_enabled = node["session_cache_enabled"].as<bool>(true);
        config.compression_enabled = node["compression_enabled"].as<bool>(false);
        config.ocsp_stapling = node["ocsp_stapling"].as<bool>(false);
        
        // I parse TLS protocols
        if (node["protocols"] && node["protocols"].IsSequence()) {
            for (const auto& protocol : node["protocols"]) {
                config.protocols.push_back(protocol.as<std::string>());
            }
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing SSL configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the authentication configuration parsing method
 * This parses authentication and security settings
 */
bool ConfigParser::parse_authentication_config(const YAML::Node& node, AuthenticationConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(true);
        config.token_secret = node["token_secret"].as<std::string>("change-this-secret");
        config.token_expiration_hours = node["token_expiration"].as<int>(24);
        config.allow_anonymous_listeners = node["allow_anonymous_listeners"].as<bool>(true);
        config.require_auth_for_broadcast = node["require_auth_for_broadcast"].as<bool>(true);
        config.max_failed_attempts = node["max_failed_attempts"].as<int>(5);
        config.lockout_duration_minutes = node["lockout_duration"].as<int>(30);
        config.rate_limiting_enabled = node["rate_limiting_enabled"].as<bool>(true);
        config.hash_algorithm = node["hash_algorithm"].as<std::string>("bcrypt");
        config.bcrypt_rounds = node["bcrypt_rounds"].as<int>(12);
        config.two_factor_enabled = node["two_factor_enabled"].as<bool>(false);
        config.geo_blocking_enabled = node["geo_blocking_enabled"].as<bool>(false);
        
        // I parse allowed IPs if present
        if (node["allowed_ips"] && node["allowed_ips"].IsSequence()) {
            for (const auto& ip : node["allowed_ips"]) {
                config.allowed_ips.push_back(ip.as<std::string>());
            }
        }
        
        // I parse blocked IPs if present
        if (node["blocked_ips"] && node["blocked_ips"].IsSequence()) {
            for (const auto& ip : node["blocked_ips"]) {
                config.blocked_ips.push_back(ip.as<std::string>());
            }
        }
        
        // I parse allowed countries if present
        if (node["allowed_countries"] && node["allowed_countries"].IsSequence()) {
            for (const auto& country : node["allowed_countries"]) {
                config.allowed_countries.push_back(country.as<std::string>());
            }
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing authentication configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the mount points parsing method
 * This parses streaming mount point configurations
 */
bool ConfigParser::parse_mount_points(const YAML::Node& node, std::unordered_map<std::string, MountPointConfig>& mounts) {
    try {
        for (const auto& mount_pair : node) {
            std::string mount_path = mount_pair.first.as<std::string>();
            const auto& mount_node = mount_pair.second;
            
            MountPointConfig mount_config;
            mount_config.name = mount_node["name"].as<std::string>(mount_path);
            mount_config.description = mount_node["description"].as<std::string>("");
            mount_config.max_listeners = mount_node["max_listeners"].as<int>(100);
            mount_config.public_listing = mount_node["public"].as<bool>(true);
            mount_config.allow_recording = mount_node["allow_recording"].as<bool>(false);
            mount_config.require_auth = mount_node["require_auth"].as<bool>(false);
            mount_config.min_bitrate = mount_node["min_bitrate"].as<int>(32);
            mount_config.max_bitrate = mount_node["max_bitrate"].as<int>(320);
            mount_config.metadata_enabled = true;
            mount_config.metadata_interval = 8192;
            mount_config.connection_timeout = 60;
            mount_config.ssl_required = false;
            mount_config.password = mount_node["password"].as<std::string>("");
            mount_config.admin_password = mount_node["admin_password"].as<std::string>("");
            
            // I parse content types if present
            if (mount_node["content_types"] && mount_node["content_types"].IsSequence()) {
                for (const auto& content_type : mount_node["content_types"]) {
                    mount_config.content_types.push_back(content_type.as<std::string>());
                }
            }
            
            // I parse metadata configuration if present
            if (mount_node["metadata"]) {
                const auto& metadata_node = mount_node["metadata"];
                mount_config.metadata_enabled = metadata_node["enabled"].as<bool>(true);
                mount_config.metadata_interval = metadata_node["interval"].as<int>(8192);
            }
            
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
 * This parses ICY protocol specific settings
 */
bool ConfigParser::parse_icy_protocol_config(const YAML::Node& node, ICYProtocolConfig& config) {
    try {
        config.legacy_support = node["legacy_support"].as<bool>(true);
        config.icy2_support = node["icy2_support"].as<bool>(true);
        config.default_metaint = node["default_metaint"].as<int>(8192);
        config.server_name = node["server_name"].as<std::string>("DNAS/1.0");
        config.hashtag_arrays = true;
        config.emoji_support = true;
        config.social_integration = true;
        config.json_metadata = true;
        config.video_metadata = true;
        config.podcast_metadata = true;
        config.certificate_verification = true;
        config.max_metadata_size = 4096;
        config.metadata_caching = true;
        config.metadata_cache_ttl = 300;
        
        // I parse ICY2 features if present
        if (node["icy2_features"]) {
            const auto& features = node["icy2_features"];
            config.hashtag_arrays = features["hashtag_arrays"].as<bool>(true);
            config.emoji_support = features["emoji_support"].as<bool>(true);
            config.social_integration = features["social_integration"].as<bool>(true);
            config.json_metadata = features["json_metadata"].as<bool>(true);
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing ICY protocol configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the logging configuration parsing method
 * This parses logging and monitoring settings
 */
bool ConfigParser::parse_logging_config(const YAML::Node& node, LoggingConfig& config) {
    try {
        config.level = node["level"].as<std::string>("INFO");
        config.file_logging_enabled = true;
        config.log_directory = expand_environment_variables("logs");
        config.error_log_file = expand_environment_variables("logs/error.log");
        config.access_log_file = expand_environment_variables("logs/access.log");
        config.security_log_file = expand_environment_variables("logs/security.log");
        config.max_file_size_mb = 100;
        config.max_log_files = 10;
        config.timestamps_enabled = true;
        config.log_format = "json";
        config.syslog_enabled = false;
        config.centralized_logging_enabled = false;
        config.gelf_enabled = false;
        
        // I parse file logging configuration if present
        if (node["file_logging"]) {
            const auto& file_logging = node["file_logging"];
            config.file_logging_enabled = file_logging["enabled"].as<bool>(true);
            config.log_directory = expand_environment_variables(file_logging["log_dir"].as<std::string>("logs"));
            config.error_log_file = expand_environment_variables(file_logging["error_file"].as<std::string>("logs/error.log"));
            config.access_log_file = expand_environment_variables(file_logging["access_log"].as<std::string>("logs/access.log"));
            config.security_log_file = expand_environment_variables(file_logging["security_log"].as<std::string>("logs/security.log"));
            config.max_file_size_mb = file_logging["max_size_mb"].as<int>(100);
            config.max_log_files = file_logging["max_files"].as<int>(10);
            config.timestamps_enabled = file_logging["timestamps"].as<bool>(true);
            config.log_format = file_logging["format"].as<std::string>("json");
        }
        
        // I parse syslog configuration if present
        if (node["syslog"]) {
            const auto& syslog = node["syslog"];
            config.syslog_enabled = syslog["enabled"].as<bool>(false);
            config.syslog_protocol = syslog["protocol"].as<std::string>("udp");
            config.syslog_host = syslog["host"].as<std::string>("127.0.0.1");
            config.syslog_port = syslog["port"].as<int>(514);
            config.syslog_facility = syslog["facility"].as<std::string>("local0");
            config.syslog_tag = syslog["tag"].as<std::string>("icy2-server");
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing logging configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the YP directories configuration parsing method
 * This parses Yellow Pages directory settings
 */
bool ConfigParser::parse_yp_directories_config(const YAML::Node& node, YPDirectoryConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(false);
        config.update_interval_seconds = 300;
        config.auto_register = false;
        config.ssl_verification = true;
        config.timeout_seconds = 30;
        config.retry_attempts = 3;
        
        // I parse default info if present
        if (node["default_info"]) {
            const auto& default_info = node["default_info"];
            for (const auto& pair : default_info) {
                config.default_info[pair.first.as<std::string>()] = pair.second.as<std::string>();
            }
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing YP directories configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the PHP configuration parsing method
 * This parses PHP-FPM integration settings
 */
bool ConfigParser::parse_php_config(const YAML::Node& node, PHPConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(false);
        config.socket_path = expand_environment_variables(node["socket_path"].as<std::string>("/run/php/php8.2-fpm.sock"));
        config.document_root = expand_environment_variables(node["document_root"].as<std::string>("www"));
        config.timeout_seconds = node["timeout"].as<int>(90);
        config.buffer_size = node["buffer_size"].as<std::string>("64k");
        config.error_reporting = node["error_reporting"].as<bool>(false);
        config.error_log_path = expand_environment_variables(node["error_log_path"].as<std::string>("logs/php_errors.log"));
        config.max_execution_time = node["max_execution_time"].as<int>(300);
        config.memory_limit = node["memory_limit"].as<std::string>("256M");
        
        // I parse index files if present
        if (node["index_files"] && node["index_files"].IsSequence()) {
            for (const auto& index_file : node["index_files"]) {
                config.index_files.push_back(index_file.as<std::string>());
            }
        } else {
            config.index_files = {"index.php", "index.html"};
        }
        
        // I parse environment variables if present
        if (node["environment_vars"]) {
            for (const auto& pair : node["environment_vars"]) {
                config.environment_vars[pair.first.as<std::string>()] = pair.second.as<std::string>();
            }
        }
        
        // I parse PHP settings if present
        if (node["php_settings"]) {
            for (const auto& pair : node["php_settings"]) {
                config.php_settings[pair.first.as<std::string>()] = pair.second.as<std::string>();
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
 * This parses REST API settings
 */
bool ConfigParser::parse_api_config(const YAML::Node& node, APIConfig& config) {
    try {
        config.enabled = node["enabled"].as<bool>(true);
        config.base_url = node["base_url"].as<std::string>("/api/v1");
        config.auth_token_required = node["auth_token_required"].as<bool>(false);
        config.rate_limit_per_minute = node["rate_limit_per_minute"].as<int>(120);
        config.output_format = node["output_format"].as<std::string>("json");
        config.cors_enabled = node["cors_enabled"].as<bool>(true);
        config.swagger_enabled = node["swagger_enabled"].as<bool>(false);
        config.max_request_size = node["max_request_size"].as<int>(1048576);
        config.request_logging = node["request_logging"].as<bool>(true);
        config.api_key_header = node["api_key_header"].as<std::string>("X-API-Key");
        
        // I parse allowed origins if present
        if (node["allowed_origins"] && node["allowed_origins"].IsSequence()) {
            for (const auto& origin : node["allowed_origins"]) {
                config.allowed_origins.push_back(origin.as<std::string>());
            }
        }
        
        // I parse public endpoints if present
        if (node["public_endpoints"] && node["public_endpoints"].IsSequence()) {
            for (const auto& endpoint : node["public_endpoints"]) {
                config.public_endpoints.push_back(endpoint.as<std::string>());
            }
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing API configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the performance configuration parsing method
 * This parses performance tuning settings
 */
bool ConfigParser::parse_performance_config(const YAML::Node& node, PerformanceConfig& config) {
    try {
        config.worker_threads = node["worker_threads"].as<int>(4);
        config.buffer_size = node["buffer_size"].as<int>(65536);
        config.max_memory_per_connection = node["max_memory_per_connection"].as<int>(1024);
        config.connection_pooling = node["connection_pooling"].as<bool>(true);
        config.thread_pool_size = node["thread_pool_size"].as<int>(8);
        config.enable_compression = node["enable_compression"].as<bool>(true);
        config.compression_algorithm = node["compression_algorithm"].as<std::string>("gzip");
        config.compression_level = node["compression_level"].as<int>(6);
        config.caching_enabled = node["caching_enabled"].as<bool>(true);
        config.cache_ttl_seconds = node["cache_ttl_seconds"].as<int>(300);
        config.max_cache_size_mb = node["max_cache_size_mb"].as<int>(128);
        config.prefork_enabled = node["prefork_enabled"].as<bool>(false);
        config.max_prefork_processes = node["max_prefork_processes"].as<int>(8);
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing performance configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing the development configuration parsing method
 * This parses development and debugging settings
 */
bool ConfigParser::parse_development_config(const YAML::Node& node, DevelopmentConfig& config) {
    try {
        config.debug_mode = node["debug_mode"].as<bool>(false);
        config.enable_cors = node["enable_cors"].as<bool>(true);
        config.log_requests = node["log_requests"].as<bool>(false);
        config.mock_mode = node["mock_mode"].as<bool>(false);
        config.hot_reload = node["hot_reload"].as<bool>(true);
        config.profiling_enabled = node["profiling_enabled"].as<bool>(false);
        config.profiling_output = node["profiling_output"].as<std::string>("profiling/");
        config.memory_debugging = node["memory_debugging"].as<bool>(false);
        config.sql_debugging = node["sql_debugging"].as<bool>(false);
        config.test_data_path = node["test_data_path"].as<std::string>("test_data/");
        
        // I parse CORS origins if present
        if (node["cors_origins"] && node["cors_origins"].IsSequence()) {
            for (const auto& origin : node["cors_origins"]) {
                config.cors_origins.push_back(origin.as<std::string>());
            }
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        add_validation_error("Error parsing development configuration: " + std::string(e.what()));
        return false;
    }
}

/**
 * I'm implementing environment variable expansion
 * This replaces ${VAR} with environment variable values
 */
std::string ConfigParser::expand_environment_variables(const std::string& value) {
    std::string result = value;
    std::regex env_regex(R"(\$\{([^}]+)\})");
    std::smatch match;
    
    while (std::regex_search(result, match, env_regex)) {
        std::string var_name = match[1].str();
        const char* env_value = std::getenv(var_name.c_str());
        std::string replacement = env_value ? env_value : "";
        
        result.replace(match.position(), match.length(), replacement);
    }
    
    return result;
}

/**
 * I'm implementing configuration validation
 * This validates all configuration settings
 */
bool ConfigParser::validate_config() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (!config_) {
        add_validation_error("No configuration loaded");
        return false;
    }
    
    clear_validation_errors();
    
    bool valid = true;
    
    // I validate network configuration
    valid &= validate_network_config(config_->network);
    
    // I validate SSL configuration
    if (config_->ssl.enabled) {
        valid &= validate_ssl_config(config_->ssl);
    }
    
    // I validate authentication configuration
    valid &= validate_authentication_config(config_->authentication);
    
    // I validate mount points
    for (const auto& mount_pair : config_->mount_points) {
        valid &= validate_mount_point_config(mount_pair.second);
    }
    
    // I validate file paths
    valid &= validate_file_paths();
    
    // I validate port ranges
    valid &= validate_port_ranges();
    
    config_->validation_passed = valid;
    
    return valid;
}

/**
 * I'm implementing network configuration validation
 * This validates network-related settings
 */
bool ConfigParser::validate_network_config(const NetworkConfig& config) {
    bool valid = true;
    
    if (config.http_port < 1 || config.http_port > 65535) {
        add_validation_error("Invalid HTTP port: " + std::to_string(config.http_port));
        valid = false;
    }
    
    if (config.https_port < 1 || config.https_port > 65535) {
        add_validation_error("Invalid HTTPS port: " + std::to_string(config.https_port));
        valid = false;
    }
    
    if (config.admin_port < 1 || config.admin_port > 65535) {
        add_validation_error("Invalid admin port: " + std::to_string(config.admin_port));
        valid = false;
    }
    
    if (config.max_connections < 1 || config.max_connections > 100000) {
        add_validation_error("Invalid max_connections: " + std::to_string(config.max_connections));
        valid = false;
    }
    
    return valid;
}

/**
 * I'm implementing SSL configuration validation
 * This validates SSL certificate and configuration
 */
bool ConfigParser::validate_ssl_config(const SSLConfig& config) {
    bool valid = true;
    
    if (config.cert_file.empty()) {
        add_validation_error("SSL certificate file path is required when SSL is enabled");
        valid = false;
    }
    
    if (config.key_file.empty()) {
        add_validation_error("SSL private key file path is required when SSL is enabled");
        valid = false;
    }
    
    return valid;
}

/**
 * I'm implementing authentication configuration validation
 * This validates authentication settings
 */
bool ConfigParser::validate_authentication_config(const AuthenticationConfig& config) {
    bool valid = true;
    
    if (config.token_secret.length() < 32) {
        add_validation_error("Token secret should be at least 32 characters long");
        valid = false;
    }
    
    if (config.token_expiration_hours < 1 || config.token_expiration_hours > 8760) {
        add_validation_error("Invalid token expiration hours: " + std::to_string(config.token_expiration_hours));
        valid = false;
    }
    
    return valid;
}

/**
 * I'm implementing mount point configuration validation
 * This validates individual mount point settings
 */
bool ConfigParser::validate_mount_point_config(const MountPointConfig& config) {
    bool valid = true;
    
    if (config.max_listeners < 1 || config.max_listeners > 10000) {
        add_validation_error("Invalid max_listeners for mount point: " + std::to_string(config.max_listeners));
        valid = false;
    }
    
    if (config.min_bitrate < 8 || config.min_bitrate > 2000) {
        add_validation_error("Invalid min_bitrate for mount point: " + std::to_string(config.min_bitrate));
        valid = false;
    }
    
    if (config.max_bitrate < config.min_bitrate || config.max_bitrate > 2000) {
        add_validation_error("Invalid max_bitrate for mount point: " + std::to_string(config.max_bitrate));
        valid = false;
    }
    
    return valid;
}

/**
 * I'm implementing file path validation
 * This validates that required files exist and are accessible
 */
bool ConfigParser::validate_file_paths() {
    bool valid = true;
    
    // I validate SSL certificate files if SSL is enabled
    if (config_->ssl.enabled) {
        if (!config_->ssl.cert_file.empty()) {
            std::ifstream cert_file(config_->ssl.cert_file);
            if (!cert_file.is_open()) {
                add_validation_error("Cannot access SSL certificate file: " + config_->ssl.cert_file);
                valid = false;
            }
        }
        
        if (!config_->ssl.key_file.empty()) {
            std::ifstream key_file(config_->ssl.key_file);
            if (!key_file.is_open()) {
                add_validation_error("Cannot access SSL private key file: " + config_->ssl.key_file);
                valid = false;
            }
        }
    }
    
    return valid;
}

/**
 * I'm implementing port range validation
 * This validates that ports don't conflict
 */
bool ConfigParser::validate_port_ranges() {
    bool valid = true;
    
    if (config_->network.http_port == config_->network.https_port) {
        add_validation_error("HTTP and HTTPS ports cannot be the same");
        valid = false;
    }
    
    if (config_->network.http_port == config_->network.admin_port) {
        add_validation_error("HTTP and admin ports cannot be the same");
        valid = false;
    }
    
    if (config_->network.https_port == config_->network.admin_port) {
        add_validation_error("HTTPS and admin ports cannot be the same");
        valid = false;
    }
    
    return valid;
}

/**
 * I'm implementing helper methods for validation
 */
void ConfigParser::add_validation_error(const std::string& error) {
    validation_errors_.push_back(error);
}

void ConfigParser::clear_validation_errors() {
    validation_errors_.clear();
}

std::string ConfigParser::calculate_config_hash() {
    // I create a simple hash of the configuration
    std::ostringstream config_stream;
    config_stream << config_file_path_ << "|";
    config_stream << config_->network.http_port << "|";
    config_stream << config_->network.https_port << "|";
    config_stream << config_->ssl.enabled << "|";
    config_stream << config_->authentication.enabled;
    
    return std::to_string(std::hash<std::string>{}(config_stream.str()));
}

/**
 * I'm implementing public interface methods
 */
bool ConfigParser::reload_config() {
    return load_config(config_file_path_);
}

const ServerConfig* ConfigParser::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_.get();
}

bool ConfigParser::is_config_modified() const {
    struct stat file_stat;
    if (stat(config_file_path_.c_str(), &file_stat) != 0) {
        return false; // I can't check, assume not modified
    }
    
    auto file_time = std::chrono::file_time_type::clock::from_time_t(file_stat.st_mtime);
    return file_time > last_file_time_;
}

std::vector<std::string> ConfigParser::get_validation_errors() const {
    return validation_errors_;
}

} // namespace icy2
