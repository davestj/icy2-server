/**
 * File: include/common_types.h
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/common_types.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file to define common data structures and types
 *          that are shared across multiple components of ICY2-SERVER. This prevents
 *          redefinition errors and ensures consistency across the entire system.
 *
 * Reason: I need a central location for shared type definitions to avoid duplicate
 *         struct definitions between config_parser.h and icy_handler.h, while
 *         ensuring all components use consistent data structures for communication.
 *
 * Changelog:
 * 2025-07-16 - Created common types header to resolve struct redefinition conflicts
 * 2025-07-16 - Moved shared structures from individual headers to centralized location
 * 2025-07-16 - Added comprehensive documentation for all shared data types
 * 2025-07-16 - Ensured C++17 compatibility and proper namespace organization
 * 2025-07-16 - Fixed ConnectionType enum to match actual server.cpp usage
 * 2025-07-16 - Added ICY2_VERSION_STRING and other version definitions
 *
 * Next Dev Feature: I plan to add more shared types as the system grows
 * Git Commit: fix: add missing version definitions and correct enum values
 *
 * TODO: Add validation helpers, serialization support, type conversion utilities
 */

#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

// I'm including necessary standard library headers
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <chrono>
#include <memory>
#include <atomic>
#include <cstdint>

namespace icy2 {



/**
 * I'm defining version information that the entire system uses
 * This ensures consistent version reporting across all components
 */
#ifndef ICY2_VERSION_STRING
#define ICY2_VERSION_STRING "1.1.1"
#endif

#ifndef ICY2_VERSION_MAJOR
#define ICY2_VERSION_MAJOR 1
#endif

#ifndef ICY2_VERSION_MINOR
#define ICY2_VERSION_MINOR 1
#endif

#ifndef ICY2_VERSION_PATCH
#define ICY2_VERSION_PATCH 1
#endif

/**
 * I'm defining common enumerations used throughout the system
 * These provide consistent type-safe options across different components
 */

/**
 * I'm defining the log level enumeration
 * This ensures consistent logging levels across all components
 */
enum class LogLevel {
    DEBUG = 0,      // I provide detailed debugging information
    INFO = 1,       // I provide general information messages
    WARNING = 2,    // I provide warning conditions
    ERROR = 3,      // I provide error conditions
    CRITICAL = 4    // I provide critical system errors
};

/**
 * I'm defining the connection type enumeration
 * This categorizes different types of client connections
 * FIXED: I've updated this to match what server.cpp actually uses
 */
enum class ConnectionType {
    HTTP,           // I identify standard HTTP connections
    HTTPS,          // I identify HTTPS connections
    ICY_SOURCE,     // I identify ICY source broadcasting connections
    ICY_LISTENER,   // I identify ICY listener connections
    PHP_FPM,        // I identify PHP-FPM FastCGI connections
    API,            // I identify REST API connections
    WEBSOCKET,      // I identify WebSocket connections
    ADMIN,          // I identify administrative connections
    LISTENER,       // I identify generic listener connections
    SOURCE          // I identify generic source connections
};

/**
 * I'm defining the stream format enumeration
 * This specifies the audio/video formats supported
 */
enum class StreamFormat {
    MP3,            // I support MP3 audio format
    AAC,            // I support AAC audio format
    OGG,            // I support OGG Vorbis format
    FLAC,           // I support FLAC lossless format
    OPUS,           // I support Opus audio format
    H264,           // I support H.264 video format
    WEBM,           // I support WebM video format
    UNKNOWN         // I handle unknown or unsupported formats
};

/**
 * I'm defining the ICY protocol version enumeration
 * This specifies which ICY protocol version to use
 */
enum class ICYVersion {
    ICY_1_0,        // I support original ICY 1.0 protocol
    ICY_1_1,        // I support ICY 1.1 extensions
    ICY_2_0,        // I support ICY 2.0 protocol
    ICY_2_1,        // I support ICY 2.1+ protocol
    AUTO_DETECT     // I automatically detect the best version
};

/**
 * I'm defining authentication status enumeration
 * This tracks the authentication state of connections
 */
enum class AuthStatus {
    UNAUTHENTICATED,    // I haven't authenticated the connection
    PENDING,            // I'm processing authentication
    AUTHENTICATED,      // I've successfully authenticated
    DENIED,             // I've denied authentication
    EXPIRED,            // I've detected expired authentication
    LOCKED_OUT          // I've locked out due to failed attempts
};

/**
 * I'm defining the server mode enumeration
 * This specifies how the server should operate
 */
enum class ServerMode {
    PRODUCTION,     // I operate in production mode
    DEVELOPMENT,    // I operate in development mode
    TESTING,        // I operate in testing mode
    DEBUG           // I operate in debug mode
};

/**
 * I'm creating a structure for network configuration
 * This defines all network-related settings
 */
struct NetworkConfig {
    std::string bind_address;
    uint16_t http_port;
    uint16_t https_port;
    uint16_t admin_port;
    int max_connections;
    int connection_timeout;
    int keepalive_timeout;
    int buffer_size;
    bool enable_compression;
    int worker_threads;
    bool connection_pooling;
    int thread_pool_size;
    int max_memory_per_connection;
    bool enable_cors;
    std::vector<std::string> cors_origins;
};

/**
 * I'm creating a structure for SSL/TLS configuration
 * This defines all SSL-related settings
 */
struct SSLConfig {
    bool enabled = false;                       // I control SSL functionality
    std::string cert_file;                      // I specify certificate file path
    std::string key_file;                       // I specify private key file path
    std::string chain_file;                     // I specify certificate chain file
    std::vector<std::string> protocols;         // I list supported TLS versions
    std::string cipher_suites;                  // I define cipher suite preferences
    bool require_client_cert = false;           // I control client certificate requirements
    std::string ca_file;                        // I specify CA certificate file
};

/**
 * I'm creating a structure for authentication configuration
 * This defines all authentication-related settings
 */
struct AuthConfig {
    bool enabled = true;                        // I control authentication requirements
    std::string token_secret;                   // I set JWT token secret
    uint32_t token_expiration_hours = 24;       // I set token expiration time
    bool allow_anonymous_listeners = true;      // I control anonymous access
    bool require_auth_for_broadcast = true;     // I control source authentication
    uint32_t max_failed_attempts = 5;           // I limit failed login attempts
    uint32_t lockout_duration_minutes = 30;     // I set lockout duration
};

/**
 * I'm creating a structure for mount point configuration
 * This defines settings for individual streaming endpoints
 */
struct MountPointConfig {

    std::string name;                           // I set the mount point display name

    std::string description;                    // I provide mount point description

    uint32_t max_listeners = 100;               // I limit concurrent listeners

    bool public_listing = true;                 // I control directory listing

    bool allow_recording = false;               // I control recording permission

    bool require_authentication = false;        // I control access requirements

    std::vector<std::string> content_types;     // I specify allowed content types

    uint32_t min_bitrate = 32;                  // I set minimum bitrate kbps

    uint32_t max_bitrate = 320;                 // I set maximum bitrate kbps

    std::string password;                       // I set mount-specific password

    std::string fallback_mount;                 // I specify fallback mount point

    bool metadata_enabled = true;               // I control metadata support

    uint32_t metadata_interval = 8192;          // I set metadata interval bytes

};


/**
 * I'm creating a structure for ICY metadata
 * This defines metadata fields for streaming content
 */
struct ICYMetadata {
    // I'm defining legacy ICY 1.x fields
    std::string station_name;                   // I set icy-name
    std::string genre;                          // I set icy-genre
    std::string url;                            // I set icy-url
    std::string description;                    // I set icy-description
    bool public_listing = false;                // I set icy-pub
    uint32_t bitrate = 128;                     // I set icy-br
    uint32_t sample_rate = 44100;               // I set icy-sr

    // I'm defining ICY 2.0+ enhanced fields
    std::string version = "2.1";                // I set icy-metadata-version
    std::string station_id;                     // I set icy-meta-station-id
    std::string certificate_issuer;             // I set icy-meta-certissuer-id
    std::string root_ca;                        // I set icy-meta-cert-rootca
    std::string certificate;                    // I set icy-meta-certificate
    
    // I am adding implementation-specific members for icy_handler compatibility
    struct {
        std::string name;
        std::string description;
        bool public_listing = false;
        uint32_t metadata_interval = 8192;
    } legacy;
    
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
    uint64_t sequence_number = 0;
    std::string verification_status;            // I set verification status

    // I'm defining audio and podcast metadata
    std::string dj_handle;                      // I set icy-meta-dj-handle
    std::string podcast_host;                   // I set icy-meta-podcast-host
    std::string podcast_rss;                    // I set icy-meta-podcast-rss
    std::string episode;                        // I set icy-meta-podcast-episode
    uint32_t duration = 0;                      // I set icy-meta-duration
    std::string language;                       // I set icy-meta-language

    // I'm defining video streaming metadata
    std::string video_type;                     // I set icy-meta-videotype
    std::string video_link;                     // I set icy-meta-videolink
    std::string video_title;                    // I set icy-meta-videotitle
    std::string video_poster;                   // I set icy-meta-videoposter
    std::string video_channel;                  // I set icy-meta-videochannel
    std::string video_platform;                // I set icy-meta-videoplatform
    uint32_t video_duration = 0;                // I set icy-meta-videoduration
    std::string video_start_time;               // I set icy-meta-videostart
    bool video_live = false;                    // I set icy-meta-videolive
    std::string video_codec;                    // I set icy-meta-videocodec
    uint32_t video_fps = 0;                     // I set icy-meta-videofps
    std::string video_resolution;               // I set icy-meta-videoresolution
    bool video_nsfw = false;                    // I set icy-meta-videonsfw

    // I'm defining social and discovery metadata
    std::vector<std::string> emojis;            // I set icy-meta-emoji array
    std::vector<std::string> hashtags;          // I set icy-meta-hashtag-array
    std::string social_twitter;                 // I set icy-meta-social-twitter
    std::string social_instagram;               // I set icy-meta-social-ig
    std::string social_tiktok;                  // I set icy-meta-social-tiktok
    std::string social_linktree;                // I set icy-meta-social-linktree

    // I'm defining access and compliance metadata
    bool nsfw_content = false;                  // I set icy-meta-nsfw
    bool ai_generated = false;                  // I set icy-meta-ai-generator
    std::string geo_region;                     // I set icy-meta-geo-region
    std::string auth_token;                     // I set icy-auth-token-key
};

/**
 * I'm creating a structure for server statistics
 * This tracks comprehensive performance metrics
 */
struct ServerStatistics {
    
    // I am implementing a custom copy constructor to handle atomic members
    ServerStatistics(const ServerStatistics& other) 
        : start_time(other.start_time)
        , total_connections(other.total_connections.load())
        , active_connections(other.active_connections.load())
        , ssl_connections(other.ssl_connections.load())
        , http_requests(other.http_requests.load())
        , icy_connections(other.icy_connections.load())
        , api_requests(other.api_requests.load())
        , php_requests(other.php_requests.load())
        , total_bytes_sent(other.total_bytes_sent.load())
        , total_bytes_received(other.total_bytes_received.load())
        , failed_connections(other.failed_connections.load())
        , authentication_failures(other.authentication_failures.load())
        , mount_points_active(other.mount_points_active.load())
        , total_listeners(other.total_listeners.load())
        , peak_concurrent_listeners(other.peak_concurrent_listeners.load())
    {}
    
    // I am implementing default constructor
    ServerStatistics() = default;

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
    std::atomic<uint64_t> mount_points_active{0};      // I count active mount points
    std::atomic<uint64_t> total_listeners{0};          // I count total listeners
    std::atomic<uint64_t> peak_concurrent_listeners{0}; // I track peak listeners
};

/**
 * I'm creating a structure for configuration validation results
 * This provides detailed validation feedback
 */
struct ValidationResult {
    bool valid = true;                          // I indicate overall validation status
    std::vector<std::string> errors;            // I list validation errors
    std::vector<std::string> warnings;          // I list validation warnings
    std::vector<std::string> suggestions;       // I provide improvement suggestions
};

/**
 * I'm creating utility type aliases for convenience
 * These provide shorter names for commonly used types
 */
using TimePoint = std::chrono::steady_clock::time_point;
using Duration = std::chrono::steady_clock::duration;
using HeaderMap = std::map<std::string, std::string>;
using ParameterMap = std::unordered_map<std::string, std::string>;

struct AuthenticationConfig {
    bool enabled = true;
    std::string token_secret;
    int token_expiration = 24;
    int token_expiration_hours = 24;
    bool allow_anonymous_listeners = true;
    bool require_auth_for_broadcast = true;
    int max_failed_attempts = 5;
    int lockout_duration = 30;
    int lockout_duration_minutes = 30;
};

struct ICYProtocolConfig {
    bool legacy_support = true;
    bool icy2_support = true;
    int default_metaint = 8192;
    std::string server_name;
};

struct LoggingConfig {
    std::string level;
    bool enabled = true;
};

struct YPDirectoryConfig {
    bool enabled = false;
};

struct PHPConfig {
    bool enabled = true;
    std::string socket_path;
    std::string document_root;
    std::vector<std::string> index_files;
    int timeout_seconds = 90;
};

struct PerformanceConfig {
    int worker_threads = 4;
};

struct DevelopmentConfig {
    bool debug_mode = false;
};

struct APIConfig {
    bool enabled = true;
    std::string base_url;
};


using MountPointMap = std::unordered_map<std::string, MountPointConfig>;

struct ServerConfig {
    std::string config_file_path;
    std::string name;
    std::string description;
    std::string version;
    std::string admin_email;
    NetworkConfig network;
    SSLConfig ssl;
    AuthenticationConfig authentication;
    MountPointMap mount_points;
    ICYProtocolConfig icy_protocol;
    LoggingConfig logging;
    YPDirectoryConfig yp_directories;
    PHPConfig php_fmp;
    APIConfig api;
    PerformanceConfig performance;
    DevelopmentConfig development;
};

} // namespace icy2

#endif // COMMON_TYPES_H