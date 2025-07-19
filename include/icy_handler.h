// File: /Users/dstjohn/dev/01_mcaster1.com/DNAS/icy2-server/include/icy_handler.h
// Author: davestj@gmail.com (David St. John)
// Created: 2025-07-16
// Title: ICY Protocol Handler - Complete Metadata Structure
// Purpose: I created this header to handle both ICY 1.x legacy protocols and ICY 2.0+ 
//          advanced features with complete metadata structure definitions
// Reason: I needed a unified handler that supports SHOUTcast v1/v2, Icecast2, and modern
//         ICY 2.0+ protocol with social media integration, video metadata, and authentication
//
// Changelog:
// 2025-07-18 - Fixed ICYMetadata struct completeness and mutex const-correctness issues
// 2025-07-16 - Complete ICY protocol implementation with authentication and social features
// 2025-07-16 - Added mount point management and listener tracking
// 2025-07-16 - Implemented metadata serialization and validation systems
// 2025-07-16 - Initial header creation with ICY 1.x and 2.0+ protocol support
//
// Next Dev Feature: I will add WebRTC integration for real-time browser streaming
// Git Commit: fix: resolve ICYMetadata struct definition and mutex const-correctness issues

#ifndef ICY2_ICY_HANDLER_H
#define ICY2_ICY_HANDLER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <regex>

namespace icy2 {

// I'm defining the ICY protocol version enumeration
enum class ICYVersion {
    ICY_1_0,        // I support original SHOUTcast protocol
    ICY_1_1,        // I support enhanced SHOUTcast v1 features
    ICY_2_0,        // I support modern ICY 2.0+ with social integration
    ICY_2_1         // I support latest ICY 2.1+ with video metadata
};

// I'm defining verification status for authenticated streams
enum class VerificationStatus {
    UNVERIFIED,     // I handle unverified streams
    PENDING,        // I manage streams under review
    VERIFIED,       // I process verified authentic streams
    GOLD            // I support premium verified content
};

// I'm defining video content types for ICY 2.0+ streams
enum class VideoType {
    LIVE,           // I handle live video streams
    SHORT,          // I process short-form video content
    CLIP,           // I manage video clips
    TRAILER,        // I handle promotional trailers
    AD              // I process advertisement content
};

// I'm defining the complete ICY metadata structure with all required fields
struct ICYMetadata {
    // I handle legacy ICY 1.x metadata for backward compatibility
    struct {
        std::string current_song;       // I store the current playing song/title
        std::string genre;              // I maintain the stream genre
        std::string url;                // I store the station URL
        int bitrate = 128;              // I track the stream bitrate
        bool is_public = true;          // I control public directory listing
    } legacy;

    // I manage ICY 2.0+ metadata version tracking
    std::string metadata_version = "2.1";  // I track the metadata specification version

    // I handle authentication and verification for trusted streams
    struct {
        std::string station_id;         // I store unique global station identifier
        std::string cert_issuer_id;     // I maintain certificate authority ID
        std::string root_ca;            // I store root CA hash or fingerprint
        std::string certificate;        // I handle Base64 PEM certificate
        VerificationStatus status = VerificationStatus::UNVERIFIED; // I track verification status
    } auth;

    // I manage social media integration for modern streams
    struct {
        std::string twitter_handle;     // I store Twitter/X handle
        std::string instagram_username; // I maintain Instagram username
        std::string tiktok_profile;     // I handle TikTok profile name
        std::string linktree_url;       // I store unified profile links
    } social;

    // I handle video streaming metadata for ICY 2.0+ content
    struct {
        VideoType type = VideoType::LIVE;   // I define the video content type
        std::string link;               // I store video content URL
        std::string title;              // I maintain video title
        std::string poster_url;         // I store thumbnail/preview image
        std::string channel;            // I track creator/uploader handle
        std::string platform;           // I identify hosting platform
        int duration_seconds = 0;       // I store video length
        std::string start_time;         // I maintain scheduled start time
        bool is_live = false;           // I track live streaming status
        std::string codec;              // I store video codec information
        int fps = 30;                   // I maintain frames per second
        std::string resolution;         // I store video resolution
        bool is_nsfw = false;           // I handle NSFW content flagging
    } video;

    // I manage podcast-specific metadata
    struct {
        std::string host_name;          // I store podcast host name
        std::string rss_feed;           // I maintain RSS feed URL
        std::string episode_title;      // I track episode information
        std::string language = "en";    // I store content language
        int duration_seconds = 0;       // I maintain episode duration
    } podcast;

    // I handle discovery and branding metadata
    std::vector<std::string> hashtags;  // I store searchable tags
    std::vector<std::string> emojis;    // I maintain mood indicators (max 5)
    std::string geo_region;             // I store location information
    bool ai_generated = false;          // I flag AI-generated content
    bool nsfw_content = false;          // I handle NSFW content marking

    // I track metadata timing and updates
    std::chrono::system_clock::time_point last_updated;
    uint64_t sequence_number = 0;       // I maintain update sequence tracking
};

// I'm defining mount point configuration structure
struct MountPointConfig {
    std::string name;                   // I store mount point display name
    std::string description;            // I maintain mount description
    int max_listeners = 100;            // I control listener limits
    bool is_public = true;              // I manage public visibility
    bool allow_recording = false;       // I control recording permissions
    bool require_auth = true;           // I enforce authentication requirements
    std::vector<std::string> content_types; // I define allowed content types
    int min_bitrate = 32;               // I set minimum bitrate limits
    int max_bitrate = 320;              // I set maximum bitrate limits
    bool metadata_enabled = true;       // I control metadata broadcasting
    int metadata_interval = 8192;       // I set metadata injection interval
};

// I'm defining listener connection information
struct ListenerInfo {
    std::string client_id;              // I track unique client identifier
    std::string ip_address;             // I store client IP address
    std::string user_agent;             // I maintain client software info
    std::chrono::system_clock::time_point connect_time; // I track connection start
    uint64_t bytes_sent = 0;            // I monitor data transfer
    std::string mount_point;            // I track accessed mount point
    bool metadata_enabled = false;      // I track metadata preference
};

// I'm defining source connection information
struct SourceInfo {
    std::string source_id;              // I store unique source identifier
    std::string ip_address;             // I track source IP address
    std::string user_agent;             // I maintain source software info
    std::chrono::system_clock::time_point connect_time; // I track connection start
    uint64_t bytes_received = 0;        // I monitor incoming data
    std::string mount_point;            // I track streaming mount point
    ICYMetadata current_metadata;       // I store current stream metadata
};

// I'm defining the main ICY protocol handler class
class ICYHandler {
public:
    // I provide constructor and destructor for proper resource management
    ICYHandler();
    ~ICYHandler();

    // I implement non-copyable and non-movable semantics for thread safety
    ICYHandler(const ICYHandler&) = delete;
    ICYHandler& operator=(const ICYHandler&) = delete;
    ICYHandler(ICYHandler&&) = delete;
    ICYHandler& operator=(ICYHandler&&) = delete;

    // I provide mount point management functionality
    bool create_mount_point(const std::string& mount_path, const MountPointConfig& config);
    bool remove_mount_point(const std::string& mount_path);
    bool mount_point_exists(const std::string& mount_path) const;
    std::unordered_map<std::string, MountPointConfig> get_mount_points() const;

    // I handle source connection management
    bool authenticate_source(const std::string& mount_path, const std::string& username, 
                           const std::string& password);
    bool register_source(const std::string& source_id, const std::string& mount_path,
                        const std::string& ip_address, const std::string& user_agent);
    void unregister_source(const std::string& source_id);
    bool source_exists(const std::string& source_id) const;

    // I provide listener connection management
    std::string register_listener(const std::string& mount_path, const std::string& ip_address,
                                 const std::string& user_agent, bool metadata_enabled);
    void unregister_listener(const std::string& client_id);
    size_t get_listener_count(const std::string& mount_path) const;

    // I handle metadata management and broadcasting
    bool update_metadata(const std::string& mount_path, const ICYMetadata& metadata);
    ICYMetadata get_metadata(const std::string& mount_path) const;
    std::string serialize_metadata(const ICYMetadata& metadata, ICYVersion version);
    bool validate_metadata(const ICYMetadata& metadata);

    // I provide ICY protocol response generation
    std::string generate_icy_response(const std::string& mount_path, ICYVersion version, 
                                    int metaint = 8192);
    std::string generate_source_response(bool success, const std::string& message = "");

    // I handle ICY header parsing and processing
    bool parse_icy_headers(const std::map<std::string, std::string>& headers, 
                          ICYMetadata& metadata);
    ICYVersion detect_icy_version(const std::map<std::string, std::string>& headers);

    // I provide statistics and monitoring functionality
    std::string get_statistics_json() const;
    void set_yp_directory_enabled(bool enabled);
    bool is_yp_directory_enabled() const;

    // I handle cleanup and maintenance operations
    void cleanup_stale_connections();
    void start_maintenance_thread();
    void stop_maintenance_thread();

private:
    // I maintain mount point management with thread safety
    std::unordered_map<std::string, MountPointConfig> mount_points_;
    mutable std::mutex mount_points_mutex_;             // I use mutable for const methods

    // I track active connections and sources
    std::unordered_map<std::string, ListenerInfo> listeners_;
    std::unordered_map<std::string, SourceInfo> sources_;
    mutable std::mutex listeners_mutex_;                // I use mutable for const methods
    mutable std::mutex sources_mutex_;                  // I use mutable for const methods

    // I manage metadata storage and updates
    std::unordered_map<std::string, ICYMetadata> metadata_cache_;
    mutable std::mutex metadata_mutex_;                 // I use mutable for const methods

    // I maintain configuration and state
    bool public_directory_enabled_;                     // I control YP directory listing
    std::atomic<uint64_t> metadata_sequence_;           // I track metadata updates
    std::atomic<bool> maintenance_running_;             // I control maintenance thread

    // I provide maintenance and cleanup functionality
    std::thread maintenance_thread_;                    // I handle background maintenance
    std::chrono::seconds cleanup_interval_;             // I set cleanup timing

    // I implement helper methods for internal operations
    std::string generate_client_id();                   // I create unique client IDs
    bool is_valid_mount_path(const std::string& path);  // I validate mount point paths
    void log_connection_event(const std::string& event, const std::string& details);
    std::string escape_json_string(const std::string& input);
    std::string format_timestamp(const std::chrono::system_clock::time_point& time);
};

} // namespace icy2

#endif // ICY2_ICY_HANDLER_H
