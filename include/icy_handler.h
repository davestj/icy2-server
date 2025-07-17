/**
 * File: include/icy_handler.h
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/icy_handler.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file to define the ICY protocol handler that implements
 *          both legacy ICY 1.x compatibility and the new ICY 2.0+ metadata specification.
 *          This handles all streaming metadata, source connections, and listener management.
 * 
 * Reason: I need a comprehensive ICY protocol implementation that bridges the gap between
 *         legacy SHOUTcast/Icecast compatibility and modern streaming requirements with
 *         social media integration, video metadata, and advanced authentication.
 *
 * Changelog:
 * 2025-07-16 - Initial ICY handler with legacy and v2.0+ protocol support
 * 2025-07-16 - Added comprehensive metadata structures and validation
 * 2025-07-16 - Implemented mount point management and listener tracking
 * 2025-07-16 - Added social media integration and video streaming metadata
 * 2025-07-16 - Integrated certificate verification and token authentication
 *
 * Next Dev Feature: I plan to add YP directory integration, load balancing, and WebRTC
 * Git Commit: feat: implement comprehensive ICY protocol handler with v2.0+ support
 *
 * TODO: Add YP directory updates, advanced load balancing, stream relay functionality
 */

#ifndef ICY_HANDLER_H
#define ICY_HANDLER_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <regex>
#include <functional>

namespace icy2 {

/**
 * I'm defining the ICY protocol version enumeration
 * This helps me handle different protocol versions appropriately
 */
enum class ICYVersion {
    ICY_1_0,        // I support legacy SHOUTcast v1 protocol
    ICY_1_1,        // I support SHOUTcast v2 protocol  
    ICY_2_0,        // I support ICY-META v2.0 protocol
    ICY_2_1,        // I support ICY-META v2.1+ full specification
    ICECAST2        // I support Icecast2 mount point protocol
};

/**
 * I'm defining verification status levels for the ICY 2.0+ certificate system
 * This implements trust levels for content creators and broadcasters
 */
enum class VerificationStatus {
    UNVERIFIED,     // I haven't verified this source yet
    PENDING,        // I'm in the process of verifying this source
    VERIFIED,       // I've confirmed this is a legitimate source
    GOLD,           // I've verified this as a premium/trusted source
    SUSPENDED       // I've temporarily suspended this source
};

/**
 * I'm defining video content types for ICY 2.0+ video streaming metadata
 * This helps me categorize and process different video content appropriately
 */
enum class VideoType {
    LIVE,           // I'm handling live video streaming
    SHORT,          // I'm processing short-form video content
    CLIP,           // I'm handling video clips or highlights
    TRAILER,        // I'm processing movie/show trailers
    AD,             // I'm handling advertisement content
    PODCAST_VIDEO   // I'm processing video podcast content
};

/**
 * I'm defining content platforms for social media integration
 * This allows me to track and integrate with various social platforms
 */
enum class ContentPlatform {
    YOUTUBE,        // I integrate with YouTube content
    TIKTOK,         // I handle TikTok integration
    TWITCH,         // I support Twitch streaming
    INSTAGRAM,      // I integrate with Instagram content
    TWITTER,        // I support Twitter/X integration
    FACEBOOK,       // I handle Facebook content
    LINKEDIN,       // I support LinkedIn integration
    CUSTOM          // I allow custom platform definitions
};

/**
 * I'm creating a structure for legacy ICY 1.x metadata
 * This maintains backwards compatibility with existing encoders
 */
struct LegacyICYMetadata {
    std::string name;           // I store the station name (icy-name)
    std::string genre;          // I track the content genre (icy-genre)
    std::string url;            // I keep the station URL (icy-url)
    std::string description;    // I store the description
    int bitrate;               // I track the stream bitrate (icy-br)
    bool public_listing;       // I flag public directory listing (icy-pub)
    int metadata_interval;     // I set metadata injection interval (icy-metaint)
    std::string current_song;  // I store the current song/title
    std::string server_name;   // I identify the server software
};

/**
 * I'm creating a structure for video streaming metadata (ICY 2.0+)
 * This supports modern video content integration and metadata
 */
struct VideoMetadata {
    VideoType type;                         // I categorize the video content type
    std::string link;                       // I store the video URL (icy-meta-videolink)
    std::string title;                      // I keep the video title (icy-meta-videotitle)
    std::string poster_url;                 // I store thumbnail URL (icy-meta-videoposter)
    std::string channel;                    // I track the creator channel (icy-meta-videochannel)
    ContentPlatform platform;               // I identify the source platform (icy-meta-videoplatform)
    int duration_seconds;                   // I store video length (icy-meta-videoduration)
    std::chrono::system_clock::time_point start_time; // I track scheduled start (icy-meta-videostart)
    bool is_live;                          // I flag live content (icy-meta-videolive)
    std::string codec;                     // I store video codec (icy-meta-videocodec)
    int fps;                               // I track frames per second (icy-meta-videofps)
    std::string resolution;                // I store resolution (icy-meta-videoresolution)
    bool nsfw;                             // I flag adult content (icy-meta-videonsfw)
};

/**
 * I'm creating a structure for social media integration (ICY 2.0+)
 * This enables cross-platform promotion and social presence
 */
struct SocialMediaInfo {
    std::string twitter_handle;            // I store Twitter/X handle (icy-meta-social-twitter)
    std::string instagram_username;        // I keep Instagram username (icy-meta-social-ig)
    std::string tiktok_profile;           // I track TikTok profile (icy-meta-social-tiktok)
    std::string linktree_url;             // I store unified profile URL (icy-meta-social-linktree)
    std::string facebook_page;            // I keep Facebook page info
    std::string youtube_channel;          // I store YouTube channel
    std::string discord_server;           // I track Discord community
    std::string website_url;              // I keep the main website URL
};

/**
 * I'm creating a structure for podcast-specific metadata (ICY 2.0+)
 * This supports modern podcast streaming and episode management
 */
struct PodcastMetadata {
    std::string host_name;                 // I store the podcast host (icy-meta-podcast-host)
    std::string episode_title;             // I keep episode title (icy-meta-podcast-episode)
    std::string rss_feed_url;             // I store RSS feed URL (icy-meta-podcast-rss)
    std::string episode_id;               // I track unique episode identifier
    std::string season;                   // I store season information
    std::string episode_number;           // I keep episode number
    std::chrono::system_clock::time_point publish_date; // I track publish date
    std::string description;              // I store episode description
    std::vector<std::string> categories;  // I track podcast categories
    std::string artwork_url;              // I store episode artwork
    int duration_seconds;                 // I track episode duration
    std::string transcript_url;           // I store transcript URL if available
};

/**
 * I'm creating a structure for authentication and verification (ICY 2.0+)
 * This implements the trust and verification system
 */
struct AuthenticationInfo {
    std::string station_id;               // I store unique station ID (icy-meta-station-id)
    std::string cert_issuer_id;          // I track certificate authority (icy-meta-certissuer-id)
    std::string root_ca_hash;            // I store root CA fingerprint (icy-meta-cert-rootca)
    std::string certificate_pem;         // I keep PEM certificate (icy-meta-certificate)
    VerificationStatus status;           // I track verification status (icy-meta-verification-status)
    std::string auth_token;              // I store JWT token (icy-auth-token-key)
    std::chrono::system_clock::time_point token_expiry; // I track token expiration
    std::vector<std::string> permissions; // I define allowed operations
    std::string issuer;                  // I track who issued the token
    bool certificate_valid;              // I flag certificate validity
};

/**
 * I'm creating the comprehensive ICY 2.0+ metadata structure
 * This combines all metadata types into a unified system
 */
struct ICYMetadata {
    // I'm including legacy compatibility fields
    LegacyICYMetadata legacy;

    // I'm adding ICY 2.0+ specific fields
    std::string metadata_version;         // I store protocol version (icy-metadata-version)
    std::string dj_handle;               // I track current DJ (icy-meta-dj-handle)
    std::string language;                // I store content language (icy-meta-language)
    int duration_seconds;                // I track content duration (icy-meta-duration)
    
    // I'm including emoji and hashtag support
    std::vector<std::string> emojis;     // I store mood emojis (icy-meta-emoji)
    std::vector<std::string> hashtags;   // I track searchable tags (icy-meta-hashtag-array)
    
    // I'm adding content classification
    bool nsfw_content;                   // I flag adult content (icy-meta-nsfw)
    bool ai_generated;                   // I flag AI content (icy-meta-ai-generator)
    std::string geo_region;              // I store geographic region (icy-meta-geo-region)
    
    // I'm including specialized metadata structures
    VideoMetadata video;                 // I embed video metadata
    SocialMediaInfo social;              // I embed social media info
    PodcastMetadata podcast;             // I embed podcast metadata
    AuthenticationInfo auth;             // I embed authentication info
    
    // I'm adding timestamps and tracking
    std::chrono::system_clock::time_point created_at;  // I track when metadata was created
    std::chrono::system_clock::time_point updated_at;  // I track last update time
    std::string source_ip;               // I store the source IP address
    uint64_t sequence_number;            // I track metadata sequence
};

/**
 * I'm creating a structure for mount point configuration
 * This defines how each stream endpoint behaves
 */
struct MountPointConfig {
    std::string name;                     // I store the display name
    std::string description;              // I keep the description
    int max_listeners;                    // I limit concurrent listeners
    bool public_listing;                  // I flag directory visibility
    bool allow_recording;                 // I control recording permissions
    bool require_auth;                    // I enforce authentication
    std::vector<std::string> content_types; // I define allowed content types
    int min_bitrate;                      // I set minimum bitrate
    int max_bitrate;                      // I set maximum bitrate
    bool metadata_enabled;                // I control metadata injection
    int metadata_interval;                // I set metadata frequency
    std::string fallback_mount;           // I define fallback stream
    int connection_timeout;               // I set connection timeout
    bool ssl_required;                    // I enforce SSL connections
    std::vector<std::string> allowed_ips; // I restrict source IPs
    std::string password;                 // I store source password
    std::string admin_password;           // I store admin password
};

/**
 * I'm creating a structure to track active listeners
 * This helps me manage connections and statistics
 */
struct ListenerInfo {
    std::string client_id;                // I assign unique client identifier
    std::string ip_address;               // I track client IP
    uint16_t port;                        // I store client port
    std::chrono::system_clock::time_point connected_at; // I record connection time
    std::chrono::system_clock::time_point last_activity; // I track activity
    std::string user_agent;               // I store client software info
    uint64_t bytes_sent;                  // I count bytes sent to client
    std::string referer;                  // I track how they found the stream
    std::string mount_point;              // I identify which stream they're on
    ICYVersion protocol_version;          // I track ICY protocol version
    bool metadata_enabled;                // I flag metadata support
    int metadata_interval;                // I store their metadata interval
};

/**
 * I'm creating a structure for source connections
 * This manages encoders and content sources
 */
struct SourceInfo {
    std::string source_id;                // I assign unique source identifier
    std::string ip_address;               // I track source IP
    uint16_t port;                        // I store source port
    std::chrono::system_clock::time_point connected_at; // I record connection time
    std::string user_agent;               // I store encoder software info
    std::string mount_point;              // I identify target mount point
    ICYVersion protocol_version;          // I track protocol version
    bool authenticated;                   // I flag authentication status
    std::string username;                 // I store authentication username
    uint64_t bytes_received;              // I count bytes received from source
    std::string content_type;             // I track stream content type
    int bitrate;                          // I monitor stream bitrate
    int sample_rate;                      // I track audio sample rate
    int channels;                         // I count audio channels
    ICYMetadata current_metadata;         // I store current stream metadata
    bool is_recording;                    // I flag if recording is active
};

/**
 * I'm defining the main ICY handler class
 * This orchestrates all ICY protocol operations
 */
class ICYHandler {
private:
    // I'm defining mount point management
    std::unordered_map<std::string, MountPointConfig> mount_points_; // I store mount configurations
    std::unordered_map<std::string, std::vector<ListenerInfo>> listeners_; // I track listeners per mount
    std::unordered_map<std::string, SourceInfo> sources_;           // I track active sources
    std::mutex mount_points_mutex_;                                 // I protect mount point data
    std::mutex listeners_mutex_;                                    // I protect listener data
    std::mutex sources_mutex_;                                      // I protect source data

    // I'm defining metadata management
    std::unordered_map<std::string, ICYMetadata> metadata_cache_;   // I cache metadata per mount
    std::mutex metadata_mutex_;                                     // I protect metadata cache
    std::atomic<uint64_t> metadata_sequence_;                       // I track metadata updates

    // I'm defining configuration and state
    bool legacy_support_enabled_;                                   // I flag legacy ICY support
    bool icy2_support_enabled_;                                     // I flag ICY 2.0+ support
    std::string server_name_;                                       // I store server identification
    int default_metadata_interval_;                                 // I set default interval
    int max_listeners_global_;                                      // I limit global listeners
    bool public_directory_enabled_;                                 // I control YP directory

    // I'm defining helper methods
    bool parse_icy_headers(const std::map<std::string, std::string>& headers, 
                          ICYMetadata& metadata);                  // I parse ICY protocol headers
    bool validate_metadata(const ICYMetadata& metadata);          // I validate metadata completeness
    std::string serialize_metadata(const ICYMetadata& metadata, 
                                 ICYVersion version);             // I serialize metadata for transmission
    bool authenticate_source(const std::string& mount_point, 
                           const std::string& username, 
                           const std::string& password);         // I authenticate source connections
    void broadcast_metadata_to_listeners(const std::string& mount_point, 
                                        const ICYMetadata& metadata); // I send metadata to all listeners
    void cleanup_disconnected_listeners();                       // I remove stale listener connections
    void update_listener_statistics();                           // I update listener metrics
    bool rate_limit_source(const std::string& ip);              // I implement source rate limiting
    void log_icy_event(const std::string& event, 
                      const std::string& details);              // I log ICY protocol events

public:
    /**
     * I'm creating the constructor to initialize the ICY handler
     */
    ICYHandler();

    /**
     * I'm creating the destructor to clean up resources
     */
    virtual ~ICYHandler();

    /**
     * I'm creating the method to configure the ICY handler
     * @param legacy_support Enable ICY 1.x compatibility
     * @param icy2_support Enable ICY 2.0+ features
     * @param server_name Server identification string
     * @param default_interval Default metadata interval
     * @return true if configuration succeeded
     */
    bool configure(bool legacy_support, bool icy2_support, 
                  const std::string& server_name, int default_interval);

    /**
     * I'm creating the method to add a mount point
     * @param mount_path Mount point path (e.g., "/stream")
     * @param config Mount point configuration
     * @return true if mount point was added successfully
     */
    bool add_mount_point(const std::string& mount_path, const MountPointConfig& config);

    /**
     * I'm creating the method to remove a mount point
     * @param mount_path Mount point path to remove
     * @return true if mount point was removed successfully
     */
    bool remove_mount_point(const std::string& mount_path);

    /**
     * I'm creating the method to handle source connections
     * @param mount_path Target mount point
     * @param headers ICY protocol headers
     * @param source_ip Source IP address
     * @param source_port Source port number
     * @return true if source connection was accepted
     */
    bool handle_source_connection(const std::string& mount_path,
                                 const std::map<std::string, std::string>& headers,
                                 const std::string& source_ip, uint16_t source_port);

    /**
     * I'm creating the method to handle listener connections
     * @param mount_path Requested mount point
     * @param headers HTTP/ICY headers
     * @param client_ip Client IP address
     * @param client_port Client port number
     * @return true if listener connection was accepted
     */
    bool handle_listener_connection(const std::string& mount_path,
                                   const std::map<std::string, std::string>& headers,
                                   const std::string& client_ip, uint16_t client_port);

    /**
     * I'm creating the method to update metadata for a mount point
     * @param mount_path Mount point to update
     * @param metadata New metadata to broadcast
     * @return true if metadata was updated successfully
     */
    bool update_metadata(const std::string& mount_path, const ICYMetadata& metadata);

    /**
     * I'm creating the method to get current metadata
     * @param mount_path Mount point to query
     * @return Current metadata for the mount point
     */
    ICYMetadata get_metadata(const std::string& mount_path) const;

    /**
     * I'm creating the method to get listener count
     * @param mount_path Mount point to query
     * @return Number of active listeners
     */
    size_t get_listener_count(const std::string& mount_path) const;

    /**
     * I'm creating the method to get all mount points
     * @return Map of mount points and their configurations
     */
    std::unordered_map<std::string, MountPointConfig> get_mount_points() const;

    /**
     * I'm creating the method to disconnect a listener
     * @param mount_path Mount point
     * @param client_id Client identifier
     * @return true if listener was disconnected
     */
    bool disconnect_listener(const std::string& mount_path, const std::string& client_id);

    /**
     * I'm creating the method to disconnect a source
     * @param mount_path Mount point
     * @return true if source was disconnected
     */
    bool disconnect_source(const std::string& mount_path);

    /**
     * I'm creating the method to generate ICY response headers
     * @param mount_path Mount point
     * @param version ICY protocol version
     * @param metadata_interval Metadata interval for client
     * @return ICY response header string
     */
    std::string generate_icy_response(const std::string& mount_path, 
                                     ICYVersion version, int metadata_interval);

    /**
     * I'm creating the method to validate a mount point exists
     * @param mount_path Mount point to check
     * @return true if mount point exists and is active
     */
    bool mount_point_exists(const std::string& mount_path) const;

    /**
     * I'm creating the method to get server statistics
     * @return JSON string with ICY handler statistics
     */
    std::string get_statistics_json() const;
};

} // namespace icy2

#endif // ICY_HANDLER_H
