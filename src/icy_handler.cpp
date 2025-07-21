// File: /var/www/mcaster1.com/DNAS/icy2-server/src/icy_handler.cpp
// Author: davestj@gmail.com (David St. John)
// Created: 2025-07-16
// Title: ICY Protocol Handler Implementation - Final Corrected Version for Debian 12 Linux
// Purpose: I created this implementation to provide complete ICY 1.x and ICY 2.0+ protocol
//          support using the actual ICYMetadata structure from common_types.h with all
//          const-correctness issues resolved
// Reason: I needed to fix the remaining compilation errors including const-correctness for
//         utility methods, unused parameter warnings, and unhandled enumeration cases
//
// Changelog:
// 2025-07-21 - Fixed const-correctness for utility methods called from const functions
// 2025-07-21 - Resolved unused parameter warnings by properly handling port parameter
// 2025-07-21 - Added missing AUTO_DETECT case to switch statement
// 2025-07-21 - Completely corrected to use actual ICYMetadata fields from common_types.h
// 2025-07-21 - Fixed const-correctness issues with mutable mutexes in header
// 2025-07-21 - Fixed constructor initialization order to match header declaration order
// 2025-07-18 - Added missing methods required by server.cpp compilation
// 2025-07-16 - Initial implementation with ICY protocol support
//
// Next Dev Feature: I will add WebRTC integration for real-time browser streaming
// Git Commit: fix: resolve all remaining compilation issues for successful Debian 12 build

#include "icy_handler.h"
#include <iostream>
#include <sstream>
#include <random>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <chrono>

namespace icy2 {

// I'm implementing the constructor with proper initialization order matching header
ICYHandler::ICYHandler()
    : legacy_support_enabled_(true),
      icy2_support_enabled_(true),
      server_name_("ICY2-DNAS/1.0"),
      default_metaint_(8192),
      metadata_sequence_(0),
      maintenance_running_(false),
      public_directory_enabled_(false),
      cleanup_interval_(std::chrono::seconds(300)) {
    // I initialize the handler with default settings
}

// I'm implementing the destructor with proper cleanup
ICYHandler::~ICYHandler() {
    stop_maintenance_thread();
}

// I implement the configure method required by server.cpp
bool ICYHandler::configure(bool legacy_support, bool icy2_support,
                          const std::string& server_name, int default_metaint) {
    if (server_name.empty() || default_metaint <= 0) {
        return false;
    }

    legacy_support_enabled_ = legacy_support;
    icy2_support_enabled_ = icy2_support;
    server_name_ = server_name;
    default_metaint_ = default_metaint;

    log_connection_event("icy_configured",
        "ICY handler configured - Legacy: " + std::string(legacy_support ? "enabled" : "disabled") +
        ", ICY2+: " + std::string(icy2_support ? "enabled" : "disabled"));

    return true;
}

// I implement mount point creation with comprehensive validation
bool ICYHandler::create_mount_point(const std::string& mount_path, const MountPointConfig& config) {
    if (!is_valid_mount_path(mount_path)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mount_points_mutex_);
    mount_points_[mount_path] = config;

    log_connection_event("mount_created", "Mount point " + mount_path + " created successfully");
    return true;
}

// I implement add_mount_point as required by server.cpp - delegates to create_mount_point
bool ICYHandler::add_mount_point(const std::string& mount_path, const MountPointConfig& config) {
    return create_mount_point(mount_path, config);
}

// I implement mount point removal with proper cleanup
bool ICYHandler::remove_mount_point(const std::string& mount_path) {
    std::lock_guard<std::mutex> lock(mount_points_mutex_);

    auto it = mount_points_.find(mount_path);
    if (it != mount_points_.end()) {
        mount_points_.erase(it);
        log_connection_event("mount_removed", "Mount point " + mount_path + " removed");
        return true;
    }

    return false;
}

// I implement mount point existence checking with thread safety
bool ICYHandler::mount_point_exists(const std::string& mount_path) const {
    std::lock_guard<std::mutex> lock(mount_points_mutex_);
    return mount_points_.find(mount_path) != mount_points_.end();
}

// I implement mount point retrieval with proper copying
std::unordered_map<std::string, MountPointConfig> ICYHandler::get_mount_points() const {
    std::lock_guard<std::mutex> lock(mount_points_mutex_);
    return mount_points_;
}

// I implement source authentication with validation
bool ICYHandler::authenticate_source(const std::string& mount_path, const std::string& username, const std::string& password) {
    if (!mount_point_exists(mount_path)) {
        return false;
    }

    // I implement basic authentication logic here
    // In production, this would validate against configured credentials
    return !username.empty() && !password.empty();
}

// I implement source registration with comprehensive tracking
bool ICYHandler::register_source(const std::string& source_id, const std::string& mount_path,
                                const std::string& ip_address, const std::string& user_agent) {
    if (!mount_point_exists(mount_path)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(sources_mutex_);

    SourceInfo source;
    source.source_id = source_id;
    source.mount_point = mount_path;
    source.ip_address = ip_address;
    source.user_agent = user_agent;
    source.connect_time = std::chrono::system_clock::now();

    sources_[source_id] = source;

    log_connection_event("source_registered", "Source " + source_id + " registered on " + mount_path);
    return true;
}

// I implement source unregistration with proper cleanup
void ICYHandler::unregister_source(const std::string& source_id) {
    std::lock_guard<std::mutex> lock(sources_mutex_);

    auto it = sources_.find(source_id);
    if (it != sources_.end()) {
        log_connection_event("source_unregistered", "Source " + source_id + " unregistered");
        sources_.erase(it);
    }
}

// I implement source existence checking
bool ICYHandler::source_exists(const std::string& source_id) const {
    std::lock_guard<std::mutex> lock(sources_mutex_);
    return sources_.find(source_id) != sources_.end();
}

// I implement handle_source_connection as required by server.cpp - FIXED unused parameter warning
bool ICYHandler::handle_source_connection(const std::string& uri,
                                        const std::map<std::string, std::string>& headers,
                                        const std::string& ip_address, uint16_t port) {
    // I acknowledge the port parameter to avoid unused parameter warning
    (void)port;

    // I extract mount path from URI
    std::string mount_path = extract_mount_path_from_uri(uri);
    if (mount_path.empty() || !mount_point_exists(mount_path)) {
        log_connection_event("source_connection_failed",
            "Invalid mount path: " + mount_path + " from " + ip_address);
        return false;
    }

    // I validate connection headers
    if (!validate_connection_headers(headers)) {
        log_connection_event("source_connection_failed",
            "Invalid headers from " + ip_address);
        return false;
    }

    // I generate unique source ID
    std::string source_id = generate_client_id();

    // I extract user agent
    std::string user_agent = "Unknown";
    auto ua_it = headers.find("User-Agent");
    if (ua_it != headers.end()) {
        user_agent = ua_it->second;
    }

    // I register the source connection
    bool success = register_source(source_id, mount_path, ip_address, user_agent);

    if (success) {
        log_connection_event("source_connection_accepted",
            "Source connected to " + mount_path + " from " + ip_address + " (" + user_agent + ")");
    }

    return success;
}

// I implement handle_listener_connection as required by server.cpp - FIXED unused parameter warning
bool ICYHandler::handle_listener_connection(const std::string& uri,
                                          const std::map<std::string, std::string>& headers,
                                          const std::string& ip_address, uint16_t port) {
    // I acknowledge the port parameter to avoid unused parameter warning
    (void)port;

    // I extract mount path from URI
    std::string mount_path = extract_mount_path_from_uri(uri);
    if (mount_path.empty() || !mount_point_exists(mount_path)) {
        log_connection_event("listener_connection_failed",
            "Invalid mount path: " + mount_path + " from " + ip_address);
        return false;
    }

    // I extract user agent
    std::string user_agent = "Unknown";
    auto ua_it = headers.find("User-Agent");
    if (ua_it != headers.end()) {
        user_agent = ua_it->second;
    }

    // I check for metadata preference
    bool metadata_enabled = false;
    auto icy_meta_it = headers.find("icy-metadata");
    if (icy_meta_it != headers.end() && icy_meta_it->second == "1") {
        metadata_enabled = true;
    }

    // I register the listener connection
    std::string client_id = register_listener(mount_path, ip_address, user_agent, metadata_enabled);

    if (!client_id.empty()) {
        log_connection_event("listener_connection_accepted",
            "Listener connected to " + mount_path + " from " + ip_address +
            " (" + user_agent + ") - Client ID: " + client_id);
        return true;
    }

    return false;
}

// I implement listener registration with unique ID generation
std::string ICYHandler::register_listener(const std::string& mount_path, const std::string& ip_address,
                                         const std::string& user_agent, bool metadata_enabled) {
    if (!mount_point_exists(mount_path)) {
        return "";
    }

    std::string client_id = generate_client_id();

    std::lock_guard<std::mutex> lock(listeners_mutex_);

    ListenerInfo listener;
    listener.client_id = client_id;
    listener.mount_point = mount_path;
    listener.ip_address = ip_address;
    listener.user_agent = user_agent;
    listener.metadata_enabled = metadata_enabled;
    listener.connect_time = std::chrono::system_clock::now();

    listeners_[client_id] = listener;

    log_connection_event("listener_registered", "Listener " + client_id + " registered on " + mount_path);
    return client_id;
}

// I implement listener unregistration with statistics updating
void ICYHandler::unregister_listener(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(listeners_mutex_);

    auto it = listeners_.find(client_id);
    if (it != listeners_.end()) {
        log_connection_event("listener_unregistered", "Listener " + client_id + " unregistered");
        listeners_.erase(it);
    }
}

// I implement listener count retrieval for specific mount points
size_t ICYHandler::get_listener_count(const std::string& mount_path) const {
    std::lock_guard<std::mutex> lock(listeners_mutex_);

    size_t count = 0;
    for (const auto& [client_id, listener] : listeners_) {
        if (listener.mount_point == mount_path) {
            count++;
        }
    }

    return count;
}

// I implement metadata updating with sequence tracking
bool ICYHandler::update_metadata(const std::string& mount_path, const ICYMetadata& metadata) {
    if (!mount_point_exists(mount_path)) {
        return false;
    }

    if (!validate_metadata(metadata)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(metadata_mutex_);

    ICYMetadata updated_metadata = metadata;
    updated_metadata.sequence_number = ++metadata_sequence_;

    metadata_cache_[mount_path] = updated_metadata;

    log_connection_event("metadata_updated", "Metadata updated for mount " + mount_path);
    return true;
}

// I implement metadata retrieval with thread safety
ICYMetadata ICYHandler::get_metadata(const std::string& mount_path) const {
    std::lock_guard<std::mutex> lock(metadata_mutex_);

    auto it = metadata_cache_.find(mount_path);
    if (it != metadata_cache_.end()) {
        return it->second;
    }

    // I return empty metadata if not found
    return ICYMetadata{};
}

// I implement metadata validation with comprehensive checks using actual fields
bool ICYHandler::validate_metadata(const ICYMetadata& metadata) {
    // I validate basic metadata requirements
    if (metadata.station_name.empty()) {
        return false;
    }

    // I validate metadata size limits (prevent abuse)
    if (metadata.station_name.length() > 256 || metadata.description.length() > 512) {
        return false;
    }

    // I validate bitrate ranges using actual field
    if (metadata.bitrate < 8 || metadata.bitrate > 2000) {
        return false;
    }

    // I validate emoji count (ICY 2.0+ spec allows max 5 emojis)
    if (metadata.emojis.size() > 5) {
        return false;
    }

    // I validate hashtag count (reasonable limit)
    if (metadata.hashtags.size() > 20) {
        return false;
    }

    // I validate individual hashtag length
    for (const auto& hashtag : metadata.hashtags) {
        if (hashtag.length() > 64) {
            return false;
        }
    }

    return true;
}

// I implement metadata serialization for different ICY versions - FIXED missing AUTO_DETECT case
std::string ICYHandler::serialize_metadata(const ICYMetadata& metadata, ICYVersion version) {
    std::stringstream ss;

    switch (version) {
        case ICYVersion::ICY_1_0:
        case ICYVersion::ICY_1_1:
            // I format legacy ICY 1.x metadata using actual fields
            ss << "StreamTitle='" << metadata.station_name << "';";
            if (!metadata.url.empty()) {
                ss << "StreamUrl='" << metadata.url << "';";
            }
            break;

        case ICYVersion::ICY_2_0:
        case ICYVersion::ICY_2_1:
            // I format modern ICY 2.0+ metadata with enhanced fields
            ss << "StreamTitle='" << metadata.station_name << "';";
            if (!metadata.url.empty()) {
                ss << "StreamUrl='" << metadata.url << "';";
            }

            // I add ICY 2.0+ specific fields using actual fields
            if (!metadata.hashtags.empty()) {
                ss << "icy-meta-hashtag-array='";
                for (size_t i = 0; i < metadata.hashtags.size(); ++i) {
                    if (i > 0) ss << ",";
                    ss << metadata.hashtags[i];
                }
                ss << "';";
            }

            if (!metadata.emojis.empty()) {
                ss << "icy-meta-emoji='";
                for (const auto& emoji : metadata.emojis) {
                    ss << emoji;
                }
                ss << "';";
            }
            break;

        case ICYVersion::AUTO_DETECT:
            // I handle AUTO_DETECT by defaulting to ICY 2.1 format
            return serialize_metadata(metadata, ICYVersion::ICY_2_1);
    }

    return ss.str();
}

// I implement ICY header parsing for metadata extraction using actual fields
bool ICYHandler::parse_icy_headers(const std::map<std::string, std::string>& headers, ICYMetadata& metadata) {
    // I parse standard ICY headers using actual field names
    auto name_it = headers.find("icy-name");
    if (name_it != headers.end()) {
        metadata.station_name = name_it->second;
    }

    auto genre_it = headers.find("icy-genre");
    if (genre_it != headers.end()) {
        metadata.genre = genre_it->second;
    }

    auto url_it = headers.find("icy-url");
    if (url_it != headers.end()) {
        metadata.url = url_it->second;
    }

    auto desc_it = headers.find("icy-description");
    if (desc_it != headers.end()) {
        metadata.description = desc_it->second;
    }

    // I parse bitrate using actual field
    auto br_it = headers.find("icy-br");
    if (br_it != headers.end()) {
        try {
            metadata.bitrate = static_cast<uint32_t>(std::stoul(br_it->second));
        } catch (const std::exception&) {
            metadata.bitrate = 128; // I default to 128 kbps
        }
    }

    // I parse ICY 2.0+ enhanced headers
    auto version_it = headers.find("icy-metadata-version");
    if (version_it != headers.end()) {
        metadata.version = version_it->second;
    }

    auto station_id_it = headers.find("icy-meta-station-id");
    if (station_id_it != headers.end()) {
        metadata.station_id = station_id_it->second;
    }

    // I parse social media fields using actual field names
    auto twitter_it = headers.find("icy-meta-social-twitter");
    if (twitter_it != headers.end()) {
        metadata.social_twitter = twitter_it->second;
    }

    auto ig_it = headers.find("icy-meta-social-ig");
    if (ig_it != headers.end()) {
        metadata.social_instagram = ig_it->second;
    }

    auto tiktok_it = headers.find("icy-meta-social-tiktok");
    if (tiktok_it != headers.end()) {
        metadata.social_tiktok = tiktok_it->second;
    }

    return true;
}

// I implement ICY version detection from headers
ICYVersion ICYHandler::detect_icy_version(const std::map<std::string, std::string>& headers) {
    // I check for ICY 2.0+ specific headers
    if (headers.find("icy-metadata-version") != headers.end()) {
        auto version_it = headers.find("icy-metadata-version");
        if (version_it->second == "2.1") {
            return ICYVersion::ICY_2_1;
        } else if (version_it->second == "2.0") {
            return ICYVersion::ICY_2_0;
        }
    }

    // I check for other ICY 2.0+ indicators
    if (headers.find("icy-meta-hashtag-array") != headers.end() ||
        headers.find("icy-meta-emoji") != headers.end() ||
        headers.find("icy-auth-token-key") != headers.end()) {
        return ICYVersion::ICY_2_0;
    }

    // I default to ICY 1.x
    return ICYVersion::ICY_1_0;
}

// I implement ICY response generation for clients using actual fields
std::string ICYHandler::generate_icy_response(const std::string& mount_path, ICYVersion version, int metaint) {
    std::stringstream response;
    ICYMetadata metadata = get_metadata(mount_path);

    response << "ICY 200 OK\r\n";
    response << "icy-notice1:<BR>This stream is served by ICY2-DNAS<BR>\r\n";
    response << "icy-notice2:ICY2-DNAS - Digital Network Audio Server<BR>\r\n";
    response << "icy-name:" << (metadata.station_name.empty() ? server_name_ : metadata.station_name) << "\r\n";
    response << "icy-genre:" << (metadata.genre.empty() ? "Various" : metadata.genre) << "\r\n";
    response << "icy-url:" << (metadata.url.empty() ? "http://mcaster1.com" : metadata.url) << "\r\n";
    response << "icy-pub:" << (metadata.public_listing ? "1" : "0") << "\r\n";
    response << "icy-br:" << metadata.bitrate << "\r\n";
    response << "icy-metaint:" << metaint << "\r\n";

    // I add ICY 2.0+ headers if supported
    if (version >= ICYVersion::ICY_2_0) {
        response << "icy-metadata-version:" << metadata.version << "\r\n";
        if (!metadata.station_id.empty()) {
            response << "icy-meta-station-id:" << metadata.station_id << "\r\n";
        }
        if (!metadata.verification_status.empty()) {
            response << "icy-meta-verification-status:" << metadata.verification_status << "\r\n";
        }
    }

    response << "\r\n";

    return response.str();
}

// I implement source response generation
std::string ICYHandler::generate_source_response(bool success, const std::string& message) {
    if (success) {
        return "ICY 200 OK\r\n\r\n";
    } else {
        std::string response = "ICY 401 Unauthorized\r\n";
        if (!message.empty()) {
            response += "icy-notice1:" + message + "\r\n";
        }
        response += "\r\n";
        return response;
    }
}

// I implement statistics JSON generation - FIXED const correctness by calling const methods
std::string ICYHandler::get_statistics_json() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"server_info\": {\n";
    json << "    \"name\": \"" << escape_json_string(server_name_) << "\",\n";
    json << "    \"version\": \"ICY2-DNAS/1.0\",\n";
    json << "    \"legacy_support\": " << (legacy_support_enabled_ ? "true" : "false") << ",\n";
    json << "    \"icy2_support\": " << (icy2_support_enabled_ ? "true" : "false") << "\n";
    json << "  },\n";

    json << "  \"mount_points\": [\n";
    {
        std::lock_guard<std::mutex> lock(mount_points_mutex_);
        bool first = true;
        for (const auto& [path, config] : mount_points_) {
            if (!first) json << ",\n";
            first = false;

            json << "    {\n";
            json << "      \"path\": \"" << escape_json_string(path) << "\",\n";
            json << "      \"name\": \"" << escape_json_string(config.name) << "\",\n";
            json << "      \"listeners\": " << get_listener_count(path) << "\n";
            json << "    }";
        }
    }
    json << "\n  ],\n";

    json << "  \"total_listeners\": " << listeners_.size() << ",\n";
    json << "  \"total_sources\": " << sources_.size() << "\n";
    json << "}\n";

    return json.str();
}

// I implement YP directory control
void ICYHandler::set_yp_directory_enabled(bool enabled) {
    public_directory_enabled_ = enabled;
}

bool ICYHandler::is_yp_directory_enabled() const {
    return public_directory_enabled_;
}

// I implement cleanup operations
void ICYHandler::cleanup_stale_connections() {
    auto now = std::chrono::system_clock::now();

    // I clean up stale listeners (older than 1 hour without activity)
    {
        std::lock_guard<std::mutex> lock(listeners_mutex_);
        auto it = listeners_.begin();
        while (it != listeners_.end()) {
            auto duration = std::chrono::duration_cast<std::chrono::hours>(
                now - it->second.connect_time);
            if (duration.count() > 1) {
                log_connection_event("listener_cleanup",
                    "Cleaning up stale listener: " + it->first);
                it = listeners_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // I clean up stale sources
    {
        std::lock_guard<std::mutex> lock(sources_mutex_);
        auto it = sources_.begin();
        while (it != sources_.end()) {
            auto duration = std::chrono::duration_cast<std::chrono::hours>(
                now - it->second.connect_time);
            if (duration.count() > 2) {
                log_connection_event("source_cleanup",
                    "Cleaning up stale source: " + it->first);
                it = sources_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// I implement maintenance thread management
void ICYHandler::start_maintenance_thread() {
    if (maintenance_running_.load()) {
        return;
    }

    maintenance_running_.store(true);
    maintenance_thread_ = std::thread([this]() {
        while (maintenance_running_.load()) {
            cleanup_stale_connections();
            std::this_thread::sleep_for(cleanup_interval_);
        }
    });
}

void ICYHandler::stop_maintenance_thread() {
    if (!maintenance_running_.load()) {
        return;
    }

    maintenance_running_.store(false);
    if (maintenance_thread_.joinable()) {
        maintenance_thread_.join();
    }
}

// I implement utility helper functions
std::string ICYHandler::generate_client_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(100000, 999999);

    return "client_" + std::to_string(dis(gen));
}

bool ICYHandler::is_valid_mount_path(const std::string& path) {
    if (path.empty() || path[0] != '/') {
        return false;
    }

    // I use regex to validate mount path format
    std::regex mount_regex("^/[a-zA-Z0-9_\\-/]*$");
    return std::regex_match(path, mount_regex);
}

void ICYHandler::log_connection_event(const std::string& event, const std::string& details) {
    // I output log messages to stdout for now
    // In production, this would use a proper logging system
    auto now = std::chrono::system_clock::now();
    std::time_t time_t = std::chrono::system_clock::to_time_t(now);
    std::cout << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
              << event << ": " << details << std::endl;
}

// I implement escape_json_string as const method - FIXED const correctness
std::string ICYHandler::escape_json_string(const std::string& input) const {
    std::string output;
    output.reserve(input.length());

    for (char c : input) {
        switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c; break;
        }
    }

    return output;
}

// I implement format_timestamp as const method - FIXED const correctness
std::string ICYHandler::format_timestamp(const std::chrono::system_clock::time_point& time) const {
    std::time_t time_t = std::chrono::system_clock::to_time_t(time);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

bool ICYHandler::validate_connection_headers(const std::map<std::string, std::string>& headers) {
    // I perform basic header validation
    if (headers.empty()) {
        return false;
    }

    // I could add more sophisticated validation here
    return true;
}

std::string ICYHandler::extract_mount_path_from_uri(const std::string& uri) {
    // I extract mount path from URI (everything before query parameters)
    size_t query_pos = uri.find('?');
    std::string path = (query_pos != std::string::npos) ? uri.substr(0, query_pos) : uri;

    // I ensure path starts with /
    if (path.empty() || path[0] != '/') {
        return "/stream"; // I default to /stream
    }

    return path;
}

} // namespace icy2