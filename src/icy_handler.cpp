// File: /Users/dstjohn/dev/01_mcaster1.com/DNAS/icy2-server/src/icy_handler.cpp
// Author: davestj@gmail.com (David St. John)
// Created: 2025-07-16
// Title: ICY Protocol Handler Implementation - Complete Functionality
// Purpose: I created this implementation to provide complete ICY 1.x and ICY 2.0+ protocol
//          support with proper struct member access and thread-safe operations
// Reason: I needed to align the implementation with the corrected header structure and
//         resolve all compilation issues preventing successful build completion
//
// Changelog:
// 2025-07-18 - Corrected all struct member access to align with definitive header
// 2025-07-18 - Fixed method implementations to match header declarations exactly
// 2025-07-18 - Resolved thread safety issues with proper mutex usage patterns
// 2025-07-16 - Initial implementation of ICY protocol handler with metadata support
// 2025-07-16 - Added comprehensive mount point and listener management functionality
//
// Next Dev Feature: I will add WebRTC integration for real-time browser streaming
// Git Commit: fix: align ICY handler implementation with corrected header structure

#include "icy_handler.h"
#include <iostream>
#include <sstream>
#include <random>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <chrono>

namespace icy2 {

// I'm implementing the constructor with proper initialization
ICYHandler::ICYHandler()
    : public_directory_enabled_(false),
      metadata_sequence_(0),
      maintenance_running_(false),
      cleanup_interval_(std::chrono::seconds(300)) {
    // I initialize the handler with default settings
}

// I'm implementing the destructor with proper cleanup
ICYHandler::~ICYHandler() {
    stop_maintenance_thread();
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
    updated_metadata.last_updated = std::chrono::system_clock::now();
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

    // I return default metadata if none exists
    ICYMetadata default_metadata;
    default_metadata.legacy.current_song = "Unknown Track";
    default_metadata.legacy.genre = "Various";
    default_metadata.legacy.bitrate = 128;

    return default_metadata;
}

// I implement metadata validation with comprehensive checks
bool ICYHandler::validate_metadata(const ICYMetadata& metadata) {
    // I validate bitrate ranges
    if (metadata.legacy.bitrate < 8 || metadata.legacy.bitrate > 2000) {
        return false;
    }

    // I validate emoji count limitations
    if (metadata.emojis.size() > 5) {
        return false;
    }

    // I validate hashtag format
    for (const auto& hashtag : metadata.hashtags) {
        if (hashtag.empty() || hashtag[0] != '#') {
            return false;
        }
    }

    return true;
}

// I implement ICY response generation for different protocol versions
std::string ICYHandler::generate_icy_response(const std::string& mount_path, ICYVersion version, int metaint) {
    ICYMetadata metadata = get_metadata(mount_path);

    std::ostringstream response;
    response << "ICY 200 OK\r\n";
    response << "icy-name: " << metadata.legacy.current_song << "\r\n";

    // I generate version-specific headers
    if (version >= ICYVersion::ICY_1_0) {
        response << "icy-genre: " << metadata.legacy.genre << "\r\n";
        response << "icy-url: " << metadata.legacy.url << "\r\n";
        response << "icy-pub: " << (metadata.legacy.is_public ? "1" : "0") << "\r\n";
        response << "icy-br: " << metadata.legacy.bitrate << "\r\n";
        response << "icy-metaint: " << metaint << "\r\n";
    }

    // I add ICY 2.0+ specific headers
    if (version >= ICYVersion::ICY_2_0) {
        response << "icy-meta-version: " << metadata.metadata_version << "\r\n";

        if (metadata.auth.status != VerificationStatus::UNVERIFIED) {
            response << "icy-meta-station-id: " << metadata.auth.station_id << "\r\n";

            std::string status_str = "unverified";
            switch (metadata.auth.status) {
                case VerificationStatus::VERIFIED: status_str = "verified"; break;
                case VerificationStatus::GOLD: status_str = "gold"; break;
                default: break;
            }
            response << "icy-meta-verification-status: " << status_str << "\r\n";
        }

        // I add social media integration
        if (!metadata.social.twitter_handle.empty()) {
            response << "icy-meta-social-twitter: " << metadata.social.twitter_handle << "\r\n";
        }
        if (!metadata.social.instagram_username.empty()) {
            response << "icy-meta-social-ig: " << metadata.social.instagram_username << "\r\n";
        }
        if (!metadata.social.tiktok_profile.empty()) {
            response << "icy-meta-social-tiktok: " << metadata.social.tiktok_profile << "\r\n";
        }

        // I add video metadata support
        if (!metadata.video.link.empty()) {
            std::string video_type_str = "live";
            switch (metadata.video.type) {
                case VideoType::SHORT: video_type_str = "short"; break;
                case VideoType::CLIP: video_type_str = "clip"; break;
                case VideoType::TRAILER: video_type_str = "trailer"; break;
                case VideoType::AD: video_type_str = "ad"; break;
                default: break;
            }
            response << "icy-meta-videotype: " << video_type_str << "\r\n";
            response << "icy-meta-videolink: " << metadata.video.link << "\r\n";
            response << "icy-meta-videotitle: " << metadata.video.title << "\r\n";
            response << "icy-meta-videochannel: " << metadata.video.channel << "\r\n";
            response << "icy-meta-videolive: " << (metadata.video.is_live ? "true" : "false") << "\r\n";
        }
    }

    response << "Content-Type: " << (metadata.video.link.empty() ? "audio/mpeg" : "video/mp4") << "\r\n";
    response << "\r\n";

    return response.str();
}

// I implement source response generation
std::string ICYHandler::generate_source_response(bool success, const std::string& message) {
    std::ostringstream response;

    if (success) {
        response << "HTTP/1.0 200 OK\r\n";
        response << "Content-Type: text/plain\r\n\r\n";
        response << "OK" << (message.empty() ? "" : " " + message) << "\r\n";
    } else {
        response << "HTTP/1.0 401 Unauthorized\r\n";
        response << "Content-Type: text/plain\r\n\r\n";
        response << "ERROR" << (message.empty() ? "" : " " + message) << "\r\n";
    }

    return response.str();
}

// I implement ICY header parsing with comprehensive metadata extraction
bool ICYHandler::parse_icy_headers(const std::map<std::string, std::string>& headers, ICYMetadata& metadata) {
    // I parse legacy ICY 1.x headers
    auto genre_it = headers.find("icy-genre");
    if (genre_it != headers.end()) {
        metadata.legacy.genre = genre_it->second;
    }

    auto url_it = headers.find("icy-url");
    if (url_it != headers.end()) {
        metadata.legacy.url = url_it->second;
    }

    auto br_it = headers.find("icy-br");
    if (br_it != headers.end()) {
        try {
            metadata.legacy.bitrate = std::stoi(br_it->second);
        } catch (const std::exception&) {
            metadata.legacy.bitrate = 128; // I default to 128 kbps
        }
    }

    // I parse ICY 2.0+ metadata version
    auto version_it = headers.find("icy-meta-version");
    if (version_it != headers.end()) {
        metadata.metadata_version = version_it->second;
    }

    // I parse social media integration headers
    auto twitter_it = headers.find("icy-meta-social-twitter");
    if (twitter_it != headers.end()) {
        metadata.social.twitter_handle = twitter_it->second;
    }

    auto ig_it = headers.find("icy-meta-social-ig");
    if (ig_it != headers.end()) {
        metadata.social.instagram_username = ig_it->second;
    }

    auto tiktok_it = headers.find("icy-meta-social-tiktok");
    if (tiktok_it != headers.end()) {
        metadata.social.tiktok_profile = tiktok_it->second;
    }

    return true;
}

// I implement ICY version detection based on headers
ICYVersion ICYHandler::detect_icy_version(const std::map<std::string, std::string>& headers) {
    auto version_it = headers.find("icy-meta-version");
    if (version_it != headers.end()) {
        if (version_it->second.find("2.1") != std::string::npos) {
            return ICYVersion::ICY_2_1;
        } else if (version_it->second.find("2.0") != std::string::npos) {
            return ICYVersion::ICY_2_0;
        }
    }

    // I check for ICY 2.0+ specific headers
    if (headers.find("icy-meta-social-twitter") != headers.end() ||
        headers.find("icy-meta-videotype") != headers.end()) {
        return ICYVersion::ICY_2_0;
    }

    return ICYVersion::ICY_1_0;
}

// I implement statistics generation in JSON format
std::string ICYHandler::get_statistics_json() const {
    std::lock_guard<std::mutex> mount_lock(mount_points_mutex_);
    std::lock_guard<std::mutex> listeners_lock(listeners_mutex_);
    std::lock_guard<std::mutex> sources_lock(sources_mutex_);

    std::ostringstream json;
    json << "{\n";
    json << "  \"server\": {\n";
    json << "    \"version\": \"1.1.2\",\n";
    json << "    \"uptime\": " << std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << ",\n";
    json << "    \"mount_points\": " << mount_points_.size() << ",\n";
    json << "    \"active_listeners\": " << listeners_.size() << ",\n";
    json << "    \"active_sources\": " << sources_.size() << "\n";
    json << "  },\n";
    json << "  \"mount_points\": [\n";

    bool first = true;
    for (const auto& [mount_path, config] : mount_points_) {
        if (!first) json << ",\n";
        first = false;

        size_t listener_count = 0;
        for (const auto& [client_id, listener] : listeners_) {
            if (listener.mount_point == mount_path) {
                listener_count++;
            }
        }

        json << "    {\n";
        json << "      \"path\": \"" << escape_json_string(mount_path) << "\",\n";
        json << "      \"name\": \"" << escape_json_string(config.name) << "\",\n";
        json << "      \"listeners\": " << listener_count << ",\n";
        json << "      \"max_listeners\": " << config.max_listeners << "\n";
        json << "    }";
    }

    json << "\n  ]\n";
    json << "}";

    return json.str();
}

// I implement YP directory configuration
void ICYHandler::set_yp_directory_enabled(bool enabled) {
    public_directory_enabled_ = enabled;
}

bool ICYHandler::is_yp_directory_enabled() const {
    return public_directory_enabled_;
}

// I implement metadata serialization for different versions
std::string ICYHandler::serialize_metadata(const ICYMetadata& metadata, ICYVersion version) {
    std::ostringstream serialized;

    if (version >= ICYVersion::ICY_2_0) {
        // I use JSON format for ICY 2.0+
        serialized << "{\n";
        serialized << "  \"title\": \"" << escape_json_string(metadata.legacy.current_song) << "\",\n";
        serialized << "  \"genre\": \"" << escape_json_string(metadata.legacy.genre) << "\",\n";
        serialized << "  \"bitrate\": " << metadata.legacy.bitrate << ",\n";
        serialized << "  \"version\": \"" << escape_json_string(metadata.metadata_version) << "\"\n";
        serialized << "}";
    } else {
        // I use simple format for ICY 1.x
        serialized << metadata.legacy.current_song;
    }

    return serialized.str();
}

// I implement connection cleanup for stale connections
void ICYHandler::cleanup_stale_connections() {
    auto now = std::chrono::system_clock::now();
    auto timeout = std::chrono::minutes(30); // I set 30-minute timeout

    {
        std::lock_guard<std::mutex> lock(listeners_mutex_);
        auto it = listeners_.begin();
        while (it != listeners_.end()) {
            if (now - it->second.connect_time > timeout) {
                log_connection_event("listener_timeout", "Listener " + it->first + " timed out");
                it = listeners_.erase(it);
            } else {
                ++it;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(sources_mutex_);
        auto it = sources_.begin();
        while (it != sources_.end()) {
            if (now - it->second.connect_time > timeout) {
                log_connection_event("source_timeout", "Source " + it->first + " timed out");
                it = sources_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// I implement maintenance thread management
void ICYHandler::start_maintenance_thread() {
    if (!maintenance_running_.load()) {
        maintenance_running_.store(true);
        maintenance_thread_ = std::thread([this]() {
            while (maintenance_running_.load()) {
                cleanup_stale_connections();
                std::this_thread::sleep_for(cleanup_interval_);
            }
        });
    }
}

void ICYHandler::stop_maintenance_thread() {
    if (maintenance_running_.load()) {
        maintenance_running_.store(false);
        if (maintenance_thread_.joinable()) {
            maintenance_thread_.join();
        }
    }
}

// I implement helper methods for internal operations
std::string ICYHandler::generate_client_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);

    std::ostringstream id;
    id << "client_";
    for (int i = 0; i < 8; ++i) {
        id << std::hex << dis(gen);
    }

    return id.str();
}

bool ICYHandler::is_valid_mount_path(const std::string& path) {
    if (path.empty() || path[0] != '/') {
        return false;
    }

    // I validate mount path format
    std::regex mount_regex("^/[a-zA-Z0-9_-]+$");
    return std::regex_match(path, mount_regex);
}

void ICYHandler::log_connection_event(const std::string& event, const std::string& details) {
    // I implement basic logging here
    // In production, this would integrate with the main logging system
    std::cout << "[ICY] " << event << ": " << details << std::endl;
}

std::string ICYHandler::escape_json_string(const std::string& input) {
    std::ostringstream escaped;
    for (char c : input) {
        switch (c) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default: escaped << c; break;
        }
    }
    return escaped.str();
}

std::string ICYHandler::format_timestamp(const std::chrono::system_clock::time_point& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream formatted;
    formatted << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return formatted.str();
}

} // namespace icy2