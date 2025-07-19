// File: /Users/dstjohn/dev/01_mcaster1.com/DNAS/icy2-server/include/icy_handler.h
// Author: davestj@gmail.com (David St. John)
// Created: 2025-07-16
// Title: ICY Protocol Handler - Corrected Header Organization
// Purpose: I created this header to handle both ICY 1.x legacy protocols and ICY 2.0+
//          advanced features while properly utilizing existing common type definitions
// Reason: I needed to resolve compilation conflicts by properly organizing type definitions
//         and ensuring compatibility with the established project architecture
//
// Changelog:
// 2025-07-18 - Fixed duplicate type definition conflicts with common_types.h
// 2025-07-18 - Reorganized header to use existing project type definitions
// 2025-07-18 - Maintained all ICY 2.0+ protocol functionality while resolving build issues
// 2025-07-16 - Initial implementation with complete ICY protocol support
// 2025-07-16 - Added mount point management and listener tracking capabilities
//
// Next Dev Feature: I will add WebRTC integration for real-time browser streaming
// Git Commit: fix: resolve duplicate type definition conflicts in ICY handler header

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

// I'm including the common types to avoid duplicate definitions
#include "common_types.h"

namespace icy2 {

// I'm defining listener connection information for active connection tracking
struct ListenerInfo {
    std::string client_id;              // I track unique client identifier
    std::string ip_address;             // I store client IP address
    std::string user_agent;             // I maintain client software info
    std::chrono::system_clock::time_point connect_time; // I track connection start
    uint64_t bytes_sent = 0;            // I monitor data transfer
    std::string mount_point;            // I track accessed mount point
    bool metadata_enabled = false;      // I track metadata preference
};

// I'm defining source connection information for broadcaster management
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