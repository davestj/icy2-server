/**
 * File: src/helper.cpp
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/src/helper.cpp
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this helper implementation to provide utility functions,
 *          system information gathering, JSON formatting, API responses, and
 *          common functionality used throughout ICY2-SERVER.
 * 
 * Reason: I need a centralized collection of utility functions that handle
 *         system monitoring, data formatting, file operations, network utilities,
 *         and API response generation to maintain consistency and avoid duplication.
 *
 * Changelog:
 * 2025-07-16 - Initial helper implementation with system info and JSON utilities
 * 2025-07-16 - Added comprehensive string manipulation and validation functions
 * 2025-07-16 - Implemented file system utilities and security validation
 * 2025-07-16 - Added network utilities and IP address handling
 * 2025-07-16 - Integrated logging and error handling mechanisms
 *
 * Next Dev Feature: I plan to add database utilities and advanced caching helpers
 * Git Commit: feat: implement comprehensive utility and API helper functions
 *
 * TODO: Add database abstraction, caching layer, advanced string formatting, crypto helpers
 */

#include "helper.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace icy2 {

namespace fs = std::filesystem;

/**
 * I'm implementing the APIHelper constructor
 * This initializes the helper with default settings
 */
APIHelper::APIHelper() 
    : log_level_(LogLevel::INFO)
    , start_time_(std::chrono::steady_clock::now())
{
    // I initialize with default values
    server_id_ = "icy2-server-" + generate_uuid().substr(0, 8);
    api_version_ = "1.0";
}

/**
 * I'm implementing the APIHelper destructor
 * This ensures proper cleanup of resources
 */
APIHelper::~APIHelper() {
    // I clean up any resources if needed
}

/**
 * I'm implementing the initialization method
 * This configures the helper with server-specific settings
 */
bool APIHelper::initialize(const std::string& server_id, const std::string& api_version, LogLevel log_level) {
    server_id_ = server_id;
    api_version_ = api_version;
    log_level_ = log_level;
    
    // I gather build information
    build_info_ = gather_build_info();
    
    log_message(LogLevel::INFO, "APIHelper initialized successfully");
    return true;
}

/**
 * I'm implementing the system information gathering method
 * This collects comprehensive system details
 */
SystemInfo APIHelper::gather_system_info() {
    SystemInfo info;
    
    // I get system and OS information
    struct utsname uname_data;
    if (uname(&uname_data) == 0) {
        info.hostname = uname_data.nodename;
        info.operating_system = uname_data.sysname;
        info.kernel_version = uname_data.release;
        info.architecture = uname_data.machine;
    }
    
    // I get CPU information including cores and threads
    info.cpu_cores = std::thread::hardware_concurrency();
    info.cpu_threads = info.cpu_cores; // I assume 1:1 for now

    // I read the CPU model from /proc/cpuinfo
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("model name") != std::string::npos) {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                info.cpu_model = trim_string(line.substr(colon_pos + 1));
                break;
            }
        }
    }
    
    // I get memory information in bytes
    struct sysinfo sys_info;
    if (sysinfo(&sys_info) == 0) {
        info.total_memory_bytes = sys_info.totalram * sys_info.mem_unit;
        info.available_memory_bytes = sys_info.freeram * sys_info.mem_unit;
        info.used_memory_bytes = info.total_memory_bytes - info.available_memory_bytes;
        info.memory_usage_percent = (double)info.used_memory_bytes / info.total_memory_bytes * 100.0;
        
        info.uptime = std::chrono::seconds(sys_info.uptime);
        info.load_average_1min = sys_info.loads[0] / 65536.0;
        info.load_average_5min = sys_info.loads[1] / 65536.0;
        info.load_average_15min = sys_info.loads[2] / 65536.0;
    }
    
    // I get disk information for the root filesystem in bytes
    auto disk_usage = get_disk_usage("/");
    info.total_disk_bytes = disk_usage["total"];
    info.available_disk_bytes = disk_usage["available"];
    info.used_disk_bytes = disk_usage["used"];
    info.disk_usage_percent = (double)info.used_disk_bytes / info.total_disk_bytes * 100.0;
    
    // I get network interfaces
    info.network_interfaces = get_network_interfaces();
    
    // I calculate boot time
    auto now = std::chrono::system_clock::now();
    auto boot_time_point = now - std::chrono::duration_cast<std::chrono::system_clock::duration>(info.uptime);
    info.boot_time = boot_time_point;
    
    // I get relevant environment variables
    const char* important_env_vars[] = {"PATH", "HOME", "USER", "SHELL", "LANG", "TZ"};
    for (const char* var : important_env_vars) {
        const char* value = std::getenv(var);
        if (value) {
            info.environment_variables[var] = value;
        }
    }
    
    return info;
}

/**
 * I'm implementing the network information gathering method
 * This collects details about network interfaces
 */
std::vector<NetworkInterface> APIHelper::gather_network_info() {
    std::vector<NetworkInterface> interfaces;
    
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        return interfaces; // I return empty vector on error
    }
    
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) {
            continue; // I skip non-IPv4 interfaces for now
        }
        
        NetworkInterface info;
        info.name = ifa->ifa_name;
        info.is_up = (ifa->ifa_flags & IFF_UP) != 0;
        info.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
        
        // I get IP address
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        info.ip_address = inet_ntoa(addr->sin_addr);
        
        // I get netmask
        if (ifa->ifa_netmask) {
            struct sockaddr_in* netmask = (struct sockaddr_in*)ifa->ifa_netmask;
            info.netmask = inet_ntoa(netmask->sin_addr);
        }
        
        // I get broadcast address
        if (ifa->ifa_broadaddr) {
            struct sockaddr_in* broadcast = (struct sockaddr_in*)ifa->ifa_broadaddr;
            info.broadcast = inet_ntoa(broadcast->sin_addr);
        }
        
        // I read statistics from /sys/class/net if available
        std::string stats_path = "/sys/class/net/" + info.name + "/statistics/";
        
        std::ifstream rx_bytes_file(stats_path + "rx_bytes");
        if (rx_bytes_file.is_open()) {
            rx_bytes_file >> info.bytes_received;
        }

        std::ifstream tx_bytes_file(stats_path + "tx_bytes");
        if (tx_bytes_file.is_open()) {
            tx_bytes_file >> info.bytes_sent;
        }
        
        interfaces.push_back(info);
    }
    
    freeifaddrs(ifaddr);
    return interfaces;
}

/**
 * I'm implementing the build information gathering method
 * This collects compilation and version details
 */
BuildInfo APIHelper::gather_build_info() {
    BuildInfo info;
    
    info.version = "1.1.1";
    info.build_date = __DATE__;
    info.build_time = __TIME__;
    info.compiler_name = 
#ifdef __GNUC__
        "GCC";
#elif defined(__clang__)
        "Clang";
#elif defined(_MSC_VER)
        "MSVC";
#else
        "Unknown";
#endif
    
    info.compiler_version = __VERSION__;
    
#ifdef DEBUG
    info.build_type = "Debug";
    info.debug_build = true;
#else
    info.build_type = "Release";
    info.debug_build = false;
#endif

#ifdef ICY2_SSL_ENABLED
    info.ssl_enabled = true;
#else
    info.ssl_enabled = false;
#endif

#ifdef ICY2_PHP_ENABLED
    info.php_support = true;
#else
    info.php_support = false;
#endif
    
    // I get hostname and username
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        info.build_host = hostname;
    }
    
    const char* username = std::getenv("USER");
    if (username) {
        info.build_user = username;
    }
    
    // I define features
    info.features = "HTTP/HTTPS Server, ICY Protocol v1.x/v2.0+, YAML Config, Multi-threading";
    
    // I add compile flags
    info.compile_flags = {"-std=c++17", "-Wall", "-Wextra"};
    
    // I add linked libraries
    info.linked_libraries = {"OpenSSL", "yaml-cpp", "FastCGI", "pthread"};
    
    return info;
}

/**
 * I'm implementing the server information method
 * This generates comprehensive server status JSON
 */
std::string APIHelper::get_server_info() {
    SystemInfo system_info = gather_system_info();
    std::vector<NetworkInterface> network_info = gather_network_info();
    
    std::map<std::string, std::string> data;
    
    // I add server identification
    data["server_id"] = server_id_;
    data["version"] = build_info_.version;
    data["api_version"] = api_version_;
    data["build_date"] = build_info_.build_date;
    data["build_time"] = build_info_.build_time;
    data["compiler"] = build_info_.compiler_name + " " + build_info_.compiler_version;
    data["build_type"] = build_info_.build_type;
    
    // I add system information
    data["hostname"] = system_info.hostname;
    data["os"] = system_info.operating_system;
    data["kernel"] = system_info.kernel_version;
    data["architecture"] = system_info.architecture;
    data["cpu_cores"] = std::to_string(system_info.cpu_cores);
    data["cpu_model"] = system_info.cpu_model;
    
    // I add memory information
    data["memory_total"] = format_number_with_units(system_info.total_memory_bytes, "B");
    data["memory_used"] = format_number_with_units(system_info.used_memory_bytes, "B");
    data["memory_available"] = format_number_with_units(system_info.available_memory_bytes, "B");
    data["memory_usage_percent"] = std::to_string(system_info.memory_usage_percent);
    
    // I add disk information
    data["disk_total"] = format_number_with_units(system_info.total_disk_bytes, "B");
    data["disk_used"] = format_number_with_units(system_info.used_disk_bytes, "B");
    data["disk_available"] = format_number_with_units(system_info.available_disk_bytes, "B");
    data["disk_usage_percent"] = std::to_string(system_info.disk_usage_percent);
    
    // I add load averages
    data["load_1min"] = std::to_string(system_info.load_average_1min);
    data["load_5min"] = std::to_string(system_info.load_average_5min);
    data["load_15min"] = std::to_string(system_info.load_average_15min);
    
    // I add uptime
    data["uptime"] = format_duration(system_info.uptime);
    data["boot_time"] = format_timestamp(system_info.boot_time);
    
    // I add feature flags
    data["ssl_enabled"] = build_info_.ssl_enabled ? "true" : "false";
    data["php_support"] = build_info_.php_support ? "true" : "false";
    data["debug_build"] = build_info_.debug_build ? "true" : "false";
    
    // I add runtime information
    auto runtime = std::chrono::steady_clock::now() - start_time_;
    data["runtime"] = format_duration(std::chrono::duration_cast<std::chrono::seconds>(runtime));
    data["timestamp"] = get_current_timestamp();
    
    return create_api_response(200, "Server information", data);
}

/**
 * I'm implementing the system status method
 * This provides current system status
 */
std::string APIHelper::get_system_status() {
    std::map<std::string, std::string> data;
    
    // I get current memory usage
    auto memory_usage = get_memory_usage();
    data["memory_total"] = std::to_string(memory_usage["total"]);
    data["memory_used"] = std::to_string(memory_usage["used"]);
    data["memory_free"] = std::to_string(memory_usage["free"]);
    
    // I get current disk usage
    auto disk_usage = get_disk_usage("/");
    data["disk_total"] = std::to_string(disk_usage["total"]);
    data["disk_used"] = std::to_string(disk_usage["used"]);
    data["disk_free"] = std::to_string(disk_usage["available"]);
    
    // I get current CPU usage
    data["cpu_usage"] = std::to_string(get_cpu_usage());
    
    // I get current timestamp
    data["timestamp"] = get_current_timestamp();
    data["status"] = "running";
    
    return create_api_response(200, "System status", data);
}

/**
 * I'm implementing the build information method
 * This provides compilation details
 */
std::string APIHelper::get_build_info() {
    std::map<std::string, std::string> data;
    
    data["version"] = build_info_.version;
    data["build_date"] = build_info_.build_date;
    data["build_time"] = build_info_.build_time;
    data["compiler"] = build_info_.compiler_name;
    data["compiler_version"] = build_info_.compiler_version;
    data["build_type"] = build_info_.build_type;
    data["build_host"] = build_info_.build_host;
    data["build_user"] = build_info_.build_user;
    data["features"] = build_info_.features;
    data["ssl_enabled"] = build_info_.ssl_enabled ? "true" : "false";
    data["php_support"] = build_info_.php_support ? "true" : "false";
    data["debug_build"] = build_info_.debug_build ? "true" : "false";
    
    return create_api_response(200, "Build information", data);
}

/**
 * I'm implementing the API response creation method
 * This generates standardized JSON responses
 */
std::string APIHelper::create_api_response(int status_code, const std::string& message,
                                         const std::map<std::string, std::string>& data,
                                         const std::string& request_id) {
    std::ostringstream json;
    json << "{";
    
    // I add response metadata
    json << "\"status_code\":" << status_code << ",";
    json << "\"status\":\"" << (status_code >= 200 && status_code < 300 ? "success" : "error") << "\",";
    json << "\"message\":\"" << escape_json_string(message) << "\",";
    json << "\"timestamp\":\"" << get_current_timestamp() << "\",";
    json << "\"api_version\":\"" << api_version_ << "\"";
    
    // I add request ID if provided
    if (!request_id.empty()) {
        json << ",\"request_id\":\"" << escape_json_string(request_id) << "\"";
    }
    
    // I add data section
    if (!data.empty()) {
        json << ",\"data\":{";
        bool first = true;
        for (const auto& pair : data) {
            if (!first) json << ",";
            json << "\"" << escape_json_string(pair.first) << "\":\"" << escape_json_string(pair.second) << "\"";
            first = false;
        }
        json << "}";
    }
    
    json << "}";
    return json.str();
}

/**
 * I'm implementing the error response creation method
 * This generates standardized error responses
 */
std::string APIHelper::create_error_response(int status_code, const std::string& error_message,
                                           const std::vector<std::string>& errors,
                                           const std::string& request_id) {
    std::ostringstream json;
    json << "{";
    
    json << "\"status_code\":" << status_code << ",";
    json << "\"status\":\"error\",";
    json << "\"message\":\"" << escape_json_string(error_message) << "\",";
    json << "\"timestamp\":\"" << get_current_timestamp() << "\",";
    json << "\"api_version\":\"" << api_version_ << "\"";
    
    if (!request_id.empty()) {
        json << ",\"request_id\":\"" << escape_json_string(request_id) << "\"";
    }
    
    if (!errors.empty()) {
        json << ",\"errors\":[";
        for (size_t i = 0; i < errors.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"" << escape_json_string(errors[i]) << "\"";
        }
        json << "]";
    }
    
    json << "}";
    return json.str();
}

/**
 * I'm implementing the logging method
 * This provides consistent logging throughout the application
 */
void APIHelper::log_message(LogLevel level, const std::string& message, const std::string& component) {
    // I check if this message should be logged based on current log level
    if (level < log_level_) {
        return;
    }
    
    // I format the log message
    std::string level_str;
    switch (level) {
        case LogLevel::DEBUG: level_str = "DEBUG"; break;
        case LogLevel::INFO: level_str = "INFO"; break;
        case LogLevel::WARNING: level_str = "WARNING"; break;
        case LogLevel::ERROR: level_str = "ERROR"; break;
        case LogLevel::CRITICAL: level_str = "CRITICAL"; break;
    }
    
    std::string timestamp = get_current_timestamp();
    std::string log_line = "[" + timestamp + "] [" + level_str + "]";
    
    if (!component.empty()) {
        log_line += " [" + component + "]";
    }
    
    log_line += " " + message;
    
    // I output to console for now
    if (level >= LogLevel::ERROR) {
        std::cerr << log_line << std::endl;
    } else {
        std::cout << log_line << std::endl;
    }
    
    // I call the custom log callback if set
    if (log_callback_) {
        log_callback_(level, log_line);
    }
}

/**
 * I'm implementing file validation method
 * This validates file paths for security
 */
bool APIHelper::validate_file_path(const std::string& file_path, const std::string& base_path) {
    // I normalize the paths
    std::string normalized_file = file_path;
    std::string normalized_base = base_path;
    
    // I check for path traversal attempts
    if (file_path.find("..") != std::string::npos) {
        return false;
    }
    
    // I check for absolute paths outside base
    if (file_path[0] == '/' && file_path.find(base_path) != 0) {
        return false;
    }
    
    // I check for null bytes
    if (file_path.find('\0') != std::string::npos) {
        return false;
    }
    
    return true;
}

/**
 * I'm implementing file reading method
 * This safely reads file contents
 */
std::string APIHelper::read_file_contents(const std::string& file_path, size_t max_size) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    
    // I check file size
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (file_size > max_size) {
        return ""; // I reject files that are too large
    }
    
    std::string content(file_size, '\0');
    file.read(&content[0], file_size);
    
    return content;
}

/**
 * I'm implementing file writing method
 * This safely writes file contents
 */
bool APIHelper::write_file_contents(const std::string& file_path, const std::string& contents,
                                   bool create_dirs) {
    if (create_dirs) {
        size_t last_slash = file_path.find_last_of('/');
        if (last_slash != std::string::npos) {
            std::string dir_path = file_path.substr(0, last_slash);
            if (!this->create_directories(dir_path)) {
                return false;
            }
        }
    }
    
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(contents.c_str(), contents.length());
    return file.good();
}

/**
 * I'm implementing string utility methods
 */
std::string APIHelper::trim_string(const std::string& text, const std::string& chars) {
    size_t start = text.find_first_not_of(chars);
    if (start == std::string::npos) {
        return "";
    }
    
    size_t end = text.find_last_not_of(chars);
    return text.substr(start, end - start + 1);
}

std::vector<std::string> APIHelper::split_string(const std::string& text, const std::string& delimiter, size_t max_splits) {
    std::vector<std::string> result;
    size_t start = 0;
    size_t splits = 0;
    
    while (start < text.length()) {
        size_t end = text.find(delimiter, start);
        
        if (end == std::string::npos || (max_splits > 0 && splits >= max_splits)) {
            result.push_back(text.substr(start));
            break;
        }
        
        result.push_back(text.substr(start, end - start));
        start = end + delimiter.length();
        splits++;
    }
    
    return result;
}

std::string APIHelper::join_strings(const std::vector<std::string>& strings, const std::string& delimiter) {
    std::ostringstream result;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (i > 0) result << delimiter;
        result << strings[i];
    }
    return result.str();
}

std::string APIHelper::to_lowercase(const std::string& text) {
    std::string result = text;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string APIHelper::to_uppercase(const std::string& text) {
    std::string result = text;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

/**
 * I'm implementing formatting utility methods
 */
std::string APIHelper::format_timestamp(const std::chrono::system_clock::time_point& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
    return oss.str();
}

std::string APIHelper::format_duration(const std::chrono::seconds& duration) {
    auto total_seconds = duration.count();
    auto days = total_seconds / 86400;
    auto hours = (total_seconds % 86400) / 3600;
    auto minutes = (total_seconds % 3600) / 60;
    auto seconds = total_seconds % 60;
    
    std::ostringstream oss;
    if (days > 0) {
        oss << days << "d ";
    }
    if (hours > 0) {
        oss << hours << "h ";
    }
    if (minutes > 0) {
        oss << minutes << "m ";
    }
    oss << seconds << "s";
    
    return oss.str();
}

std::string APIHelper::format_number_with_units(uint64_t value, const std::string& unit, bool binary) {
    const uint64_t base = binary ? 1024 : 1000;
    const std::vector<std::string> prefixes = binary ? 
        std::vector<std::string>{"", "Ki", "Mi", "Gi", "Ti", "Pi"} :
        std::vector<std::string>{"", "K", "M", "G", "T", "P"};
    
    double size = static_cast<double>(value);
    size_t prefix_index = 0;
    
    while (size >= base && prefix_index < prefixes.size() - 1) {
        size /= base;
        prefix_index++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << prefixes[prefix_index] << unit;
    return oss.str();
}

std::string APIHelper::get_current_timestamp(const std::string& format) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), format.c_str());
    return oss.str();
}

/**
 * I'm implementing JSON utility methods
 */
std::string APIHelper::escape_json_string(const std::string& input) {
    std::ostringstream oss;
    for (char c : input) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    oss << c;
                }
                break;
        }
    }
    return oss.str();
}

/**
 * I'm implementing system information methods
 */
std::map<std::string, uint64_t> APIHelper::get_disk_usage(const std::string& path) {
    std::map<std::string, uint64_t> usage;
    
    struct statvfs stat;
    if (statvfs(path.c_str(), &stat) == 0) {
        uint64_t total = stat.f_blocks * stat.f_frsize;
        uint64_t available = stat.f_bavail * stat.f_frsize;
        uint64_t used = total - available;
        
        usage["total"] = total;
        usage["used"] = used;
        usage["available"] = available;
    }
    
    return usage;
}

std::map<std::string, uint64_t> APIHelper::get_memory_usage() {
    std::map<std::string, uint64_t> usage;
    
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        usage["total"] = info.totalram * info.mem_unit;
        usage["free"] = info.freeram * info.mem_unit;
        usage["used"] = usage["total"] - usage["free"];
        usage["shared"] = info.sharedram * info.mem_unit;
        usage["buffer"] = info.bufferram * info.mem_unit;
    }
    
    return usage;
}

double APIHelper::get_cpu_usage() {
    // I implement a simple CPU usage calculation
    static uint64_t last_idle = 0;
    static uint64_t last_total = 0;
    
    std::ifstream stat_file("/proc/stat");
    std::string line;
    if (std::getline(stat_file, line) && line.substr(0, 3) == "cpu") {
        std::istringstream iss(line);
        std::string cpu;
        uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
        
        iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
        
        uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
        uint64_t total_diff = total - last_total;
        uint64_t idle_diff = idle - last_idle;
        
        double cpu_usage = 0.0;
        if (total_diff > 0) {
            cpu_usage = 100.0 * (total_diff - idle_diff) / total_diff;
        }
        
        last_total = total;
        last_idle = idle;
        
        return cpu_usage;
    }
    
    return 0.0;
}

/**
 * I'm implementing utility methods for file operations
 */
bool APIHelper::create_directories(const std::string& path) {
    try {
        fs::create_directories(path);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool APIHelper::path_exists(const std::string& path) {
    return fs::exists(path);
}

std::chrono::system_clock::time_point APIHelper::get_file_modification_time(const std::string& file_path) {
    try {
        auto ftime = fs::last_write_time(file_path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
        return sctp;
    } catch (const std::exception&) {
        return std::chrono::system_clock::time_point{};
    }
}

uint64_t APIHelper::get_file_size(const std::string& file_path) {
    try {
        return fs::file_size(file_path);
    } catch (const std::exception&) {
        return 0;
    }
}

/**
 * I'm implementing UUID generation
 */
std::string APIHelper::generate_uuid() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::ostringstream oss;
    oss << std::hex;
    
    for (int i = 0; i < 32; ++i) {
        if (i == 8 || i == 12 || i == 16 || i == 20) oss << "-";
        oss << dis(gen);
    }
    
    return oss.str();
}

/**
 * I'm implementing hash calculation
 */
std::string APIHelper::calculate_hash(const std::string& data, const std::string& algorithm) {
    const EVP_MD* md = nullptr;
    
    if (algorithm == "md5") {
        md = EVP_md5();
    } else if (algorithm == "sha1") {
        md = EVP_sha1();
    } else if (algorithm == "sha256") {
        md = EVP_sha256();
    } else {
        return ""; // I don't support this algorithm
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    if (EVP_DigestUpdate(ctx, data.c_str(), data.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    // I convert to hex string
    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return oss.str();
}

/**
 * I'm implementing base64 encoding/decoding
 */
std::string APIHelper::base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    
    return result;
}

std::vector<uint8_t> APIHelper::base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    std::vector<uint8_t> result(encoded.length());
    int decoded_length = BIO_read(bio, result.data(), encoded.length());
    
    BIO_free_all(bio);
    
    if (decoded_length > 0) {
        result.resize(decoded_length);
    } else {
        result.clear();
    }
    
    return result;
}

/**
 * I'm implementing remaining interface methods
 */
void APIHelper::set_log_callback(std::function<void(LogLevel, const std::string&)> callback) {
    log_callback_ = callback;
}

std::vector<NetworkInterface> APIHelper::get_network_interfaces() {
    return gather_network_info();
}

std::string APIHelper::html_escape(const std::string& input) {
    std::ostringstream oss;
    for (char c : input) {
        switch (c) {
            case '<': oss << "&lt;"; break;
            case '>': oss << "&gt;"; break;
            case '&': oss << "&amp;"; break;
            case '"': oss << "&quot;"; break;
            case '\'': oss << "&#39;"; break;
            default: oss << c; break;
        }
    }
    return oss.str();
}

bool APIHelper::is_valid_utf8(const std::string& text) {
    // I implement basic UTF-8 validation
    for (size_t i = 0; i < text.length(); ) {
        unsigned char c = text[i];
        
        if (c < 0x80) {
            i++;
        } else if ((c >> 5) == 0x06) {
            if (i + 1 >= text.length() || (text[i + 1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((c >> 4) == 0x0E) {
            if (i + 2 >= text.length() || (text[i + 1] & 0xC0) != 0x80 || (text[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((c >> 3) == 0x1E) {
            if (i + 3 >= text.length() || (text[i + 1] & 0xC0) != 0x80 || (text[i + 2] & 0xC0) != 0x80 || (text[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

} // namespace icy2
