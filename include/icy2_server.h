/**
 * File: include/icy2_server.h
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/icy2_server.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file as the public API for the ICY2-SERVER library
 *          that will be installed at /usr/include/icy2_server.h for other applications
 *          to integrate ICY2-SERVER functionality as a library or SDK component.
 * 
 * Reason: I need a clean, stable public API that abstracts the complexity of the
 *         ICY2-SERVER while providing essential streaming, authentication, and
 *         management functionality for third-party applications and services.
 *
 * Changelog:
 * 2025-07-16 - Initial public API with essential server functionality
 * 2025-07-16 - Added streaming and mount point management functions
 * 2025-07-16 - Implemented authentication and security API functions
 * 2025-07-16 - Added configuration and monitoring API functions
 * 2025-07-16 - Integrated callback and event handling mechanisms
 *
 * Next Dev Feature: I plan to add advanced streaming options and clustering support
 * Git Commit: feat: implement public library API for third-party integration
 *
 * TODO: Add advanced configuration API, clustering functions, plugin system
 */

#ifndef ICY2_SERVER_PUBLIC_H
#define ICY2_SERVER_PUBLIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * I'm defining the library version information
 * This helps applications verify compatibility
 */
#define ICY2_VERSION_MAJOR 1
#define ICY2_VERSION_MINOR 1
#define ICY2_VERSION_PATCH 1
#define ICY2_VERSION_STRING "1.1.1"

/**
 * I'm defining return codes for all library functions
 * This provides consistent error handling across the API
 */
typedef enum {
    ICY2_SUCCESS = 0,           // I indicate successful operation
    ICY2_ERROR_INVALID_PARAM,   // I flag invalid parameter values
    ICY2_ERROR_NOT_INITIALIZED, // I flag uninitialized library state
    ICY2_ERROR_ALREADY_RUNNING, // I flag server already running
    ICY2_ERROR_NOT_RUNNING,     // I flag server not running
    ICY2_ERROR_CONFIG_ERROR,    // I flag configuration errors
    ICY2_ERROR_NETWORK_ERROR,   // I flag network-related errors
    ICY2_ERROR_SSL_ERROR,       // I flag SSL/TLS errors
    ICY2_ERROR_AUTH_FAILED,     // I flag authentication failures
    ICY2_ERROR_PERMISSION_DENIED, // I flag permission errors
    ICY2_ERROR_FILE_NOT_FOUND,  // I flag missing files
    ICY2_ERROR_OUT_OF_MEMORY,   // I flag memory allocation failures
    ICY2_ERROR_TIMEOUT,         // I flag timeout conditions
    ICY2_ERROR_UNKNOWN          // I flag unspecified errors
} icy2_result_t;

/**
 * I'm defining log levels for library logging
 * This allows applications to control logging verbosity
 */
typedef enum {
    ICY2_LOG_DEBUG = 0,         // I provide detailed debugging information
    ICY2_LOG_INFO = 1,          // I provide general information
    ICY2_LOG_WARNING = 2,       // I provide warning conditions
    ICY2_LOG_ERROR = 3,         // I provide error conditions
    ICY2_LOG_CRITICAL = 4       // I provide critical system errors
} icy2_log_level_t;

/**
 * I'm defining connection types for callback identification
 * This helps applications handle different connection types
 */
typedef enum {
    ICY2_CONNECTION_LISTENER,   // I identify listener connections
    ICY2_CONNECTION_SOURCE,     // I identify source/broadcaster connections
    ICY2_CONNECTION_ADMIN,      // I identify admin interface connections
    ICY2_CONNECTION_API         // I identify API connections
} icy2_connection_type_t;

/**
 * I'm defining server handle as an opaque pointer
 * This hides implementation details from library users
 */
typedef struct icy2_server* icy2_server_handle_t;

/**
 * I'm defining mount point handle as an opaque pointer
 * This provides mount point management functionality
 */
typedef struct icy2_mount* icy2_mount_handle_t;

/**
 * I'm defining session handle as an opaque pointer
 * This manages authentication sessions
 */
typedef struct icy2_session* icy2_session_handle_t;

/**
 * I'm creating a structure for server configuration
 * This provides basic server configuration options
 */
typedef struct {
    const char* config_file_path;   // I specify configuration file path
    const char* bind_address;       // I set bind IP address
    uint16_t http_port;             // I set HTTP port
    uint16_t https_port;            // I set HTTPS port
    bool ssl_enabled;               // I control SSL functionality
    const char* ssl_cert_path;      // I specify SSL certificate path
    const char* ssl_key_path;       // I specify SSL private key path
    int debug_level;                // I set debug verbosity (0-4)
    int max_connections;            // I limit concurrent connections
    bool php_enabled;               // I control PHP-FPM integration
    const char* document_root;      // I set web document root
} icy2_config_t;

/**
 * I'm creating a structure for mount point configuration
 * This defines streaming mount point settings
 */
typedef struct {
    const char* mount_path;         // I specify mount point path
    const char* name;               // I set display name
    const char* description;        // I set description
    int max_listeners;              // I limit concurrent listeners
    bool public_listing;            // I control directory visibility
    bool require_auth;              // I enforce authentication
    const char* password;           // I set source password
    bool metadata_enabled;          // I control metadata injection
    int metadata_interval;          // I set metadata frequency
} icy2_mount_config_t;

/**
 * I'm creating a structure for connection information
 * This provides details about active connections
 */
typedef struct {
    const char* connection_id;      // I provide unique connection identifier
    icy2_connection_type_t type;    // I identify connection type
    const char* ip_address;         // I provide client IP address
    uint16_t port;                  // I provide client port
    const char* user_agent;         // I provide client user agent
    const char* mount_point;        // I identify associated mount point
    uint64_t bytes_sent;            // I count bytes sent to client
    uint64_t bytes_received;        // I count bytes received from client
    uint64_t connected_seconds;     // I track connection duration
    bool authenticated;             // I flag authentication status
    const char* username;           // I provide authenticated username
} icy2_connection_info_t;

/**
 * I'm creating a structure for server statistics
 * This provides comprehensive server metrics
 */
typedef struct {
    uint64_t total_connections;     // I count total connections ever made
    uint64_t active_connections;    // I count currently active connections
    uint64_t total_bytes_sent;      // I sum all bytes sent
    uint64_t total_bytes_received;  // I sum all bytes received
    uint64_t uptime_seconds;        // I calculate server uptime
    int active_mount_points;        // I count active mount points
    int total_listeners;            // I count total listeners across all mounts
    uint64_t http_requests;         // I count HTTP requests processed
    uint64_t api_requests;          // I count API requests processed
    uint64_t auth_failures;         // I count authentication failures
} icy2_stats_t;

/**
 * I'm defining callback function types for event handling
 * This allows applications to receive notifications
 */

/**
 * I'm defining the log callback function type
 * Applications can implement this to receive log messages
 */
typedef void (*icy2_log_callback_t)(icy2_log_level_t level, const char* message, const char* component);

/**
 * I'm defining the connection callback function type
 * Applications can implement this to monitor connections
 */
typedef void (*icy2_connection_callback_t)(const char* event, const icy2_connection_info_t* info);

/**
 * I'm defining the metadata callback function type
 * Applications can implement this to monitor metadata updates
 */
typedef void (*icy2_metadata_callback_t)(const char* mount_path, const char* metadata_json);

/**
 * I'm defining the authentication callback function type
 * Applications can implement custom authentication logic
 */
typedef bool (*icy2_auth_callback_t)(const char* username, const char* password, const char* ip_address);

/**
 * I'm defining the server lifecycle functions
 * These functions control the basic server operations
 */

/**
 * I'm creating the function to get library version information
 * @param major Pointer to store major version number
 * @param minor Pointer to store minor version number
 * @param patch Pointer to store patch version number
 * @return Version string
 */
const char* icy2_get_version(int* major, int* minor, int* patch);

/**
 * I'm creating the function to initialize the ICY2-SERVER library
 * @return ICY2_SUCCESS if initialization succeeded
 */
icy2_result_t icy2_initialize();

/**
 * I'm creating the function to cleanup the ICY2-SERVER library
 * @return ICY2_SUCCESS if cleanup succeeded
 */
icy2_result_t icy2_cleanup();

/**
 * I'm creating the function to create a server instance
 * @param config Server configuration structure
 * @param handle Pointer to store server handle
 * @return ICY2_SUCCESS if server was created successfully
 */
icy2_result_t icy2_server_create(const icy2_config_t* config, icy2_server_handle_t* handle);

/**
 * I'm creating the function to start the server
 * @param handle Server handle
 * @return ICY2_SUCCESS if server started successfully
 */
icy2_result_t icy2_server_start(icy2_server_handle_t handle);

/**
 * I'm creating the function to stop the server
 * @param handle Server handle
 * @return ICY2_SUCCESS if server stopped successfully
 */
icy2_result_t icy2_server_stop(icy2_server_handle_t handle);

/**
 * I'm creating the function to destroy a server instance
 * @param handle Server handle
 * @return ICY2_SUCCESS if server was destroyed successfully
 */
icy2_result_t icy2_server_destroy(icy2_server_handle_t handle);

/**
 * I'm creating the function to check if server is running
 * @param handle Server handle
 * @param running Pointer to store running status
 * @return ICY2_SUCCESS if status was retrieved successfully
 */
icy2_result_t icy2_server_is_running(icy2_server_handle_t handle, bool* running);

/**
 * I'm defining the configuration management functions
 * These functions handle server configuration
 */

/**
 * I'm creating the function to reload server configuration
 * @param handle Server handle
 * @return ICY2_SUCCESS if configuration was reloaded successfully
 */
icy2_result_t icy2_server_reload_config(icy2_server_handle_t handle);

/**
 * I'm creating the function to validate configuration file
 * @param config_path Path to configuration file
 * @param errors Buffer to store error messages (optional)
 * @param errors_size Size of error buffer
 * @return ICY2_SUCCESS if configuration is valid
 */
icy2_result_t icy2_validate_config(const char* config_path, char* errors, size_t errors_size);

/**
 * I'm defining the mount point management functions
 * These functions handle streaming mount points
 */

/**
 * I'm creating the function to add a mount point
 * @param handle Server handle
 * @param config Mount point configuration
 * @param mount_handle Pointer to store mount handle
 * @return ICY2_SUCCESS if mount point was added successfully
 */
icy2_result_t icy2_mount_add(icy2_server_handle_t handle, const icy2_mount_config_t* config, 
                            icy2_mount_handle_t* mount_handle);

/**
 * I'm creating the function to remove a mount point
 * @param handle Server handle
 * @param mount_path Mount point path to remove
 * @return ICY2_SUCCESS if mount point was removed successfully
 */
icy2_result_t icy2_mount_remove(icy2_server_handle_t handle, const char* mount_path);

/**
 * I'm creating the function to get mount point listener count
 * @param handle Server handle
 * @param mount_path Mount point path
 * @param count Pointer to store listener count
 * @return ICY2_SUCCESS if count was retrieved successfully
 */
icy2_result_t icy2_mount_get_listeners(icy2_server_handle_t handle, const char* mount_path, int* count);

/**
 * I'm creating the function to update mount point metadata
 * @param handle Server handle
 * @param mount_path Mount point path
 * @param metadata_json JSON metadata string
 * @return ICY2_SUCCESS if metadata was updated successfully
 */
icy2_result_t icy2_mount_update_metadata(icy2_server_handle_t handle, const char* mount_path, 
                                        const char* metadata_json);

/**
 * I'm defining the authentication and session management functions
 * These functions handle user authentication and sessions
 */

/**
 * I'm creating the function to authenticate a user
 * @param handle Server handle
 * @param username Username to authenticate
 * @param password Password for authentication
 * @param ip_address Client IP address
 * @param session_handle Pointer to store session handle
 * @return ICY2_SUCCESS if authentication succeeded
 */
icy2_result_t icy2_auth_login(icy2_server_handle_t handle, const char* username, const char* password, 
                             const char* ip_address, icy2_session_handle_t* session_handle);

/**
 * I'm creating the function to logout a session
 * @param handle Server handle
 * @param session_handle Session handle to logout
 * @return ICY2_SUCCESS if logout succeeded
 */
icy2_result_t icy2_auth_logout(icy2_server_handle_t handle, icy2_session_handle_t session_handle);

/**
 * I'm creating the function to validate a session
 * @param handle Server handle
 * @param session_id Session identifier
 * @param valid Pointer to store validation result
 * @return ICY2_SUCCESS if validation completed
 */
icy2_result_t icy2_auth_validate_session(icy2_server_handle_t handle, const char* session_id, bool* valid);

/**
 * I'm creating the function to create a user account
 * @param handle Server handle
 * @param username Username for new account
 * @param password Password for new account
 * @param email Email address for new account
 * @param role User role (admin, user, etc.)
 * @return ICY2_SUCCESS if user was created successfully
 */
icy2_result_t icy2_auth_create_user(icy2_server_handle_t handle, const char* username, 
                                   const char* password, const char* email, const char* role);

/**
 * I'm defining the monitoring and statistics functions
 * These functions provide server monitoring capabilities
 */

/**
 * I'm creating the function to get server statistics
 * @param handle Server handle
 * @param stats Pointer to store statistics
 * @return ICY2_SUCCESS if statistics were retrieved successfully
 */
icy2_result_t icy2_get_stats(icy2_server_handle_t handle, icy2_stats_t* stats);

/**
 * I'm creating the function to get active connections
 * @param handle Server handle
 * @param connections Array to store connection information
 * @param count Input: array size, Output: number of connections
 * @return ICY2_SUCCESS if connections were retrieved successfully
 */
icy2_result_t icy2_get_connections(icy2_server_handle_t handle, icy2_connection_info_t* connections, 
                                  int* count);

/**
 * I'm creating the function to get server information as JSON
 * @param handle Server handle
 * @param json_buffer Buffer to store JSON string
 * @param buffer_size Size of JSON buffer
 * @return ICY2_SUCCESS if information was retrieved successfully
 */
icy2_result_t icy2_get_server_info_json(icy2_server_handle_t handle, char* json_buffer, size_t buffer_size);

/**
 * I'm defining the callback registration functions
 * These functions allow applications to register for events
 */

/**
 * I'm creating the function to set the log callback
 * @param handle Server handle
 * @param callback Log callback function
 * @return ICY2_SUCCESS if callback was set successfully
 */
icy2_result_t icy2_set_log_callback(icy2_server_handle_t handle, icy2_log_callback_t callback);

/**
 * I'm creating the function to set the connection callback
 * @param handle Server handle
 * @param callback Connection callback function
 * @return ICY2_SUCCESS if callback was set successfully
 */
icy2_result_t icy2_set_connection_callback(icy2_server_handle_t handle, icy2_connection_callback_t callback);

/**
 * I'm creating the function to set the metadata callback
 * @param handle Server handle
 * @param callback Metadata callback function
 * @return ICY2_SUCCESS if callback was set successfully
 */
icy2_result_t icy2_set_metadata_callback(icy2_server_handle_t handle, icy2_metadata_callback_t callback);

/**
 * I'm creating the function to set the authentication callback
 * @param handle Server handle
 * @param callback Authentication callback function
 * @return ICY2_SUCCESS if callback was set successfully
 */
icy2_result_t icy2_set_auth_callback(icy2_server_handle_t handle, icy2_auth_callback_t callback);

/**
 * I'm defining the SSL certificate management functions
 * These functions handle SSL certificate operations
 */

/**
 * I'm creating the function to generate self-signed certificates
 * @param cert_path Output certificate file path
 * @param key_path Output private key file path
 * @param hostname Hostname for certificate
 * @param days_valid Number of days certificate is valid
 * @return ICY2_SUCCESS if certificates were generated successfully
 */
icy2_result_t icy2_ssl_generate_cert(const char* cert_path, const char* key_path, 
                                    const char* hostname, int days_valid);

/**
 * I'm creating the function to validate SSL certificates
 * @param cert_path Certificate file path
 * @param key_path Private key file path
 * @param valid Pointer to store validation result
 * @return ICY2_SUCCESS if validation completed
 */
icy2_result_t icy2_ssl_validate_cert(const char* cert_path, const char* key_path, bool* valid);

/**
 * I'm defining the utility functions
 * These functions provide general utility operations
 */

/**
 * I'm creating the function to get error message for result code
 * @param result Result code
 * @return Error message string
 */
const char* icy2_get_error_message(icy2_result_t result);

/**
 * I'm creating the function to set debug level
 * @param handle Server handle
 * @param level Debug level (0-4)
 * @return ICY2_SUCCESS if debug level was set successfully
 */
icy2_result_t icy2_set_debug_level(icy2_server_handle_t handle, int level);

/**
 * I'm creating the function to get library build information
 * @param json_buffer Buffer to store JSON build info
 * @param buffer_size Size of buffer
 * @return ICY2_SUCCESS if build info was retrieved successfully
 */
icy2_result_t icy2_get_build_info(char* json_buffer, size_t buffer_size);

/**
 * I'm creating the function to test network connectivity
 * @param host Hostname or IP address to test
 * @param port Port number to test
 * @param timeout_ms Timeout in milliseconds
 * @param reachable Pointer to store reachability result
 * @return ICY2_SUCCESS if test completed
 */
icy2_result_t icy2_test_connectivity(const char* host, uint16_t port, int timeout_ms, bool* reachable);

/**
 * I'm defining the advanced configuration functions
 * These functions provide advanced server configuration
 */

/**
 * I'm creating the function to set configuration value dynamically
 * @param handle Server handle
 * @param key_path Dot-separated configuration key path
 * @param value New value to set
 * @return ICY2_SUCCESS if value was set successfully
 */
icy2_result_t icy2_config_set_value(icy2_server_handle_t handle, const char* key_path, const char* value);

/**
 * I'm creating the function to get configuration value
 * @param handle Server handle
 * @param key_path Dot-separated configuration key path
 * @param value_buffer Buffer to store value
 * @param buffer_size Size of value buffer
 * @return ICY2_SUCCESS if value was retrieved successfully
 */
icy2_result_t icy2_config_get_value(icy2_server_handle_t handle, const char* key_path, 
                                   char* value_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif // ICY2_SERVER_PUBLIC_H
