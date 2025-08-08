/**
 * File: include/auth_token.h
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/auth_token.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file to define the authentication and token management
 *          system for ICY2-SERVER. This handles JWT tokens, user authentication, 
 *          session management, and implements zero trust security principles.
 * 
 * Reason: I need a comprehensive authentication system that supports both legacy
 *         password-based authentication and modern JWT token-based authentication
 *         with proper security measures including rate limiting and threat detection.
 *
 * Changelog:
 * 2025-07-16 - Initial authentication system with JWT token support
 * 2025-07-16 - Added rate limiting and brute force protection
 * 2025-07-16 - Implemented session management and token validation
 * 2025-07-16 - Added IP-based access control and geo-blocking
 * 2025-07-16 - Integrated certificate-based authentication for ICY 2.0+
 *
 * Next Dev Feature: I plan to add LDAP integration, OAuth2 support, and hardware tokens
 * Git Commit: feat: implement comprehensive authentication system with JWT and security
 *
 * TODO: Add OAuth2 flows, LDAP integration, hardware token support, SSO integration
 */

#ifndef AUTH_TOKEN_H
#define AUTH_TOKEN_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <regex>

namespace icy2 {

/**
 * I'm defining authentication types supported by the system
 * This allows me to handle different authentication methods appropriately
 */
enum class AuthenticationType {
    NONE,               // I allow unauthenticated access
    PASSWORD,           // I use traditional username/password authentication
    JWT_TOKEN,          // I use JWT token-based authentication
    CERTIFICATE,        // I use client certificate authentication
    API_KEY,            // I use API key authentication
    BEARER_TOKEN,       // I use HTTP Bearer token authentication
    OAUTH2,             // I use OAuth2 authentication (future)
    LDAP                // I use LDAP authentication (future)
};

/**
 * I'm defining user roles and permissions
 * This implements role-based access control (RBAC)
 */
enum class UserRole {
    ANONYMOUS,          // I allow basic listener access
    LISTENER,           // I allow authenticated listener access
    BROADCASTER,        // I allow source streaming permissions
    MODERATOR,          // I allow stream moderation capabilities
    ADMIN,              // I allow full administrative access
    SUPER_ADMIN,        // I allow system-level administration
    API_USER,           // I allow API access only
    SERVICE_ACCOUNT     // I allow automated service access
};

/**
 * I'm defining permission flags for fine-grained access control
 * This allows me to implement detailed authorization policies
 */
enum class Permission {
    LISTEN_STREAM,      // I allow listening to streams
    BROADCAST_STREAM,   // I allow broadcasting/source streaming
    MANAGE_METADATA,    // I allow metadata updates
    ADMIN_ACCESS,       // I allow admin interface access
    API_ACCESS,         // I allow API endpoint access
    VIEW_STATISTICS,    // I allow viewing server statistics
    MANAGE_USERS,       // I allow user management
    MANAGE_MOUNTS,      // I allow mount point management
    MANAGE_CONFIG,      // I allow configuration changes
    SYSTEM_CONTROL,     // I allow server start/stop/restart
    CERTIFICATE_MGMT,   // I allow certificate management
    LOG_ACCESS,         // I allow log file access
    FILE_UPLOAD,        // I allow file uploads
    YP_MANAGEMENT       // I allow YP directory management
};

/**
 * I'm creating a structure for authentication attempts tracking
 * This helps me implement rate limiting and brute force protection
 */
struct AuthAttempt {
    std::string ip_address;                 // I track the source IP
    std::string username;                   // I track attempted username
    AuthenticationType auth_type;           // I track authentication method
    std::chrono::system_clock::time_point timestamp; // I record attempt time
    bool successful;                        // I flag if attempt succeeded
    std::string user_agent;                 // I track client user agent
    std::string failure_reason;             // I store failure details
    std::string geolocation;                // I track geographic location
};

/**
 * I'm creating a structure for user sessions
 * This manages active user sessions and their state
 */
struct UserSession {
    std::string session_id;                 // I assign unique session identifier
    std::string user_id;                    // I link to user account
    std::string username;                   // I store username for convenience
    UserRole role;                          // I track user role
    std::vector<Permission> permissions;    // I store granted permissions
    std::string ip_address;                 // I track session IP
    std::chrono::system_clock::time_point created_at; // I record session creation
    std::chrono::system_clock::time_point last_activity; // I track last activity
    std::chrono::system_clock::time_point expires_at; // I set session expiration
    std::string jwt_token;                  // I store associated JWT token
    bool is_active;                         // I flag session status
    std::map<std::string, std::string> metadata; // I store session metadata
    std::string refresh_token;              // I store refresh token
    int refresh_count;                      // I track token refreshes
};

/**
 * I'm creating a structure for user account information
 * This stores user details and authentication data
 */
struct UserAccount {
    std::string user_id;                    // I assign unique user identifier
    std::string username;                   // I store username
    std::string email;                      // I store email address
    std::string password_hash;              // I store hashed password
    std::string salt;                       // I store password salt
    UserRole role;                          // I assign user role
    std::vector<Permission> permissions;    // I grant specific permissions
    bool account_enabled;                   // I control account status
    bool email_verified;                    // I track email verification
    std::chrono::system_clock::time_point created_at; // I record account creation
    std::chrono::system_clock::time_point last_login; // I track last login
    std::chrono::system_clock::time_point password_changed; // I track password changes
    int failed_login_attempts;             // I count failed attempts
    std::chrono::system_clock::time_point locked_until; // I track account lockout
    std::string two_factor_secret;          // I store 2FA secret
    bool two_factor_enabled;                // I flag 2FA requirement
    std::vector<std::string> allowed_ips;   // I restrict IP access
    std::vector<std::string> api_keys;      // I store API keys
    std::map<std::string, std::string> profile; // I store additional profile data
};

/**
 * I'm creating a structure for JWT token claims
 * This defines the contents of JWT tokens I issue
 */
struct JWTClaims {
    std::string issuer;                     // I identify token issuer (iss)
    std::string subject;                    // I identify token subject (sub) 
    std::string audience;                   // I specify token audience (aud)
    std::chrono::system_clock::time_point issued_at; // I record issue time (iat)
    std::chrono::system_clock::time_point expires_at; // I set expiration (exp)
    std::chrono::system_clock::time_point not_before; // I set valid from time (nbf)
    std::string jti;                        // I assign unique token ID (jti)
    std::string username;                   // I embed username
    UserRole role;                          // I embed user role
    std::vector<Permission> permissions;    // I embed permissions
    std::string session_id;                 // I link to session
    std::string ip_address;                 // I bind to IP address
    std::map<std::string, std::string> custom_claims; // I allow custom claims
};

/**
 * I'm creating a structure for API key information
 * This manages API key authentication and permissions
 */
struct APIKey {
    std::string key_id;                     // I assign unique key identifier
    std::string key_hash;                   // I store hashed API key
    std::string name;                       // I assign descriptive name
    std::string user_id;                    // I link to user account
    std::vector<Permission> permissions;    // I limit key permissions
    std::vector<std::string> allowed_ips;   // I restrict IP access
    std::chrono::system_clock::time_point created_at; // I record creation time
    std::chrono::system_clock::time_point expires_at; // I set expiration
    std::chrono::system_clock::time_point last_used; // I track last usage
    int usage_count;                        // I count API calls
    int rate_limit_per_hour;                // I set rate limits
    bool is_active;                         // I control key status
    std::string description;                // I store key purpose
};

/**
 * I'm creating a structure for security events
 * This tracks security-related incidents for monitoring
 */
struct SecurityEvent {
    std::string event_id;                   // I assign unique event identifier
    std::string event_type;                 // I categorize the event
    std::string source_ip;                  // I track source IP
    std::string username;                   // I track affected username
    std::chrono::system_clock::time_point timestamp; // I record event time
    std::string description;                // I describe the event
    std::string severity;                   // I rate event severity
    std::string user_agent;                 // I track client information
    std::string geolocation;                // I track geographic location
    std::map<std::string, std::string> metadata; // I store additional details
    bool requires_action;                   // I flag if action needed
    std::string action_taken;               // I record response actions
};

/**
 * I'm defining the main authentication and token manager class
 * This orchestrates all authentication and authorization operations
 */
class AuthTokenManager {
private:
    // I'm defining user and session storage
    std::unordered_map<std::string, UserAccount> users_;    // I store user accounts
    std::unordered_map<std::string, UserSession> sessions_; // I manage active sessions
    std::unordered_map<std::string, APIKey> api_keys_;      // I store API keys
    std::mutex users_mutex_;                                // I protect user data
    std::mutex sessions_mutex_;                             // I protect session data
    std::mutex api_keys_mutex_;                             // I protect API key data

    // I'm defining authentication tracking
    std::vector<AuthAttempt> auth_attempts_;                // I track auth attempts
    std::vector<SecurityEvent> security_events_;            // I log security events
    std::mutex auth_attempts_mutex_;                        // I protect attempt data
    std::mutex security_events_mutex_;                      // I protect event data

    // I'm defining configuration
    std::string jwt_secret_;                                // I store JWT signing secret
    int token_expiration_hours_;                            // I set token lifetime
    int max_failed_attempts_;                               // I limit failed attempts
    int lockout_duration_minutes_;                          // I set lockout duration
    bool rate_limiting_enabled_;                            // I control rate limiting
    std::string hash_algorithm_;                            // I specify hash algorithm
    int bcrypt_rounds_;                                     // I set bcrypt rounds

    // I'm defining rate limiting and security
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> rate_limits_; // I track IP rates
    std::unordered_map<std::string, int> failed_attempts_; // I count failed attempts per IP
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lockouts_; // I track IP lockouts
    std::mutex rate_limit_mutex_;                           // I protect rate limit data

    // I'm defining helper methods
    std::string generate_session_id();                      // I create unique session IDs
    std::string generate_jwt_token(const JWTClaims& claims); // I create JWT tokens
    bool validate_jwt_token(const std::string& token, JWTClaims& claims); // I validate tokens
    std::string hash_password(const std::string& password, const std::string& salt); // I hash passwords
    std::string generate_salt();                            // I create password salts
    bool verify_password(const std::string& password, const std::string& hash, const std::string& salt); // I verify passwords
    bool check_rate_limit(const std::string& ip);          // I enforce rate limits
    void record_auth_attempt(const AuthAttempt& attempt);  // I log authentication attempts
    void record_security_event(const SecurityEvent& event); // I log security events
    void cleanup_expired_sessions();                       // I remove expired sessions
    void cleanup_old_attempts();                           // I remove old auth attempts
    bool is_ip_locked(const std::string& ip);              // I check IP lockout status
    void lock_ip(const std::string& ip);                   // I lock suspicious IPs
    std::vector<Permission> get_role_permissions(UserRole role); // I get default role permissions
    bool validate_username(const std::string& username);   // I validate username format
    bool validate_password_strength(const std::string& password); // I check password strength
    std::string get_geolocation(const std::string& ip);    // I get IP geolocation
    std::string base64_encode(const std::string& input);   // I base64 encode data
    std::string base64_decode(const std::string& input);   // I base64 decode data
    std::string hmac_sha256(const std::string& data, const std::string& key); // I compute HMAC-SHA256

public:
    /**
     * I'm creating the constructor to initialize the auth manager
     */
    AuthTokenManager();

    /**
     * I'm creating the destructor to clean up resources
     */
    virtual ~AuthTokenManager();

    /**
     * I'm creating the method to configure the authentication system
     * @param jwt_secret Secret key for JWT token signing
     * @param token_expiration Token lifetime in hours
     * @param max_failed_attempts Maximum failed attempts before lockout
     * @param lockout_duration Lockout duration in minutes
     * @return true if configuration succeeded
     */
    bool configure(const std::string& jwt_secret, int token_expiration, 
                  int max_failed_attempts, int lockout_duration);

    /**
     * I'm creating the method to authenticate a user with username/password
     * @param username User's username
     * @param password User's password
     * @param ip_address Client IP address
     * @param user_agent Client user agent
     * @return UserSession pointer if successful, nullptr if failed
     */
    std::unique_ptr<UserSession> authenticate_user(const std::string& username,
                                                   const std::string& password,
                                                   const std::string& ip_address,
                                                   const std::string& user_agent);

    /**
     * I'm creating the method to authenticate using a JWT token
     * @param token JWT token string
     * @param ip_address Client IP address
     * @return UserSession pointer if valid, nullptr if invalid
     */
    std::unique_ptr<UserSession> authenticate_token(const std::string& token,
                                                    const std::string& ip_address);

    /**
     * I'm creating the method to authenticate using an API key
     * @param api_key API key string
     * @param ip_address Client IP address
     * @return UserSession pointer if valid, nullptr if invalid
     */
    std::unique_ptr<UserSession> authenticate_api_key(const std::string& api_key,
                                                      const std::string& ip_address);

    /**
     * I'm creating the method to create a new user account
     * @param username Unique username
     * @param password User password
     * @param email User email address
     * @param role User role
     * @return true if user was created successfully
     */
    bool create_user(const std::string& username, const std::string& password,
                    const std::string& email, UserRole role);

    /**
     * I'm creating the method to delete a user account
     * @param username Username to delete
     * @return true if user was deleted successfully
     */
    bool delete_user(const std::string& username);

    /**
     * I'm creating the method to update user permissions
     * @param username Username to update
     * @param permissions New permission set
     * @return true if permissions were updated
     */
    bool update_user_permissions(const std::string& username,
                                const std::vector<Permission>& permissions);

    /**
     * I'm creating the method to change user password
     * @param username Username
     * @param old_password Current password
     * @param new_password New password
     * @return true if password was changed successfully
     */
    bool change_password(const std::string& username, const std::string& old_password,
                        const std::string& new_password);

    /**
     * I'm creating the method to validate a session
     * @param session_id Session identifier
     * @return UserSession pointer if valid, nullptr if invalid
     */
    std::unique_ptr<UserSession> validate_session(const std::string& session_id);

    /**
     * I'm creating the method to invalidate a session
     * @param session_id Session identifier to invalidate
     * @return true if session was invalidated
     */
    bool invalidate_session(const std::string& session_id);

    /**
     * I'm creating the method to refresh a JWT token
     * @param refresh_token Refresh token
     * @return New JWT token if successful, empty string if failed
     */
    std::string refresh_token(const std::string& refresh_token);

    /**
     * I'm creating the method to create an API key
     * @param user_id User who owns the key
     * @param name Descriptive name for the key
     * @param permissions Allowed permissions
     * @param expires_in_days Expiration in days (0 = no expiration)
     * @return API key string if created, empty string if failed
     */
    std::string create_api_key(const std::string& user_id, const std::string& name,
                              const std::vector<Permission>& permissions,
                              int expires_in_days = 0);

    /**
     * I'm creating the method to revoke an API key
     * @param key_id API key identifier
     * @return true if key was revoked
     */
    bool revoke_api_key(const std::string& key_id);

    /**
     * I'm creating the method to check user permissions
     * @param session User session
     * @param required_permission Permission to check
     * @return true if user has the permission
     */
    bool check_permission(const UserSession& session, Permission required_permission);

    /**
     * I'm creating the method to get user account info
     * @param username Username to query
     * @return UserAccount pointer if found, nullptr if not found
     */
    const UserAccount* get_user(const std::string& username) const;

    /**
     * I'm creating the method to list all users
     * @return Vector of usernames
     */
    std::vector<std::string> list_users() const;

    /**
     * I'm creating the method to get security events
     * @param since_timestamp Get events since this time
     * @param limit Maximum number of events
     * @return Vector of security events
     */
    std::vector<SecurityEvent> get_security_events(
        std::chrono::system_clock::time_point since_timestamp,
        int limit = 100) const;

    /**
     * I'm creating the method to get authentication statistics
     * @return JSON string with authentication metrics
     */
    std::string get_auth_statistics() const;

    /**
     * I'm creating the method to enable or disable rate limiting
     * @param enabled Whether to enable rate limiting
     */
    void set_rate_limiting(bool enabled) { rate_limiting_enabled_ = enabled; }

    /**
     * I'm creating the method to manually lock an IP address
     * @param ip_address IP to lock
     * @param duration_minutes Lockout duration
     */
    void manual_ip_lock(const std::string& ip_address, int duration_minutes);

    /**
     * I'm creating the method to unlock an IP address
     * @param ip_address IP to unlock
     */
    void unlock_ip(const std::string& ip_address);
};

} // namespace icy2

#endif // AUTH_TOKEN_H
