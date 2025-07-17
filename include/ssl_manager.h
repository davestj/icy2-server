/**
 * File: include/ssl_manager.h
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/include/ssl_manager.h
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this header file to define the SSL/TLS certificate management
 *          system for ICY2-SERVER. This handles certificate generation, validation,
 *          SSL context management, and secure connection establishment.
 * 
 * Reason: I need a comprehensive SSL management system that can generate self-signed
 *         certificates, integrate with Let's Encrypt/Certbot, manage certificate
 *         renewal, and provide secure streaming with proper cipher suites.
 *
 * Changelog:
 * 2025-07-16 - Initial SSL manager with OpenSSL integration
 * 2025-07-16 - Added certificate generation and validation
 * 2025-07-16 - Implemented SSL context management and configuration
 * 2025-07-16 - Added certificate renewal and monitoring
 * 2025-07-16 - Integrated OCSP stapling and security hardening
 *
 * Next Dev Feature: I plan to add Let's Encrypt integration and certificate transparency
 * Git Commit: feat: implement comprehensive SSL certificate management system
 *
 * TODO: Add Let's Encrypt ACME client, certificate transparency logging, HSM support
 */

#ifndef SSL_MANAGER_H
#define SSL_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <map>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

namespace icy2 {

/**
 * I'm defining SSL certificate types that I can manage
 * This helps me handle different certificate use cases appropriately
 */
enum class CertificateType {
    SELF_SIGNED,        // I generate self-signed certificates for development
    CA_SIGNED,          // I handle CA-signed certificates for production
    LETS_ENCRYPT,       // I manage Let's Encrypt certificates
    INTERMEDIATE_CA,    // I handle intermediate CA certificates
    ROOT_CA,            // I manage root CA certificates
    CLIENT_CERT,        // I handle client authentication certificates
    CODE_SIGNING        // I manage code signing certificates
};

/**
 * I'm defining certificate validation status
 * This tracks the health and validity of certificates
 */
enum class CertificateStatus {
    VALID,              // I've verified the certificate is valid
    EXPIRED,            // I've detected the certificate has expired
    EXPIRING_SOON,      // I've flagged the certificate expires within warning period
    INVALID,            // I've determined the certificate is invalid
    REVOKED,            // I've confirmed the certificate was revoked
    UNKNOWN,            // I haven't been able to determine certificate status
    PENDING_VALIDATION  // I'm currently validating the certificate
};

/**
 * I'm creating a structure for certificate information
 * This stores all relevant certificate metadata and details
 */
struct CertificateInfo {
    std::string certificate_path;           // I store the certificate file path
    std::string private_key_path;           // I store the private key file path
    std::string chain_path;                 // I store the certificate chain path
    CertificateType type;                   // I identify the certificate type
    CertificateStatus status;               // I track the certificate status
    std::string subject;                    // I store certificate subject DN
    std::string issuer;                     // I store certificate issuer DN
    std::string serial_number;              // I store certificate serial number
    std::chrono::system_clock::time_point valid_from;    // I track validity start
    std::chrono::system_clock::time_point valid_until;   // I track validity end
    std::vector<std::string> subject_alt_names;          // I store SAN entries
    std::string fingerprint_sha1;           // I calculate SHA1 fingerprint
    std::string fingerprint_sha256;         // I calculate SHA256 fingerprint
    std::string public_key_algorithm;       // I identify public key algorithm
    int key_size;                           // I store key size in bits
    std::string signature_algorithm;        // I identify signature algorithm
    bool is_ca_certificate;                 // I flag CA certificates
    bool has_private_key;                   // I flag if private key is available
    std::string ocsp_responder_url;         // I store OCSP responder URL
    std::string crl_distribution_point;     // I store CRL distribution point
    std::vector<std::string> key_usage;     // I store key usage extensions
    std::vector<std::string> extended_key_usage; // I store extended key usage
    std::chrono::system_clock::time_point last_validated; // I track last validation
    std::string validation_error;           // I store validation error details
};

/**
 * I'm creating a structure for SSL context configuration
 * This defines how SSL contexts should be configured
 */
struct SSLContextConfig {
    std::vector<std::string> protocols;     // I define allowed TLS protocols
    std::string cipher_suites;              // I specify allowed cipher suites
    std::string curve_list;                 // I define elliptic curves for ECDHE
    bool require_client_cert;               // I control client certificate requirements
    bool verify_client_cert;                // I control client certificate verification
    std::string ca_certificate_path;        // I specify CA certificate file
    std::string ca_certificate_dir;         // I specify CA certificate directory
    bool enable_ocsp_stapling;              // I control OCSP stapling
    std::string ocsp_responder_url;         // I specify OCSP responder URL
    int session_timeout;                    // I set SSL session timeout
    bool session_cache_enabled;             // I control SSL session caching
    int session_cache_size;                 // I set session cache size
    bool compression_enabled;               // I control SSL compression
    std::string dh_params_file;             // I specify DH parameters file
    bool enable_sct;                        // I control certificate transparency
    std::string sct_list_file;              // I specify SCT list file
    std::map<std::string, std::string> custom_options; // I allow custom SSL options
};

/**
 * I'm creating a structure for certificate generation parameters
 * This controls how I generate new certificates
 */
struct CertificateGenerationParams {
    CertificateType type;                   // I specify certificate type to generate
    int key_size;                           // I set RSA key size in bits
    std::string key_algorithm;              // I choose key algorithm (RSA, ECDSA)
    std::string curve_name;                 // I specify ECDSA curve name
    int validity_days;                      // I set certificate validity period
    std::string country;                    // I set country code (C)
    std::string state;                      // I set state/province (ST)
    std::string locality;                   // I set locality/city (L)
    std::string organization;               // I set organization (O)
    std::string organizational_unit;        // I set organizational unit (OU)
    std::string common_name;                // I set common name (CN)
    std::string email;                      // I set email address
    std::vector<std::string> subject_alt_names; // I add subject alternative names
    std::vector<std::string> key_usage;     // I define key usage extensions
    std::vector<std::string> extended_key_usage; // I define extended key usage
    bool is_ca_certificate;                 // I flag CA certificate generation
    int path_length_constraint;             // I set CA path length constraint
    std::string crl_distribution_point;     // I set CRL distribution point
    std::string ocsp_responder_url;         // I set OCSP responder URL
    std::string ca_certificate_path;        // I specify signing CA certificate
    std::string ca_private_key_path;        // I specify signing CA private key
};

/**
 * I'm creating a structure for certificate monitoring and alerts
 * This helps me track certificate health and send notifications
 */
struct CertificateMonitoring {
    std::string certificate_id;             // I assign unique certificate identifier
    std::string description;                // I store certificate description
    bool monitoring_enabled;                // I control monitoring for this certificate
    int expiry_warning_days;                // I set days before expiry to warn
    int expiry_critical_days;               // I set days before expiry for critical alert
    std::vector<std::string> notification_emails; // I store notification recipients
    std::string webhook_url;                // I specify webhook for notifications
    std::chrono::system_clock::time_point last_check; // I track last monitoring check
    std::chrono::system_clock::time_point last_notification; // I track last notification sent
    std::string last_status_message;        // I store last status message
    bool auto_renewal_enabled;              // I control automatic renewal
    std::string renewal_command;            // I store renewal command to execute
    int renewal_retry_attempts;             // I set retry attempts for renewal
    std::chrono::system_clock::time_point next_renewal_check; // I schedule next renewal check
};

/**
 * I'm defining the main SSL manager class
 * This orchestrates all SSL certificate management operations
 */
class SSLManager {
private:
    // I'm defining SSL contexts and configuration
    SSL_CTX* ssl_context_;                  // I manage the main SSL context
    SSL_CTX* client_ssl_context_;           // I manage client SSL context
    std::mutex ssl_context_mutex_;          // I protect SSL context access
    SSLContextConfig context_config_;       // I store SSL context configuration

    // I'm defining certificate storage and tracking
    std::map<std::string, CertificateInfo> certificates_; // I store certificate information
    std::map<std::string, CertificateMonitoring> monitoring_; // I track certificate monitoring
    std::mutex certificates_mutex_;         // I protect certificate data
    std::mutex monitoring_mutex_;           // I protect monitoring data

    // I'm defining certificate validation and caching
    std::map<std::string, std::pair<CertificateStatus, std::chrono::steady_clock::time_point>> validation_cache_; // I cache validation results
    std::mutex validation_cache_mutex_;     // I protect validation cache
    int validation_cache_ttl_minutes_;      // I set cache TTL

    // I'm defining monitoring and renewal
    std::chrono::steady_clock::time_point last_monitoring_run_; // I track last monitoring run
    std::function<void(const std::string&, const std::string&)> notification_callback_; // I call this for notifications
    bool auto_renewal_enabled_;             // I control automatic renewal globally
    std::string renewal_script_path_;       // I store path to renewal script

    // I'm defining helper methods
    bool initialize_openssl();              // I initialize OpenSSL library
    void cleanup_openssl();                 // I clean up OpenSSL resources
    bool load_certificate_file(const std::string& cert_path, X509** cert); // I load X509 certificates
    bool load_private_key_file(const std::string& key_path, EVP_PKEY** key); // I load private keys
    bool validate_certificate_chain(X509* cert, STACK_OF(X509)* chain); // I validate certificate chains
    CertificateStatus check_certificate_status(const CertificateInfo& cert_info); // I check certificate status
    bool extract_certificate_info(X509* cert, CertificateInfo& info); // I extract certificate metadata
    std::string calculate_fingerprint(X509* cert, const EVP_MD* md); // I calculate certificate fingerprints
    bool configure_ssl_context(SSL_CTX* ctx, const SSLContextConfig& config); // I configure SSL contexts
    bool setup_cipher_suites(SSL_CTX* ctx, const std::string& cipher_suites); // I set cipher suites
    bool setup_protocols(SSL_CTX* ctx, const std::vector<std::string>& protocols); // I set TLS protocols
    bool setup_client_verification(SSL_CTX* ctx, const SSLContextConfig& config); // I set client verification
    bool setup_ocsp_stapling(SSL_CTX* ctx, const std::string& ocsp_url); // I set OCSP stapling
    bool verify_certificate_chain_callback(int preverify_ok, X509_STORE_CTX* ctx); // I handle certificate verification
    void log_ssl_error(const std::string& operation); // I log SSL errors
    void send_certificate_notification(const std::string& cert_id, const std::string& message); // I send notifications
    bool execute_renewal_command(const std::string& command); // I execute renewal commands
    std::string format_certificate_subject(X509_NAME* name); // I format certificate subjects
    std::vector<std::string> extract_subject_alt_names(X509* cert); // I extract SAN entries

public:
    /**
     * I'm creating the constructor to initialize the SSL manager
     */
    SSLManager();

    /**
     * I'm creating the destructor to clean up SSL resources
     */
    virtual ~SSLManager();

    /**
     * I'm creating the method to initialize SSL with configuration
     * @param config SSL context configuration
     * @return true if initialization succeeded
     */
    bool initialize(const SSLContextConfig& config);

    /**
     * I'm creating the method to generate a self-signed certificate
     * @param params Certificate generation parameters
     * @param cert_path Output certificate file path
     * @param key_path Output private key file path
     * @return true if certificate was generated successfully
     */
    bool generate_self_signed_certificate(const CertificateGenerationParams& params,
                                         const std::string& cert_path,
                                         const std::string& key_path);

    /**
     * I'm creating the method to load an existing certificate
     * @param cert_id Unique certificate identifier
     * @param cert_path Certificate file path
     * @param key_path Private key file path
     * @param chain_path Certificate chain file path (optional)
     * @return true if certificate was loaded successfully
     */
    bool load_certificate(const std::string& cert_id,
                         const std::string& cert_path,
                         const std::string& key_path,
                         const std::string& chain_path = "");

    /**
     * I'm creating the method to validate a certificate
     * @param cert_id Certificate identifier to validate
     * @param force_revalidate Whether to bypass cache and revalidate
     * @return Certificate validation status
     */
    CertificateStatus validate_certificate(const std::string& cert_id,
                                          bool force_revalidate = false);

    /**
     * I'm creating the method to get certificate information
     * @param cert_id Certificate identifier
     * @return Certificate information structure
     */
    const CertificateInfo* get_certificate_info(const std::string& cert_id) const;

    /**
     * I'm creating the method to list all managed certificates
     * @return Vector of certificate identifiers
     */
    std::vector<std::string> list_certificates() const;

    /**
     * I'm creating the method to remove a certificate from management
     * @param cert_id Certificate identifier to remove
     * @return true if certificate was removed
     */
    bool remove_certificate(const std::string& cert_id);

    /**
     * I'm creating the method to create SSL connection
     * @param socket_fd Socket file descriptor
     * @param is_server Whether this is a server-side connection
     * @return SSL pointer if successful, nullptr if failed
     */
    SSL* create_ssl_connection(int socket_fd, bool is_server = true);

    /**
     * I'm creating the method to destroy SSL connection
     * @param ssl SSL connection pointer
     */
    void destroy_ssl_connection(SSL* ssl);

    /**
     * I'm creating the method to get SSL context for manual use
     * @param is_server Whether to get server or client context
     * @return SSL_CTX pointer
     */
    SSL_CTX* get_ssl_context(bool is_server = true);

    /**
     * I'm creating the method to set up certificate monitoring
     * @param cert_id Certificate identifier
     * @param monitoring Monitoring configuration
     * @return true if monitoring was set up successfully
     */
    bool setup_certificate_monitoring(const std::string& cert_id,
                                     const CertificateMonitoring& monitoring);

    /**
     * I'm creating the method to run certificate monitoring checks
     * @return Number of certificates that require attention
     */
    int run_certificate_monitoring();

    /**
     * I'm creating the method to renew a certificate
     * @param cert_id Certificate identifier to renew
     * @param force_renewal Whether to force renewal even if not needed
     * @return true if renewal was successful
     */
    bool renew_certificate(const std::string& cert_id, bool force_renewal = false);

    /**
     * I'm creating the method to set notification callback
     * @param callback Function to call for certificate notifications
     */
    void set_notification_callback(std::function<void(const std::string&, const std::string&)> callback);

    /**
     * I'm creating the method to enable or disable auto-renewal
     * @param enabled Whether to enable automatic renewal
     * @param script_path Path to renewal script
     */
    void set_auto_renewal(bool enabled, const std::string& script_path = "");

    /**
     * I'm creating the method to update SSL context configuration
     * @param config New SSL context configuration
     * @return true if configuration was updated successfully
     */
    bool update_ssl_configuration(const SSLContextConfig& config);

    /**
     * I'm creating the method to verify client certificate
     * @param ssl SSL connection with client certificate
     * @return true if client certificate is valid
     */
    bool verify_client_certificate(SSL* ssl);

    /**
     * I'm creating the method to get certificate expiry information
     * @return Map of certificate IDs to days until expiry
     */
    std::map<std::string, int> get_certificate_expiry_info() const;

    /**
     * I'm creating the method to export certificate information as JSON
     * @param cert_id Certificate identifier (empty for all certificates)
     * @return JSON string with certificate information
     */
    std::string export_certificate_info_json(const std::string& cert_id = "") const;

    /**
     * I'm creating the method to generate certificate signing request
     * @param params Certificate generation parameters
     * @param csr_path Output CSR file path
     * @param key_path Output private key file path
     * @return true if CSR was generated successfully
     */
    bool generate_certificate_signing_request(const CertificateGenerationParams& params,
                                             const std::string& csr_path,
                                             const std::string& key_path);

    /**
     * I'm creating the method to install certificate from CSR response
     * @param cert_id Certificate identifier
     * @param cert_data Certificate data from CA
     * @param key_path Existing private key file path
     * @param chain_data Certificate chain data (optional)
     * @return true if certificate was installed successfully
     */
    bool install_certificate_from_response(const std::string& cert_id,
                                          const std::string& cert_data,
                                          const std::string& key_path,
                                          const std::string& chain_data = "");

    /**
     * I'm creating the method to get SSL statistics
     * @return JSON string with SSL connection and certificate statistics
     */
    std::string get_ssl_statistics() const;
};

} // namespace icy2

#endif // SSL_MANAGER_H
