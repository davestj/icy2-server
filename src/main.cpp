/**
 * File: src/main.cpp
 * Path: /var/www/mcaster1.com/DNAS/icy2-server/src/main.cpp
 * Author: davestj@gmail.com (David St. John)
 * Created: 2025-07-16
 * Purpose: I created this main entry point for the ICY2-SERVER application that handles
 *          command line arguments, initializes the server, and manages the application
 *          lifecycle. This is the primary executable entry point.
 * 
 * Reason: I need a robust main function that can handle various startup modes,
 *         command line overrides, signal handling, and graceful shutdown while
 *         providing comprehensive error reporting and debugging capabilities.
 *
 * Changelog:
 * 2025-07-16 - Initial main application with command line argument parsing
 * 2025-07-16 - Added signal handling for graceful shutdown
 * 2025-07-16 - Implemented configuration validation and test mode
 * 2025-07-16 - Added SSL certificate generation capability
 * 2025-07-16 - Integrated comprehensive error handling and logging
 *
 * Next Dev Feature: I plan to add daemon mode, service integration, and clustering
 * Git Commit: feat: implement main application entry point with full CLI support
 *
 * TODO: Add Windows service support, systemd integration, configuration wizard
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <csignal>
#include <cstdlib>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>

#include "server.h"
#include "config_parser.h"
#include "helper.h"

using namespace icy2;

// I'm defining global variables for signal handling
static std::unique_ptr<ICY2Server> g_server;
static std::atomic<bool> g_shutdown_requested{false};
static std::unique_ptr<APIHelper> g_helper;

/**
 * I'm creating a structure to hold command line options
 * This organizes all the possible command line arguments
 */
struct CommandLineOptions {
    std::string config_file = "/etc/icy2-server/mcaster1.yaml";  // I set default config path
    std::string bind_ip;                                          // I override bind IP
    uint16_t port = 0;                                           // I override port number
    int debug_level = 1;                                         // I set debug verbosity
    bool test_mode = false;                                      // I flag test mode
    bool generate_ssl = false;                                   // I flag SSL generation
    bool daemon_mode = false;                                    // I flag daemon mode
    bool show_help = false;                                      // I flag help display
    bool show_version = false;                                   // I flag version display
    bool validate_config = false;                                // I flag config validation
    std::string ssl_cert_path;                                   // I override SSL cert path
    std::string ssl_key_path;                                    // I override SSL key path
    std::string log_level;                                       // I override log level
    bool foreground = false;                                     // I force foreground mode
};

/**
 * I'm creating the signal handler for graceful shutdown
 * This ensures the server stops cleanly when receiving signals
 */
void signal_handler(int signal) {
    const char* signal_name = "UNKNOWN";
    
    switch (signal) {
        case SIGINT:
            signal_name = "SIGINT";
            break;
        case SIGTERM:
            signal_name = "SIGTERM";
            break;
        case SIGHUP:
            signal_name = "SIGHUP";
            // I handle configuration reload for SIGHUP
            if (g_server && g_server->is_running()) {
                std::cout << "\nI received SIGHUP, reloading configuration..." << std::endl;
                if (g_server->reload_configuration()) {
                    std::cout << "I successfully reloaded the configuration." << std::endl;
                } else {
                    std::cerr << "I failed to reload the configuration." << std::endl;
                }
                return;
            }
            break;
        case SIGUSR1:
            // I handle statistics dump for SIGUSR1
            if (g_server && g_server->is_running()) {
                std::cout << "\nI received SIGUSR1, dumping statistics..." << std::endl;
                std::cout << g_server->get_server_info() << std::endl;
                return;
            }
            break;
        default:
            break;
    }
    
    if (!g_shutdown_requested.load()) {
        std::cout << "\nI received signal " << signal_name << " (" << signal << "), initiating graceful shutdown..." << std::endl;
        g_shutdown_requested.store(true);
        
        if (g_server) {
            g_server->stop();
        }
    }
}

/**
 * I'm creating the function to setup signal handlers
 * This registers handlers for various signals
 */
void setup_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    // I'm registering handlers for graceful shutdown signals
    sigaction(SIGINT, &sa, nullptr);   // I handle Ctrl+C
    sigaction(SIGTERM, &sa, nullptr);  // I handle termination requests
    sigaction(SIGHUP, &sa, nullptr);   // I handle configuration reload
    sigaction(SIGUSR1, &sa, nullptr);  // I handle statistics dump
    
    // I'm ignoring SIGPIPE to handle broken connections gracefully
    signal(SIGPIPE, SIG_IGN);
}

/**
 * I'm creating the function to display usage information
 * This shows users how to use the ICY2-SERVER application
 */
void show_usage(const char* program_name) {
    std::cout << "ICY2-SERVER - Digital Network Audio Server v" << ICY2_VERSION_STRING << std::endl;
    std::cout << "Author: davestj@gmail.com (David St. John)" << std::endl;
    std::cout << "Website: https://mcaster1.com" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cout << std::endl;
    std::cout << "OPTIONS:" << std::endl;
    std::cout << "  -c, --config=FILE        Configuration file path" << std::endl;
    std::cout << "                           Default: /etc/icy2-server/mcaster1.yaml" << std::endl;
    std::cout << "  -i, --ip=ADDRESS         Bind IP address (overrides config)" << std::endl;
    std::cout << "  -p, --port=PORT          HTTP port number (overrides config)" << std::endl;
    std::cout << "  -d, --debug=LEVEL        Debug level 1-4 (1=info, 4=verbose)" << std::endl;
    std::cout << "  -t, --test-mode          Validate configuration and exit" << std::endl;
    std::cout << "  -g, --generate-ssl       Generate self-signed SSL certificates" << std::endl;
    std::cout << "  -D, --daemon             Run as daemon process" << std::endl;
    std::cout << "  -f, --foreground         Force foreground mode (disable daemon)" << std::endl;
    std::cout << "  -v, --validate           Validate configuration file only" << std::endl;
    std::cout << "  -V, --version            Show version information" << std::endl;
    std::cout << "  -h, --help               Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "SSL OPTIONS:" << std::endl;
    std::cout << "  --ssl-cert=FILE          SSL certificate file path" << std::endl;
    std::cout << "  --ssl-key=FILE           SSL private key file path" << std::endl;
    std::cout << std::endl;
    std::cout << "LOGGING OPTIONS:" << std::endl;
    std::cout << "  --log-level=LEVEL        Log level (DEBUG, INFO, WARNING, ERROR)" << std::endl;
    std::cout << std::endl;
    std::cout << "EXAMPLES:" << std::endl;
    std::cout << "  # I start the server with default configuration" << std::endl;
    std::cout << "  " << program_name << std::endl;
    std::cout << std::endl;
    std::cout << "  # I start with custom IP and port" << std::endl;
    std::cout << "  " << program_name << " --ip=0.0.0.0 --port=5656" << std::endl;
    std::cout << std::endl;
    std::cout << "  # I validate configuration without starting" << std::endl;
    std::cout << "  " << program_name << " --test-mode --config=custom.yaml" << std::endl;
    std::cout << std::endl;
    std::cout << "  # I generate SSL certificates" << std::endl;
    std::cout << "  " << program_name << " --generate-ssl" << std::endl;
    std::cout << std::endl;
    std::cout << "  # I run with maximum debugging" << std::endl;
    std::cout << "  " << program_name << " --debug=4 --foreground" << std::endl;
    std::cout << std::endl;
    std::cout << "SIGNALS:" << std::endl;
    std::cout << "  SIGINT/SIGTERM          Graceful shutdown" << std::endl;
    std::cout << "  SIGHUP                  Reload configuration" << std::endl;
    std::cout << "  SIGUSR1                 Dump statistics to stdout" << std::endl;
    std::cout << std::endl;
    std::cout << "For more information, visit: https://mcaster1.com/docs/icy2-server" << std::endl;
}

/**
 * I'm creating the function to display version information
 * This shows detailed version and build information
 */
void show_version() {
    std::cout << "ICY2-SERVER v" << ICY2_VERSION_STRING << std::endl;
    std::cout << "Digital Network Audio Server - SHOUTcast/Icecast Clone with ICY 2.0+ Protocol" << std::endl;
    std::cout << std::endl;
    std::cout << "Version Information:" << std::endl;
    std::cout << "  Version:        " << ICY2_VERSION_STRING << std::endl;
    std::cout << "  Build Date:     " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "  Compiler:       " << __VERSION__ << std::endl;
    std::cout << "  Architecture:   " << 
#ifdef __x86_64__
        "x86_64"
#elif defined(__i386__)
        "i386"
#elif defined(__aarch64__)
        "aarch64"
#elif defined(__arm__)
        "arm"
#else
        "unknown"
#endif
        << std::endl;
    std::cout << "  Platform:       " <<
#ifdef __linux__
        "Linux"
#elif defined(_WIN32)
        "Windows"
#elif defined(__APPLE__)
        "macOS"
#else
        "Unknown"
#endif
        << std::endl;
    std::cout << std::endl;
    std::cout << "Features:" << std::endl;
    std::cout << "  SSL/TLS:        Enabled (OpenSSL)" << std::endl;
    std::cout << "  PHP-FPM:        Enabled (FastCGI)" << std::endl;
    std::cout << "  ICY 1.x:        Enabled (Legacy compatibility)" << std::endl;
    std::cout << "  ICY 2.0+:       Enabled (Full specification)" << std::endl;
    std::cout << "  YAML Config:    Enabled (yaml-cpp)" << std::endl;
    std::cout << "  Authentication: Enabled (JWT tokens)" << std::endl;
    std::cout << std::endl;
    std::cout << "Author:         David St. John (davestj@gmail.com)" << std::endl;
    std::cout << "Website:        https://mcaster1.com" << std::endl;
    std::cout << "License:        MIT License" << std::endl;
    std::cout << "Repository:     https://github.com/davestj/icy2-server" << std::endl;
}

/**
 * I'm creating the function to parse command line arguments
 * This processes all command line options and flags
 */
bool parse_command_line(int argc, char* argv[], CommandLineOptions& options) {
    static struct option long_options[] = {
        {"config",        required_argument, 0, 'c'},
        {"ip",            required_argument, 0, 'i'},
        {"port",          required_argument, 0, 'p'},
        {"debug",         required_argument, 0, 'd'},
        {"test-mode",     no_argument,       0, 't'},
        {"generate-ssl",  no_argument,       0, 'g'},
        {"daemon",        no_argument,       0, 'D'},
        {"foreground",    no_argument,       0, 'f'},
        {"validate",      no_argument,       0, 'v'},
        {"version",       no_argument,       0, 'V'},
        {"help",          no_argument,       0, 'h'},
        {"ssl-cert",      required_argument, 0, 1001},
        {"ssl-key",       required_argument, 0, 1002},
        {"log-level",     required_argument, 0, 1003},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "c:i:p:d:tgDfvVh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                options.config_file = optarg;
                break;
            case 'i':
                options.bind_ip = optarg;
                break;
            case 'p':
                options.port = static_cast<uint16_t>(std::stoi(optarg));
                break;
            case 'd':
                options.debug_level = std::stoi(optarg);
                if (options.debug_level < 1 || options.debug_level > 4) {
                    std::cerr << "Error: Debug level must be between 1 and 4" << std::endl;
                    return false;
                }
                break;
            case 't':
                options.test_mode = true;
                break;
            case 'g':
                options.generate_ssl = true;
                break;
            case 'D':
                options.daemon_mode = true;
                break;
            case 'f':
                options.foreground = true;
                break;
            case 'v':
                options.validate_config = true;
                break;
            case 'V':
                options.show_version = true;
                break;
            case 'h':
                options.show_help = true;
                break;
            case 1001:
                options.ssl_cert_path = optarg;
                break;
            case 1002:
                options.ssl_key_path = optarg;
                break;
            case 1003:
                options.log_level = optarg;
                break;
            case '?':
                // I handle invalid options
                return false;
            default:
                std::cerr << "Error: Unknown option" << std::endl;
                return false;
        }
    }
    
    // I validate option combinations
    if (options.daemon_mode && options.foreground) {
        std::cerr << "Error: Cannot specify both --daemon and --foreground" << std::endl;
        return false;
    }
    
    if (options.port > 0 && (options.port < 1024 && geteuid() != 0)) {
        std::cerr << "Warning: Port " << options.port << " requires root privileges" << std::endl;
    }
    
    return true;
}

/**
 * I'm creating the function to validate file permissions and paths
 * This ensures the server has access to required files
 */
bool validate_file_access(const CommandLineOptions& options) {
    // I check configuration file access
    if (!options.config_file.empty()) {
        struct stat st;
        if (stat(options.config_file.c_str(), &st) != 0) {
            std::cerr << "Error: Cannot access configuration file: " << options.config_file << std::endl;
            return false;
        }
        if (!(st.st_mode & S_IRUSR)) {
            std::cerr << "Error: No read permission for configuration file: " << options.config_file << std::endl;
            return false;
        }
    }
    
    // I check SSL certificate files if specified
    if (!options.ssl_cert_path.empty()) {
        struct stat st;
        if (stat(options.ssl_cert_path.c_str(), &st) != 0) {
            std::cerr << "Error: Cannot access SSL certificate file: " << options.ssl_cert_path << std::endl;
            return false;
        }
    }
    
    if (!options.ssl_key_path.empty()) {
        struct stat st;
        if (stat(options.ssl_key_path.c_str(), &st) != 0) {
            std::cerr << "Error: Cannot access SSL private key file: " << options.ssl_key_path << std::endl;
            return false;
        }
    }
    
    return true;
}

/**
 * I'm creating the function to run in daemon mode
 * This detaches the process from the terminal
 */
bool daemonize() {
    pid_t pid = fork();
    
    if (pid < 0) {
        std::cerr << "Error: Failed to fork process" << std::endl;
        return false;
    }
    
    if (pid > 0) {
        // I'm the parent process, exit
        exit(EXIT_SUCCESS);
    }
    
    // I'm the child process, continue as daemon
    if (setsid() < 0) {
        std::cerr << "Error: Failed to create new session" << std::endl;
        return false;
    }
    
    // I fork again to prevent acquiring a controlling terminal
    pid = fork();
    if (pid < 0) {
        std::cerr << "Error: Failed to fork second time" << std::endl;
        return false;
    }
    
    if (pid > 0) {
        // I'm the first child, exit
        exit(EXIT_SUCCESS);
    }
    
    // I change to root directory
    if (chdir("/") < 0) {
        std::cerr << "Error: Failed to change to root directory" << std::endl;
        return false;
    }
    
    // I set file creation mask
    umask(0);
    
    // I close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    return true;
}

/**
 * I'm creating the main application entry point
 * This is where the ICY2-SERVER application starts
 */
int main(int argc, char* argv[]) {
    CommandLineOptions options;
    
    // I parse command line arguments first
    if (!parse_command_line(argc, argv, options)) {
        show_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // I handle help and version requests immediately
    if (options.show_help) {
        show_usage(argv[0]);
        return EXIT_SUCCESS;
    }
    
    if (options.show_version) {
        show_version();
        return EXIT_SUCCESS;
    }
    
    // I initialize the API helper for logging and utilities
    g_helper = std::make_unique<APIHelper>();
    if (!g_helper->initialize("icy2-dnas-001", "1.0", 
                             static_cast<LogLevel>(options.debug_level - 1))) {
        std::cerr << "Error: Failed to initialize API helper" << std::endl;
        return EXIT_FAILURE;
    }
    
    // I log startup information
    g_helper->log_message(LogLevel::INFO, "ICY2-SERVER v" + std::string(ICY2_VERSION_STRING) + " starting up");
    g_helper->log_message(LogLevel::DEBUG, "Command line parsed successfully");
    
    // I validate file access before proceeding
    if (!validate_file_access(options)) {
        return EXIT_FAILURE;
    }
    
    // I handle SSL certificate generation if requested
    if (options.generate_ssl) {
        g_helper->log_message(LogLevel::INFO, "Generating SSL certificates...");
        
        ICY2Server temp_server;
        if (temp_server.generate_ssl_certificates()) {
            std::cout << "I successfully generated SSL certificates" << std::endl;
            g_helper->log_message(LogLevel::INFO, "SSL certificates generated successfully");
            return EXIT_SUCCESS;
        } else {
            std::cerr << "Error: Failed to generate SSL certificates" << std::endl;
            g_helper->log_message(LogLevel::ERROR, "Failed to generate SSL certificates");
            return EXIT_FAILURE;
        }
    }
    
    // I handle configuration validation if requested
    if (options.validate_config) {
        g_helper->log_message(LogLevel::INFO, "Validating configuration file: " + options.config_file);
        
        ConfigParser config_parser;
        if (config_parser.load_config(options.config_file) && config_parser.validate_config()) {
            std::cout << "I validated the configuration successfully" << std::endl;
            g_helper->log_message(LogLevel::INFO, "Configuration validation passed");
            return EXIT_SUCCESS;
        } else {
            std::cerr << "Error: Configuration validation failed" << std::endl;
            auto errors = config_parser.get_validation_errors();
            for (const auto& error : errors) {
                std::cerr << "  " << error << std::endl;
                g_helper->log_message(LogLevel::ERROR, "Config error: " + error);
            }
            return EXIT_FAILURE;
        }
    }
    
    // I setup signal handlers for graceful shutdown
    setup_signal_handlers();
    g_helper->log_message(LogLevel::DEBUG, "Signal handlers configured");
    
    // I daemonize if requested and not in foreground mode
    if (options.daemon_mode && !options.foreground) {
        g_helper->log_message(LogLevel::INFO, "Entering daemon mode");
        if (!daemonize()) {
            return EXIT_FAILURE;
        }
    }
    
    // I create and initialize the server
    g_server = std::make_unique<ICY2Server>();
    
    if (!g_server->initialize(options.config_file)) {
        std::cerr << "Error: Failed to initialize server" << std::endl;
        g_helper->log_message(LogLevel::ERROR, "Server initialization failed");
        return EXIT_FAILURE;
    }
    
    g_helper->log_message(LogLevel::INFO, "Server initialized successfully");
    
    // I start the server with command line overrides
    if (!g_server->start(options.bind_ip, options.port, options.debug_level, options.test_mode)) {
        std::cerr << "Error: Failed to start server" << std::endl;
        g_helper->log_message(LogLevel::ERROR, "Server startup failed");
        return EXIT_FAILURE;
    }
    
    if (options.test_mode) {
        std::cout << "I completed test mode successfully" << std::endl;
        g_helper->log_message(LogLevel::INFO, "Test mode completed successfully");
        g_server->stop();
        return EXIT_SUCCESS;
    }
    
    std::cout << "I started ICY2-SERVER successfully" << std::endl;
    std::cout << "Server is listening and ready for connections" << std::endl;
    std::cout << "Press Ctrl+C to stop the server gracefully" << std::endl;
    
    g_helper->log_message(LogLevel::INFO, "Server started successfully and accepting connections");
    
    // I wait for shutdown signal
    while (g_server->is_running() && !g_shutdown_requested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // I perform graceful shutdown
    g_helper->log_message(LogLevel::INFO, "Initiating graceful shutdown");
    std::cout << "I'm shutting down the server gracefully..." << std::endl;
    
    g_server->stop();
    g_server.reset();
    
    std::cout << "I shut down ICY2-SERVER successfully" << std::endl;
    g_helper->log_message(LogLevel::INFO, "Server shutdown completed successfully");
    
    return EXIT_SUCCESS;
}
