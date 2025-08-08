# File: src/Makefile.am
# Path: /var/www/mcaster1.com/DNAS/icy2-server/src/Makefile.am
# Author: davestj@gmail.com (David St. John)
# Created: 2025-07-16
# Purpose: I created this Makefile.am to define the build rules for all ICY2-SERVER
#          source files, including the main executable, static library, and shared
#          library components for the complete build system.
# 
# Reason: I need a comprehensive automake configuration that handles all source
#         compilation, library creation, installation, and dependency management
#         while supporting both development and production builds.
#
# Changelog:
# 2025-07-16 - Initial Makefile.am with complete source compilation
# 2025-07-16 - Added static and shared library targets
# 2025-07-16 - Implemented installation rules and header dependencies
# 2025-07-16 - Added debug and release build configurations
# 2025-07-16 - Integrated external library dependencies and linking
#
# Next Dev Feature: I plan to add Windows build support and cross-compilation
# Git Commit: feat: implement comprehensive automake build system for all components
#
# TODO: Add Windows support, cross-compilation, packaging rules, test targets

# I'm setting the include directory path for headers
AM_CPPFLAGS = -I$(top_srcdir)/include

# I'm defining compiler flags for different build types
if DEBUG
AM_CXXFLAGS = -std=c++17 -Wall -Wextra -g -O0 -DDEBUG -DICY2_DEBUG
AM_CFLAGS = -Wall -Wextra -g -O0 -DDEBUG
else
AM_CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -DNDEBUG
AM_CFLAGS = -Wall -Wextra -O2 -DNDEBUG
endif

# I'm adding SSL support flags when enabled
if SSL
AM_CPPFLAGS += -DICY2_SSL_ENABLED
endif

# I'm adding PHP-FPM support flags when enabled
if PHP_FMP
AM_CPPFLAGS += -DICY2_PHP_ENABLED
endif

# I'm defining the main executable
bin_PROGRAMS = icy2-server

# I'm listing all source files for the main executable
icy2_server_SOURCES = \
    main.cpp \
    server.cpp \
    icy_handler.cpp \
    config_parser.cpp \
    auth_token.cpp \
    php_handler.cpp \
    helper.cpp

if SSL
icy2_server_SOURCES += ssl_manager.cpp
endif

# I'm defining header dependencies for proper rebuilding
noinst_HEADERS = \
    $(top_srcdir)/include/server.h \
    $(top_srcdir)/include/icy_handler.h \
    $(top_srcdir)/include/config_parser.h \
    $(top_srcdir)/include/auth_token.h \
    $(top_srcdir)/include/ssl_manager.h \
    $(top_srcdir)/include/php_handler.h \
    $(top_srcdir)/include/helper.h

# I'm defining external library dependencies
icy2_server_LDADD = $(YAML_CPP_LIBS) -lfcgi -lpthread -ldl
if SSL
icy2_server_LDADD += $(OPENSSL_LIBS)
endif

# I'm setting up library installation
lib_LIBRARIES = libicy2-server.a
if SHARED_LIBS
lib_LTLIBRARIES = libicy2-server.la
endif

# I'm defining source files for the static library (excluding main.cpp)
libicy2_server_a_SOURCES = \
    server.cpp \
    icy_handler.cpp \
    config_parser.cpp \
    auth_token.cpp \
    php_handler.cpp \
    helper.cpp

if SSL
libicy2_server_a_SOURCES += ssl_manager.cpp
endif

# I'm setting library-specific compiler flags
libicy2_server_a_CXXFLAGS = $(AM_CXXFLAGS) -fPIC

# I'm defining shared library configuration
if SHARED_LIBS
libicy2_server_la_SOURCES = $(libicy2_server_a_SOURCES)
libicy2_server_la_CXXFLAGS = $(AM_CXXFLAGS) -fPIC
libicy2_server_la_LDFLAGS = -version-info 1:1:0 -shared
libicy2_server_la_LIBADD = $(YAML_CPP_LIBS) -lfcgi -lpthread -ldl
if SSL
libicy2_server_la_LIBADD += $(OPENSSL_LIBS)
endif
endif

# I'm defining header installation for the public API
include_HEADERS = $(top_srcdir)/include/icy2_server.h

# I'm creating custom targets for development tasks
.PHONY: lib shared debug release clean-local install-lib uninstall-lib

# I'm defining the lib target for convenience
lib: libicy2-server.a

# I'm defining the shared target for shared library
if SHARED_LIBS
shared: libicy2-server.la
else
shared:
	@echo "Shared libraries not enabled in configuration"
endif

# I'm defining debug build target
debug:
	$(MAKE) AM_CXXFLAGS="$(AM_CXXFLAGS) -DDEBUG -g -O0" AM_CFLAGS="$(AM_CFLAGS) -DDEBUG -g -O0"

# I'm defining release build target
release:
	$(MAKE) AM_CXXFLAGS="$(AM_CXXFLAGS) -DNDEBUG -O2" AM_CFLAGS="$(AM_CFLAGS) -DNDEBUG -O2"

# I'm defining installation targets for libraries
install-lib: libicy2-server.a
	$(INSTALL) -d $(DESTDIR)$(libdir)
	$(INSTALL) -m 644 libicy2-server.a $(DESTDIR)$(libdir)/
if SHARED_LIBS
	$(INSTALL) -m 755 .libs/libicy2-server.so.1.1.0 $(DESTDIR)$(libdir)/
	cd $(DESTDIR)$(libdir) && $(LN_S) libicy2-server.so.1.1.0 libicy2-server.so.1
	cd $(DESTDIR)$(libdir) && $(LN_S) libicy2-server.so.1.1.0 libicy2-server.so
endif
	$(INSTALL) -d $(DESTDIR)$(includedir)
	$(INSTALL) -m 644 $(top_srcdir)/include/icy2_server.h $(DESTDIR)$(includedir)/

# I'm defining uninstallation targets
uninstall-lib:
	rm -f $(DESTDIR)$(libdir)/libicy2-server.a
if SHARED_LIBS
	rm -f $(DESTDIR)$(libdir)/libicy2-server.so*
endif
	rm -f $(DESTDIR)$(includedir)/icy2_server.h

# I'm defining custom clean targets
clean-local:
	rm -f *.gcda *.gcno *.gcov
	rm -f core core.*
	rm -f *.log *.tmp
	rm -rf .libs

# I'm defining distribution rules for packaging
EXTRA_DIST = \
    $(top_srcdir)/config/mcaster1.yaml \
    $(top_srcdir)/README.md \
    $(top_srcdir)/LICENSE.md \
    $(top_srcdir)/bootstrap.sh \
    $(top_srcdir)/.github/workflows/dev.yaml

# I'm defining test targets (placeholder for future implementation)
check-local:
	@echo "I'm running basic functionality tests..."
	./icy2-server --test-mode
	@echo "Basic tests completed successfully"

# I'm defining memory leak checking with valgrind
memcheck: icy2-server
	@echo "I'm running memory leak detection..."
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
		--log-file=valgrind.log ./icy2-server --test-mode
	@echo "Memory check completed, see valgrind.log for results"

# I'm defining code coverage analysis
if DEBUG
coverage: clean all check
	@echo "I'm generating code coverage report..."
	gcov $(libicy2_server_a_SOURCES)
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage-report
	@echo "Coverage report generated in coverage-report/"
endif

# I'm defining static analysis with cppcheck
static-analysis:
	@echo "I'm running static code analysis..."
	cppcheck --enable=all --std=c++17 --suppress=missingIncludeSystem \
		--xml --xml-version=2 $(icy2_server_SOURCES) 2> cppcheck.xml
	@echo "Static analysis completed, see cppcheck.xml for results"

# I'm defining formatting check and correction
format-check:
	@echo "I'm checking code formatting..."
	clang-format --dry-run --Werror $(icy2_server_SOURCES) $(noinst_HEADERS)

format-fix:
	@echo "I'm fixing code formatting..."
	clang-format -i $(icy2_server_SOURCES) $(noinst_HEADERS)

# I'm defining dependency generation for proper rebuilding
depend: $(icy2_server_SOURCES)
	@echo "I'm generating dependency information..."
	$(CXX) $(AM_CPPFLAGS) $(CPPFLAGS) -MM $(icy2_server_SOURCES) > .depend

# I'm including generated dependencies if they exist
-include .depend

# I'm defining installation hooks for post-install configuration
install-exec-hook:
	@echo "I'm setting up post-installation configuration..."
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/icy2-server
	if [ ! -f $(DESTDIR)$(sysconfdir)/icy2-server/mcaster1.yaml ]; then \
		$(INSTALL) -m 644 $(top_srcdir)/config/mcaster1.yaml \
			$(DESTDIR)$(sysconfdir)/icy2-server/; \
	fi
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/lib/icy2-server
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/log/icy2-server
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run/icy2-server

# I'm defining system service installation (Linux systemd)
if LINUX
install-service:
	@echo "I'm installing systemd service files..."
	$(INSTALL) -d $(DESTDIR)$(systemddir)
	$(INSTALL) -m 644 $(top_srcdir)/scripts/icy2-server.service \
		$(DESTDIR)$(systemddir)/
	systemctl daemon-reload || true

uninstall-service:
	@echo "I'm removing systemd service files..."
	systemctl stop icy2-server || true
	systemctl disable icy2-server || true
	rm -f $(DESTDIR)$(systemddir)/icy2-server.service
	systemctl daemon-reload || true
endif

# I'm defining documentation installation
install-docs:
	@echo "I'm installing documentation..."
	$(INSTALL) -d $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(top_srcdir)/README.md $(DESTDIR)$(docdir)/
	$(INSTALL) -m 644 $(top_srcdir)/LICENSE.md $(DESTDIR)$(docdir)/

# I'm defining development environment setup
dev-setup:
	@echo "I'm setting up development environment..."
	$(INSTALL) -d $(HOME)/.config/icy2-server
	$(INSTALL) -m 644 $(top_srcdir)/config/mcaster1.yaml \
		$(HOME)/.config/icy2-server/
	@echo "Development environment setup completed"

# I'm defining packaging targets for distribution
if PACKAGING
dist-rpm: dist
	@echo "I'm creating RPM package..."
	rpmbuild -ta $(PACKAGE)-$(VERSION).tar.gz

dist-deb: dist
	@echo "I'm creating DEB package..."
	alien --to-deb --scripts $(PACKAGE)-$(VERSION)-1.*.rpm

dist-docker: all
	@echo "I'm creating Docker image..."
	docker build -t icy2-server:$(VERSION) $(top_srcdir)
endif

# I'm defining benchmark targets for performance testing
benchmark: icy2-server
	@echo "I'm running performance benchmarks..."
	./icy2-server --test-mode --debug=1 > benchmark.log 2>&1
	@echo "Benchmark completed, see benchmark.log for results"

# I'm defining security scanning
security-scan:
	@echo "I'm running security analysis..."
	flawfinder $(icy2_server_SOURCES) $(noinst_HEADERS) > security-report.txt
	@echo "Security scan completed, see security-report.txt for results"

# I'm defining help target to show available targets
help:
	@echo "Available targets:"
	@echo "  all          - Build the main executable and libraries"
	@echo "  lib          - Build static library only"
	@echo "  shared       - Build shared library only"
	@echo "  install      - Install all components"
	@echo "  install-lib  - Install libraries and headers only"
	@echo "  clean        - Remove build files"
	@echo "  check        - Run basic tests"
	@echo "  memcheck     - Run memory leak detection"
	@echo "  coverage     - Generate code coverage report (debug builds)"
	@echo "  static-analysis - Run static code analysis"
	@echo "  format-check - Check code formatting"
	@echo "  format-fix   - Fix code formatting"
	@echo "  dev-setup    - Setup development environment"
	@echo "  security-scan - Run security analysis"
	@echo "  benchmark    - Run performance benchmarks"
	@echo "  help         - Show this help message"
