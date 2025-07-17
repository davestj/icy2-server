# File: Makefile.am  
# Path: /var/www/mcaster1.com/DNAS/icy2-server/Makefile.am
# Author: davestj@gmail.com (David St. John)
# Created: 2025-07-16  
# Purpose: I created this enhanced Makefile.am that includes comprehensive cleanup
#          targets to reset the autotools build system completely. This gives users
#          multiple levels of cleaning from basic to complete project reset.
# 
# Reason: I need robust cleanup mechanisms that can handle different scenarios:
#         normal cleaning, configuration reset, and complete autotools reset.
#         This prevents build system corruption and provides reliable recovery.
#
# Changelog:
# 2025-07-16 - Added comprehensive cleanup targets for autotools reset
# 2025-07-16 - Implemented multiple levels of cleaning (clean, distclean, reset)
# 2025-07-16 - Added safety checks and informative output for cleanup operations
# 2025-07-16 - Integrated with standard autotools cleaning conventions
# 2025-07-16 - Added bootstrap reset functionality for complete project restart
#
# Next Dev Feature: I plan to add automated backup before major cleanups
# Git Commit: feat: implement comprehensive build system cleanup and reset targets
#
# TODO: Add backup functionality, Windows-specific cleanup, dependency checking

# I'm defining only the subdirectories that actually exist and have Makefile.am files
SUBDIRS = src

# I'm including files that actually exist in the distribution
EXTRA_DIST = \
    README.md \
    LICENSE.md \
    bootstrap.sh \
    autogen.sh \
    config/mcaster1.yaml

# I'm defining custom cleaning targets with different levels of thoroughness
# These targets provide users with multiple options for resetting their build environment

# Comprehensive autotools reset target - removes everything autotools generated
# This is the most thorough cleanup available
.PHONY: bootstrap-clean reset-autotools clean-all maintainer-clean-local

bootstrap-clean: maintainer-clean-local
	@echo "I'm performing comprehensive autotools reset..."
	@echo "This will remove all generated autotools files and reset to pristine state."
	@echo "Removing autotools cache..."
	-rm -rf autom4te.cache
	@echo "Removing generated template files..."
	-rm -f Makefile.in src/Makefile.in config/Makefile.in include/Makefile.in
	-rm -f config.h.in
	@echo "Removing configure script..."
	-rm -f configure
	@echo "Removing generated makefiles..."
	-rm -f Makefile src/Makefile config/Makefile include/Makefile
	@echo "Removing autotools helper files..."
	-rm -f compile config.guess config.sub depcomp install-sh missing ltmain.sh
	-rm -f libtool config.lt config.status config.log
	@echo "Cleaning macro directory..."
	-find m4 -name "*.m4" -not -name "README.md" -delete 2>/dev/null || true
	@echo "Removing compiled artifacts..."
	-find . -name "*.o" -delete 2>/dev/null || true
	-find . -name "*.lo" -delete 2>/dev/null || true
	-find . -name "*.la" -delete 2>/dev/null || true
	-find . -name "*.a" -delete 2>/dev/null || true
	-find . -name ".libs" -type d -exec rm -rf {} + 2>/dev/null || true
	-find . -name ".deps" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Bootstrap cleanup complete. Project is now in pristine state."
	@echo "Run './autogen.sh' to regenerate the build system."

# I'm creating an alias for the bootstrap-clean target
reset-autotools: bootstrap-clean

# I'm creating a complete clean target that includes everything
clean-all: bootstrap-clean
	@echo "Complete project cleanup finished."

# Enhanced maintainer-clean target - integrates with autotools standard cleaning hierarchy
maintainer-clean-local:
	@echo "I'm performing maintainer-level cleanup..."
	@echo "Removing backup files that editors might create..."
	-find . -name "*~" -delete 2>/dev/null || true
	-find . -name "*.bak" -delete 2>/dev/null || true
	-find . -name ".#*" -delete 2>/dev/null || true
	@echo "Removing temporary files that might accumulate..."
	-find . -name "core" -delete 2>/dev/null || true
	-find . -name "core.*" -delete 2>/dev/null || true
	@echo "Maintainer cleanup complete."

# Enhanced distclean target - removes configuration files but keeps autotools infrastructure
distclean-local:
	@echo "I'm performing distribution cleanup..."
	@echo "Removing local configuration that shouldn't be in distributions..."
	-rm -f config.cache
	-rm -f config.h config.status config.log
	@echo "Removing local build directories..."
	-rm -rf .libs
	@echo "Distribution cleanup complete."

# Enhanced clean target - removes compiled files but keeps configuration  
clean-local:
	@echo "I'm performing standard cleanup..."
	@echo "Removing temporary build artifacts in the top level..."
	-rm -f *.tmp *.temp
	@echo "Removing test artifacts that might be left behind..."
	-rm -f test-*.log test-*.tmp
	@echo "Standard cleanup complete."

# I'm adding library building support (referenced by configure.ac output)
lib: all
	@echo "I'm building the static library..."
	cd src && $(MAKE) libicy2-server.a

# I'm adding library installation support  
install-lib: lib
	@echo "I'm installing the library and headers..."
	$(INSTALL) -d $(DESTDIR)$(libdir)
	$(INSTALL) -d $(DESTDIR)$(includedir)
	$(INSTALL) -m 644 src/libicy2-server.a $(DESTDIR)$(libdir)/
	$(INSTALL) -m 644 include/icy2_server.h $(DESTDIR)$(includedir)/

# I'm adding SSL certificate generation
generate-ssl:
	@echo "I'm generating SSL certificates..."
	./bootstrap.sh ssl-only

# I'm adding configuration testing
test-config:
	@echo "I'm testing the configuration..."
	./src/icy2-server --test-mode

# Development setup target that includes cleanup and regeneration
dev-reset: bootstrap-clean
	@echo "I'm performing complete development environment reset..."
	@echo "Regenerating autotools build system..."
	./autogen.sh
	@echo "Configuring with development options..."
	./configure --enable-debug --enable-ssl --enable-php-fmp
	@echo "Development environment reset complete."

# I'm adding a help target that explains all the cleaning options
clean-help:
	@echo "ICY2-SERVER Cleanup Options:"
	@echo "============================"
	@echo ""
	@echo "Standard Autotools Targets:"
	@echo "  make clean            - Remove compiled files, keep configuration"
	@echo "  make distclean        - Remove compiled files and configuration"
	@echo "  make maintainer-clean - Remove all generated files"
	@echo ""
	@echo "Custom Reset Targets:"
	@echo "  make bootstrap-clean  - Complete autotools reset (most thorough)"
	@echo "  make reset-autotools  - Alias for bootstrap-clean"
	@echo "  make clean-all        - Complete project cleanup"
	@echo "  make dev-reset        - Clean, regenerate, and configure for development"
	@echo ""
	@echo "Other Targets:"
	@echo "  make lib              - Build static library"
	@echo "  make install-lib      - Install library and headers"
	@echo "  make generate-ssl     - Generate SSL certificates"
	@echo "  make test-config      - Test server configuration"
	@echo "  make clean-help       - Show this help message"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make bootstrap-clean && ./autogen.sh  # Complete reset and regenerate"
	@echo "  make dev-reset                        # Reset and configure for development"
	@echo "  make clean && make                    # Quick rebuild"

.PHONY: lib install-lib generate-ssl test-config dev-reset clean-help
