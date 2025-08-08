# File: configure.ac
# Path: /var/www/mcaster1.com/DNAS/icy2-server/configure.ac
# Author: davestj@gmail.com (David St. John)
# Created: 2025-07-16
# Purpose: I created this configure.ac to fix all compilation errors by properly
#          defining version constants and ensuring all dependencies are correctly
#          detected and configured for successful compilation.
#
# Reason: I need to resolve the ICY2_VERSION_STRING compilation error and ensure
#         all autotools conditionals and definitions are properly set up to
#         match what the source code actually expects and uses.
#
# Changelog:
# 2025-07-16 - Fixed all autotools errors from actual build output
# 2025-07-16 - Added all missing AC_PROG_* declarations
# 2025-07-16 - Defined all conditionals that src/Makefile.am uses
# 2025-07-16 - Added libtool support for shared library building
# 2025-07-16 - Fixed ICY2_VERSION_STRING definition for compilation success
# 2025-07-16 - Added proper AC_CONFIG_HEADERS for config.h generation
#
# Next Dev Feature: I plan to add more features as the build stabilizes
# Git Commit: fix: properly define version constants and resolve compilation errors
#
# TODO: Optimize configuration once basic build works

# I'm initializing autoconf with basic project information
AC_INIT([icy2-server], [1.1.1], [davestj@gmail.com], [icy2-server], [https://mcaster1.com])

# I'm setting up automake configuration
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# I'm defining source configuration
AC_CONFIG_SRCDIR([src/main.cpp])

# I'm configuring the header generation - this creates config.h with all our defines
AC_CONFIG_HEADERS([config.h])

# I'm checking for all the build programs that src/Makefile.am needs
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# I'm adding the missing RANLIB program (fixes "RANLIB is undefined" error)
AC_PROG_RANLIB

# I'm adding the missing AR program (fixes "AM_PROG_AR" warning)
AM_PROG_AR

# I'm initializing libtool (fixes "LIBTOOL is undefined" error)
LT_INIT

# I'm ensuring C++17 standard support
AX_CXX_COMPILE_STDCXX_17([noext], [mandatory])

# I'm checking for pthread support (required for multi-threading)
AX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
], [
    AC_MSG_ERROR([I require pthread support for multi-threaded operation])
])

# I'm checking for required libraries (all passed in your test)
if test "x$enable_ssl" = "xyes"; then
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0], [
    AC_DEFINE([HAVE_OPENSSL], [1], [Define if OpenSSL is available])
], [
    AC_MSG_ERROR([I require OpenSSL 1.1.0+. Install: apt-get install libssl-dev])
])
else
    OPENSSL_LIBS=""
    OPENSSL_CFLAGS=""
fi
AC_SUBST([OPENSSL_LIBS])
AC_SUBST([OPENSSL_CFLAGS])

PKG_CHECK_MODULES([YAML_CPP], [yaml-cpp >= 0.6.0], [
    AC_DEFINE([HAVE_YAML_CPP], [1], [Define if yaml-cpp is available])
], [
    AC_MSG_ERROR([I require yaml-cpp 0.6.0+. Install: apt-get install libyaml-cpp-dev])
])

# I'm checking for FastCGI library (passed in your test)
AC_CHECK_LIB([fcgi], [FCGI_Accept], [
    FCGI_LIBS="-lfcgi"
    AC_SUBST([FCGI_LIBS])
    AC_DEFINE([HAVE_FCGI], [1], [Define if FastCGI library is available])
], [
    AC_MSG_ERROR([I require libfcgi. Install: apt-get install libfcgi-dev])
])

# I'm checking for FastCGI headers (passed in your test)
AC_CHECK_HEADERS([fcgiapp.h], [], [
    AC_MSG_ERROR([I require fcgiapp.h. Install: apt-get install libfcgi-dev])
])

# I'm checking for standard headers that we use
AC_CHECK_HEADERS([stdio.h stdlib.h string.h inttypes.h stdint.h strings.h])
AC_CHECK_HEADERS([sys/stat.h sys/types.h unistd.h dlfcn.h])
AC_CHECK_HEADERS([sys/socket.h netinet/in.h arpa/inet.h fcntl.h sys/epoll.h])

# I'm setting up build configuration options
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debug build]),
    [enable_debug=$enableval], [enable_debug=no])

AC_ARG_ENABLE([ssl],
    AS_HELP_STRING([--enable-ssl], [Enable SSL support]),
    [enable_ssl=$enableval], [enable_ssl=no])

AC_ARG_ENABLE([php-fpm],
    AS_HELP_STRING([--enable-php-fpm], [Enable PHP-FPM support]),
    [enable_php_fpm=$enableval], [enable_php_fpm=yes])

AC_ARG_ENABLE([shared],
    AS_HELP_STRING([--enable-shared], [Build shared libraries]),
    [enable_shared_libs=$enableval], [enable_shared_libs=yes])

# I'm defining ALL the conditionals that src/Makefile.am actually uses
# This fixes the "does not appear in AM_CONDITIONAL" errors

# I'm fixing the PHP_FPM conditional (this was the main error)
AM_CONDITIONAL([PHP_FPM], [test "x$enable_php_fpm" = "xyes"])

# I'm defining the other conditionals that src/Makefile.am references
AM_CONDITIONAL([DEBUG], [test "x$enable_debug" = "xyes"])
AM_CONDITIONAL([SSL], [test "x$enable_ssl" = "xyes"])
AM_CONDITIONAL([SHARED_LIBS], [test "x$enable_shared_libs" = "xyes"])

# I'm setting up platform detection for the LINUX conditional
AC_CANONICAL_HOST
case $host_os in
    linux*) platform_linux=yes ;;
    *) platform_linux=no ;;
esac
AM_CONDITIONAL([LINUX], [test "x$platform_linux" = "xyes"])

# I'm defining the PACKAGING conditional (even if not used yet)
AM_CONDITIONAL([PACKAGING], [false])

# I'm setting up compiler flags based on debug setting
if test "x$enable_debug" = "xyes"; then
    AC_DEFINE([DEBUG], [1], [Define for debug build])
    CXXFLAGS="$CXXFLAGS -g -O0 -DDEBUG -Wall -Wextra"
    CFLAGS="$CFLAGS -g -O0 -DDEBUG -Wall -Wextra"
else
    AC_DEFINE([NDEBUG], [1], [Define for release build])
    CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
    CFLAGS="$CFLAGS -O2 -DNDEBUG"
fi

# I'm setting up feature-specific defines
if test "x$enable_ssl" = "xyes"; then
    AC_DEFINE([ICY2_SSL_ENABLED], [1], [Define if SSL support is enabled])
fi

if test "x$enable_php_fpm" = "xyes"; then
    AC_DEFINE([ICY2_PHP_ENABLED], [1], [Define if PHP-FPM support is enabled])
fi

# I'm setting up version information that the source code expects
# THIS IS THE KEY FIX: I'm properly defining ICY2_VERSION_STRING
AC_DEFINE_UNQUOTED([ICY2_VERSION_STRING], ["$PACKAGE_VERSION"], [Full version string])
AC_DEFINE_UNQUOTED([ICY2_VERSION_MAJOR], [1], [Major version number])
AC_DEFINE_UNQUOTED([ICY2_VERSION_MINOR], [1], [Minor version number])
AC_DEFINE_UNQUOTED([ICY2_VERSION_PATCH], [1], [Patch version number])

# I'm setting up build information
AC_DEFINE_UNQUOTED([ICY2_BUILD_DATE], ["`date +%Y-%m-%d`"], [Build date])
AC_DEFINE_UNQUOTED([ICY2_BUILD_TIME], ["`date +%H:%M:%S`"], [Build time])

# I'm adding package information defines
AC_DEFINE_UNQUOTED([PACKAGE_NAME], ["$PACKAGE_NAME"], [Package name])
AC_DEFINE_UNQUOTED([PACKAGE_VERSION], ["$PACKAGE_VERSION"], [Package version])
AC_DEFINE_UNQUOTED([PACKAGE_STRING], ["$PACKAGE_STRING"], [Package string])
AC_DEFINE_UNQUOTED([PACKAGE_TARNAME], ["$PACKAGE_TARNAME"], [Package tar name])
AC_DEFINE_UNQUOTED([PACKAGE_URL], ["$PACKAGE_URL"], [Package URL])
AC_DEFINE_UNQUOTED([PACKAGE_BUGREPORT], ["$PACKAGE_BUGREPORT"], [Package bug report])

# I'm generating the output files (only for directories that exist)
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT

# I'm showing a comprehensive configuration summary
echo ""
echo "ICY2-SERVER Configuration Complete"
echo "=================================="
echo "Version:           $PACKAGE_VERSION"
echo "Debug build:       $enable_debug"
echo "SSL support:       $enable_ssl"
echo "PHP-FPM support:   $enable_php_fpm"
echo "Shared libraries:  $enable_shared_libs"
echo "Platform:          $host_os"
echo ""
echo "Build tools found:"
echo "  C++ Compiler:    $CXX"
echo "  C Compiler:      $CC"
echo "  Ranlib:          $(which ranlib)"
echo "  AR archiver:     $(which ar)"
echo "  Libtool:         Available"
echo ""
echo "Dependencies found:"
echo "  OpenSSL:         $OPENSSL_LIBS"
echo "  YAML-CPP:        $YAML_CPP_LIBS"
echo "  FastCGI:         $FCGI_LIBS"
echo ""
echo "Version definitions:"
echo "  ICY2_VERSION_STRING: $PACKAGE_VERSION"
echo "  ICY2_VERSION_MAJOR:  1"
echo "  ICY2_VERSION_MINOR:  1"
echo "  ICY2_VERSION_PATCH:  1"
echo ""
echo "Next steps:"
echo "  make             # Build the server and libraries"
echo "  make install     # Install the server"
echo ""