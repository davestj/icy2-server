#!/bin/bash
# I created this script to bootstrap the autotools build system
set -e

echo "I'm running autoreconf to generate build files..."
autoreconf -fiv

echo "I have successfully bootstrapped the build system."
echo "Run './configure' to configure the build."
