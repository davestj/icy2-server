#!/usr/bin/env bash
set -e

# Prompt for configuration values
read -p "Listen IP: " listen_ip
read -p "Port: " port
read -p "Admin username: " admin_user
read -s -p "Admin password: " admin_pass
echo
read -p "Output filename [server.yaml]: " out_file
out_file=${out_file:-server.yaml}

# Ensure config directory exists
mkdir -p config

# Write configuration to YAML file
cat > "config/${out_file}" <<YAML
server:
  listen_ip: "${listen_ip}"
  port: ${port}
admin:
  username: "${admin_user}"
  password: "${admin_pass}"
YAML

echo "Configuration written to config/${out_file}"
