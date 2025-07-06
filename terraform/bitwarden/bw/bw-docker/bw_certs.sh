#!/bin/bash

# Bitwarden Unified Self-Signed Certificate Generator
# Usage: ./bw_unified_self_signed_cert.sh [domain]

set -e

# Check if domain argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 [domain]"
    echo "Example: $0 bitwarden.example.com"
    exit 1
fi

DOMAIN=$1
SSL_DIR="./ssl"
COMPOSE_FILE="docker-compose.yml"

# Create SSL directory if it doesn't exist
mkdir -p "$SSL_DIR"

# Generate self-signed certificate
echo "Generating self-signed certificate for $DOMAIN..."
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 365 \
    -keyout "$SSL_DIR/key.pem" \
    -out "$SSL_DIR/cert.pem" \
    -reqexts SAN -extensions SAN \
    -config <(cat /etc/ssl/openssl.cnf 2>/dev/null || cat /usr/lib/ssl/openssl.cnf 2>/dev/null || cat /etc/pki/tls/openssl.cnf 2>/dev/null; printf "\n[SAN]\nsubjectAltName=DNS:$DOMAIN\nbasicConstraints=CA:true") \
    -subj "/C=US/ST=California/L=Los Angeles/O=Bitwarden/OU=Self-Hosted/CN=$DOMAIN"

# Generate Diffie-Hellman parameters
echo "Generating Diffie-Hellman parameters (this may take a while)..."
openssl dhparam -out "$SSL_DIR/dhparam.pem" 2048

# Update nginx configuration if needed
if [ -f "./bitwarden-ssl.conf" ]; then
    echo "Updating nginx configuration..."
    sed -i "s/server_name .*;/server_name $DOMAIN;/g" "./bitwarden-ssl.conf"
fi

# Set proper permissions
chmod -R 600 "$SSL_DIR"
chmod 644 "$SSL_DIR/cert.pem"

echo ""
echo "Self-signed certificate generation complete!"
echo "Files created in: $SSL_DIR"
echo ""
echo "Certificate: $SSL_DIR/cert.pem"
echo "Private Key: $SSL_DIR/key.pem"
echo "DH Params:   $SSL_DIR/dhparam.pem"
echo ""
echo "Next steps:"
echo "1. Restart your containers: docker-compose down && docker-compose up -d"
echo "2. Install the certificate in your trusted store on all devices that will access this server"
echo "3. Consider setting globalSettings__requireSsl=true in your docker-compose.yml for better security"
