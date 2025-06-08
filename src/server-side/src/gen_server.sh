#!/bin/bash

# Exit on error
set -e

# Check if all required arguments are passed
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <ca_cert_path> <ca_key_path> <key_dir>"
    exit 1
fi

# Parse arguments
CA_CERT_PATH=$1
CA_KEY_PATH=$2
KEY_DIR=$3

# Ensure the key directory exists
mkdir -p "$KEY_DIR"

# Paths for client-specific files
SERVER_KEY="$KEY_DIR/server_private.key"
SERVER_CSR="$KEY_DIR/server.csr"
SERVER_CERT="$KEY_DIR/server.crt"
JWT_SECRET_FILE="$KEY_DIR/jwt_secret.key"

# Generate private key for the server
if [ ! -f "$SERVER_KEY" ]; then
    echo "Generating private key for server ..."
    openssl genpkey -algorithm RSA -out "$SERVER_KEY" -pkeyopt rsa_keygen_bits:2048
else
    echo "Private key already exists for server. Skipping generation."
fi

# Generate CSR for the server
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=localhost"

# Sign the CSR with the CA to create the server certificate
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT_PATH" -CAkey "$CA_KEY_PATH" -CAcreateserial -out "$SERVER_CERT" -days 365 -sha256

# Clean up CSR
rm "${KEY_DIR}/server.csr"

# Copy the CA certificate to the server directory
echo "Copying CA certificate to server key directory..."
cp "$CA_CERT_PATH" "$KEY_DIR/"

# Step: Generate JWT Secret if it does not exist
if [ ! -f "$JWT_SECRET_FILE" ]; then
    echo "Generating JWT secret key ..."
    # Generate a random 64-byte secret key
    openssl rand -base64 64 > "$JWT_SECRET_FILE"
else
    echo "JWT secret key already exists. Skipping generation."
fi

# Success message
echo "Generated certificate and key for server in $KEY_DIR"
echo "CA certificate copied to $KEY_DIR"
