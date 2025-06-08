#!/bin/bash

# Exit on error
set -e

# Check if all required arguments are passed
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <client_id> <ca_cert_path> <ca_key_path> <key_dir>"
    exit 1
fi

# Parse arguments
CLIENT_ID=$1
CA_CERT_PATH=$2
CA_KEY_PATH=$3
KEY_DIR=$4

# Ensure the key directory exists
mkdir -p "$KEY_DIR"
mkdir -p "$KEY_DIR/../storage"

# Paths for client-specific files
CLIENT_KEY="$KEY_DIR/${CLIENT_ID}_private.key"
CLIENT_CSR="$KEY_DIR/${CLIENT_ID}.csr"
CLIENT_CERT="$KEY_DIR/${CLIENT_ID}.crt"

# Generate private key for the client
if [ ! -f "$CLIENT_KEY" ]; then
    echo "Generating private key for client '$CLIENT_ID'..."
    openssl genpkey -algorithm RSA -out "$CLIENT_KEY" -pkeyopt rsa_keygen_bits:2048
else
    echo "Private key already exists for client '$CLIENT_ID'. Skipping generation."
fi

# Generate CSR for the client
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=$CLIENT_ID"

# Sign the CSR with the CA to create the client certificate
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT_PATH" -CAkey "$CA_KEY_PATH" -CAcreateserial -out "$CLIENT_CERT" -days 365 -sha256

# Clean up CSR
rm "${KEY_DIR}/${CLIENT_ID}.csr"

# Copy the CA certificate to the client directory
echo "Copying CA certificate to client key directory..."
cp "$CA_CERT_PATH" "$KEY_DIR/"

# Success message
echo "Generated certificate and key for client '$CLIENT_ID' in $KEY_DIR"
echo "CA certificate copied to $KEY_DIR"
