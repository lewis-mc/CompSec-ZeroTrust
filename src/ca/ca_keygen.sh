#!/bin/bash

# Usage check
if [ "$#" -ne 4 ]; then
   echo "Usage: $0 <client_id> <ca_cert_path> <ca_key_path> <key_dir>"
   exit 1
fi

# Command line arguments
CLIENT_ID=$1
CA_CERT_PATH=$2
CA_KEY_PATH=$3
KEY_DIR=$4

# If keys don't exist, creates directory to store them
mkdir -p "${KEY_DIR}"

# Generate an RSA private key
openssl genrsa -out "${KEY_DIR}/${CLIENT_ID}.key" 2048

# Create a certificate signing request (CSR)
openssl req -new -key "${KEY_DIR}/${CLIENT_ID}.key" -out "${KEY_DIR}/${CLIENT_ID}.csr" -subj "/CN=${CLIENT_ID}"

# Sign the CSR with the CA certificate and key to create a client certificate
openssl x509 -req -days 365 -in "${KEY_DIR}/${CLIENT_ID}.csr" -CA "${CA_CERT_PATH}" -CAkey "${CA_KEY_PATH}" -set_serial 01 -out "${KEY_DIR}/${CLIENT_ID}.crt"

# Clean up CSR
rm "${KEY_DIR}/${CLIENT_ID}.csr"

# Copy the CA certificate to the client key directory
cp "${CA_CERT_PATH}" "${KEY_DIR}/ca.crt"

echo "Generated certificate and key for ${CLIENT_ID} in ${KEY_DIR}"
echo "CA certificate copied to ${KEY_DIR}"