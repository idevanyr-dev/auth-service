#!/bin/bash

# Script to generate RSA key pair for JWT signing
# This script generates development keys - for production, use a secure key management system

echo "🔐 Generating RSA key pair for JWT signing..."

# Create keys directory if it doesn't exist
mkdir -p keys

# Generate private key (3072 bits for good security)
echo "📝 Generating private key..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/private_key.pem

# Generate public key from private key
echo "📝 Generating public key..."
openssl rsa -pubout -in keys/private_key.pem -out keys/public_key.pem

# Convert to base64 for environment variables
echo "📝 Converting keys to base64..."
PRIVATE_KEY_B64=$(cat keys/private_key.pem | base64 -w0)
PUBLIC_KEY_B64=$(cat keys/public_key.pem | base64 -w0)

# Save base64 versions
echo "$PRIVATE_KEY_B64" > keys/private_key_base64.txt
echo "$PUBLIC_KEY_B64" > keys/public_key_base64.txt

echo ""
echo "✅ Keys generated successfully!"
echo ""
echo "📁 Files created:"
echo "  - keys/private_key.pem (Private key in PEM format)"
echo "  - keys/public_key.pem (Public key in PEM format)"
echo "  - keys/private_key_base64.txt (Private key in base64)"
echo "  - keys/public_key_base64.txt (Public key in base64)"
echo ""
echo "🔒 SECURITY WARNING:"
echo "  - Keep private_key.pem secure and never commit it to version control"
echo "  - Use a secure key management system in production"
echo "  - The keys/ directory is ignored by git"
echo ""
echo "📋 To use with environment variables:"
echo "  JWT_PRIVATE_KEY=$(cat keys/private_key_base64.txt)"
echo "  JWT_PUBLIC_KEY=$(cat keys/public_key_base64.txt)"
echo ""
echo "🐳 To use with Docker:"
echo "  Copy the content of the base64 files to your .env file"
echo ""