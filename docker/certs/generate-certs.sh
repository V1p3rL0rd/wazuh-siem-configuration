#!/usr/bin/env bash
# ==============================================================================
# Generate TLS / SSL Certificates for Wazuh SIEM Components
# Generates Root CA, Indexer, Filebeat (Manager), and Dashboard certificates.
# Supports SAN (Subject Alternative Names) for IP and FQDN from .env.
# ==============================================================================
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ENV_FILE="${CERTS_DIR}/../.env"

# Load SAN variables from .env if present
WAZUH_SERVER_IP="127.0.0.1"
WAZUH_SERVER_FQDN="localhost"

if [ -f "${ENV_FILE}" ]; then
    # Extract without exporting everything
    ENV_IP=$(grep -E '^WAZUH_SERVER_IP=' "${ENV_FILE}" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)
    ENV_FQDN=$(grep -E '^WAZUH_SERVER_FQDN=' "${ENV_FILE}" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)
    [ -n "${ENV_IP}" ] && WAZUH_SERVER_IP="${ENV_IP}"
    [ -n "${ENV_FQDN}" ] && WAZUH_SERVER_FQDN="${ENV_FQDN}"
fi

echo "==> Certificate SAN Target: FQDN=${WAZUH_SERVER_FQDN}, IP=${WAZUH_SERVER_IP}"
cd "${CERTS_DIR}"

echo "==> 1. Generating Root Certificate Authority (CA)..."
openssl genrsa -out root-ca-key.pem 2048
openssl req -x509 -new -nodes -key root-ca-key.pem -sha256 -days 1095 -out root-ca.pem \
  -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=root-ca"

generate_node_cert() {
    local name="$1"
    local cn="$2"
    echo "==> Generating certificate for ${name} (CN=${cn})..."
    openssl genrsa -out "${name}-key.pem" 2048
    openssl req -new -key "${name}-key.pem" -out "${name}.csr" \
      -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=${cn}"
    
    cat > "${name}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${cn}
DNS.2 = localhost
DNS.3 = wazuh-${name}
DNS.4 = ${WAZUH_SERVER_FQDN}
IP.1 = 127.0.0.1
IP.2 = ${WAZUH_SERVER_IP}
EOF

    openssl x509 -req -in "${name}.csr" -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial \
      -out "${name}.pem" -days 730 -sha256 -extfile "${name}.ext"
    rm -f "${name}.csr" "${name}.ext"
}

# Generate certificates for components
generate_node_cert "indexer" "wazuh-indexer"
generate_node_cert "filebeat" "wazuh-manager"
generate_node_cert "dashboard" "wazuh-dashboard"

# Restrict private key permissions
chmod 600 *-key.pem
chmod 644 *.pem

echo "==> Certificates generated successfully in ${CERTS_DIR}:"
ls -lh *.pem
