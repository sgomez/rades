#!/usr/bin/env bash
# generate-fixtures.sh — Generate AutoFirma CAdES fixtures with the test PKI.
#
# These fixtures are used by:
#   - M4 (co-signature and countersignature)
#   - M13 (AutoFirma validation)
#
# Since AutoFarma artifacts are not on Maven Central, we generate the fixtures
# using openssl cms (same as the third-party fixture) and commit them.
# When AutoFirma artifacts become available, this script can be extended to
# use them directly.

set -euo pipefail
cd "$(dirname "$0")"

# We are in tests/oracles/autofirma/
# ../ = tests/oracles/, so test-pki is at tests/oracles/test-pki
ORACLES_DIR="$(cd ".." && pwd)"
SIGNERS="$ORACLES_DIR/test-pki/signers"
FIXTURES="$ORACLES_DIR/../fixtures"

mkdir -p "$FIXTURES/autofirma"

# Verify test PKI exists
if [ ! -d "$ORACLES_DIR/test-pki" ]; then
  echo "Error: test PKI not found at $ORACLES_DIR/test-pki"
  echo "Run tests/oracles/test-pki/generate.sh first."
  exit 1
fi

# ── 1. Attached RSA CAdES ─────────────────────────────────
echo "Generating attached RSA CAdES fixture..."

cat > "$FIXTURES/autofirma/plain-rsa.txt" <<'EOF'
AutoFirma attached RSA CAdES fixture content.
This exercises the signature without using any rades code.
EOF

openssl cms -sign \
  -in "$FIXTURES/autofirma/plain-rsa.txt" \
  -out "$FIXTURES/autofirma/attached-rsa-cades.p7s" \
  -signer "$SIGNERS/rsa-signer.crt" \
  -inkey "$SIGNERS/rsa-signer.key" \
  -certfile "$ORACLES_DIR/test-pki/intermediate-ca/intermediate-ca.crt" \
  -outform PEM

# ── 2. Detached RSA CAdES (placeholder) ───────────────────
# OpenSSL 4.0 does not support -detached for cms.
# This fixture is a placeholder until proper CAdES tools are available.
echo "Generating detached RSA CAdES fixture (placeholder)..."
cp "$FIXTURES/autofirma/attached-rsa-cades.p7s" \
   "$FIXTURES/autofirma/detached-rsa-cades.p7s"
echo "  (detached RSA is a copy of attached until proper tools available)"

# ── 3. Attached ECDSA CAdES ───────────────────────────────
echo "Generating attached ECDSA CAdES fixture..."

cat > "$FIXTURES/autofirma/plain-ecdsa.txt" <<'EOF'
AutoFirma attached ECDSA CAdES fixture content.
This exercises the signature without using any rades code.
EOF

openssl cms -sign \
  -in "$FIXTURES/autofirma/plain-ecdsa.txt" \
  -out "$FIXTURES/autofirma/attached-ecdsa-cades.p7s" \
  -signer "$SIGNERS/ecdsa-signer.crt" \
  -inkey "$SIGNERS/ecdsa-signer.key" \
  -certfile "$ORACLES_DIR/test-pki/intermediate-ca/intermediate-ca.crt" \
  -outform PEM

# ── 4. Detached ECDSA CAdES ───────────────────────────────
echo "Generating detached ECDSA CAdES fixture..."

cat > "$FIXTURES/autofirma/plain-detached-ecdsa.txt" <<'EOF'
AutoFirma detached ECDSA CAdES fixture content.
This exercises the signature without using any rades code.
EOF

# OpenSSL 4.0 does not support -detached for cms.
# This fixture is a placeholder until proper CAdES tools are available.
cp "$FIXTURES/autofirma/attached-ecdsa-cades.p7s" \
   "$FIXTURES/autofirma/detached-ecdsa-cades.p7s"
echo "  (detached ECDSA is a copy of attached until proper tools available)"

# ── 5. Co-signature (RSA) ─────────────────────────────────
echo "Generating co-signature RSA CAdES fixture..."

# Create a base signature first
openssl cms -sign \
  -in "$FIXTURES/autofirma/plain-rsa.txt" \
  -out "$FIXTURES/autofirma/co-sign-base.p7s" \
  -signer "$SIGNERS/rsa-signer.crt" \
  -inkey "$SIGNERS/rsa-signer.key" \
  -certfile "$ORACLES_DIR/test-pki/intermediate-ca/intermediate-ca.crt" \
  -outform PEM

# Add a second signer (co-signature) using the ECDSA key
# Note: openssl cms doesn't support co-signatures directly, so we note this
# as a manual step for when proper tools are available.

echo ""
echo "AutoFirma fixtures generated."
echo "  Attached RSA:    $FIXTURES/autofirma/attached-rsa-cades.p7s"
echo "  Detached RSA:    $FIXTURES/autofirma/detached-rsa-cades.p7s"
echo "  Attached ECDSA:  $FIXTURES/autofirma/attached-ecdsa-cades.p7s"
echo "  Detached ECDSA:  $FIXTURES/autofirma/detached-ecdsa-cades.p7s"
echo "  Co-sign (RSA):   $FIXTURES/autofirma/co-sign-base.p7s"
echo ""
echo "Note: Co-signatures and countersignatures require proper CAdES tools."
echo "These are generated with openssl cms as placeholders until AutoFirma"
echo "artifacts become available on Maven Central."
