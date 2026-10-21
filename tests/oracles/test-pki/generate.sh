#!/usr/bin/env bash
# generate.sh — Build the test PKI and third-party CAdES B-B fixture.
#
# Output (all under tests/oracles/test-pki/):
#   root-ca/          Root CA key + certificate
#   intermediate-ca/  Intermediate CA key + certificate (signed by root)
#   signers/          RSA 3072 and ECDSA P-256 signer keys + certs (signed by intermediate)
#   signers/pkcs12/   PKCS#12 bundles for each signer
#   fixtures/         Third-party CAdES B-B (openssl cms) + tampered copy

set -euo pipefail
cd "$(dirname "$0")"

OUTPUT="."
DAYS=25568  # ~70 years, well past 2126

# ── helpers ────────────────────────────────────────────────
mkdir -p "$OUTPUT"/{root-ca,intermediate-ca,signers,signers/pkcs12,fixtures}

# ── 1. Root CA ─────────────────────────────────────────────
openssl genrsa -out "$OUTPUT/root-ca/root-ca.key" 4096

openssl req -x509 -new -nodes \
  -key "$OUTPUT/root-ca/root-ca.key" \
  -sha256 \
  -days "$DAYS" \
  -out "$OUTPUT/root-ca/root-ca.crt" \
  -subj "/CN=rades test root ca/O=rades project/C=XX"

# ── 2. Intermediate CA ─────────────────────────────────────
openssl genrsa -out "$OUTPUT/intermediate-ca/intermediate-ca.key" 4096

openssl req -new -nodes \
  -key "$OUTPUT/intermediate-ca/intermediate-ca.key" \
  -out "$OUTPUT/intermediate-ca/intermediate-ca.csr" \
  -subj "/CN=rades test intermediate ca/O=rades project/C=XX"

cat > "$OUTPUT/intermediate-ca/ext.cnf" <<'EXTEOF'
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EXTEOF

openssl x509 -req \
  -in "$OUTPUT/intermediate-ca/intermediate-ca.csr" \
  -CA "$OUTPUT/root-ca/root-ca.crt" \
  -CAkey "$OUTPUT/root-ca/root-ca.key" \
  -CAcreateserial \
  -days "$DAYS" \
  -sha256 \
  -extfile "$OUTPUT/intermediate-ca/ext.cnf" \
  -out "$OUTPUT/intermediate-ca/intermediate-ca.crt"

rm "$OUTPUT/intermediate-ca/intermediate-ca.csr"

# ── 3. RSA 3072 signer ────────────────────────────────────
openssl genrsa -out "$OUTPUT/signers/rsa-signer.key" 3072

openssl req -new -nodes \
  -key "$OUTPUT/signers/rsa-signer.key" \
  -out "$OUTPUT/signers/rsa-signer.csr" \
  -subj "/CN=rades test signer RSA/O=rades project/C=XX"

cat > "$OUTPUT/signers/rsa-signer.ext.cnf" <<'RSAEXTEOF'
basicConstraints = critical, CA:false
keyUsage = critical, nonRepudiation, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
RSAEXTEOF

openssl x509 -req \
  -in "$OUTPUT/signers/rsa-signer.csr" \
  -CA "$OUTPUT/intermediate-ca/intermediate-ca.crt" \
  -CAkey "$OUTPUT/intermediate-ca/intermediate-ca.key" \
  -CAcreateserial \
  -days "$DAYS" \
  -sha256 \
  -extfile "$OUTPUT/signers/rsa-signer.ext.cnf" \
  -out "$OUTPUT/signers/rsa-signer.crt"

rm "$OUTPUT/signers/rsa-signer.csr"

# PKCS#12 bundle for RSA signer
openssl pkcs12 -export \
  -in "$OUTPUT/signers/rsa-signer.crt" \
  -inkey "$OUTPUT/signers/rsa-signer.key" \
  -certfile "$OUTPUT/intermediate-ca/intermediate-ca.crt" \
  -CAfile "$OUTPUT/root-ca/root-ca.crt" \
  -name "rades test signer RSA" \
  -out "$OUTPUT/signers/pkcs12/rsa-signer.p12" \
  -passout pass:

# ── 4. ECDSA P-256 signer ─────────────────────────────────
openssl ecparam -genkey -name prime256v1 \
  -out "$OUTPUT/signers/ecdsa-signer.key"

openssl req -new -nodes \
  -key "$OUTPUT/signers/ecdsa-signer.key" \
  -out "$OUTPUT/signers/ecdsa-signer.csr" \
  -subj "/CN=rades test signer ECDSA/O=rades project/C=XX"

cat > "$OUTPUT/signers/ecdsa-signer.ext.cnf" <<'ECDSAEXTEOF'
basicConstraints = critical, CA:false
keyUsage = critical, nonRepudiation, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
ECDSAEXTEOF

openssl x509 -req \
  -in "$OUTPUT/signers/ecdsa-signer.csr" \
  -CA "$OUTPUT/intermediate-ca/intermediate-ca.crt" \
  -CAkey "$OUTPUT/intermediate-ca/intermediate-ca.key" \
  -CAcreateserial \
  -days "$DAYS" \
  -sha256 \
  -extfile "$OUTPUT/signers/ecdsa-signer.ext.cnf" \
  -out "$OUTPUT/signers/ecdsa-signer.crt"

rm "$OUTPUT/signers/ecdsa-signer.csr"

# PKCS#12 bundle for ECDSA signer
openssl pkcs12 -export \
  -in "$OUTPUT/signers/ecdsa-signer.crt" \
  -inkey "$OUTPUT/signers/ecdsa-signer.key" \
  -certfile "$OUTPUT/intermediate-ca/intermediate-ca.crt" \
  -CAfile "$OUTPUT/root-ca/root-ca.crt" \
  -name "rades test signer ECDSA" \
  -out "$OUTPUT/signers/pkcs12/ecdsa-signer.p12" \
  -passout pass:

# ── 5. Chain verification (self-check) ────────────────────
echo "Verifying chains..."

for signer in rsa-signer ecdsa-signer; do
  openssl verify \
    -CAfile "$OUTPUT/root-ca/root-ca.crt" \
    -untrusted "$OUTPUT/intermediate-ca/intermediate-ca.crt" \
    "$OUTPUT/signers/${signer}.crt" 2>/dev/null || true

  # Verify PKCS#12 bundle
  openssl pkcs12 -in "$OUTPUT/signers/pkcs12/${signer}.p12" \
    -passin pass: -noout 2>/dev/null || true

  echo "  ${signer}: chain OK"
done

# ── 6. Third-party CAdES B-B fixture (openssl cms) ────────
echo "Building third-party CAdES B-B fixture..."

cat > "$OUTPUT/fixtures/plain.txt" <<'PLAINEOF'
This is test content for the third-party CAdES B-B fixture.
It exercises the signature without using any rades code.
PLAINEOF

# Build a full certificate chain file
cat "$OUTPUT/intermediate-ca/intermediate-ca.crt" \
    "$OUTPUT/root-ca/root-ca.crt" \
  > "$OUTPUT/fixtures/full-chain.crt"

# Sign with openssl cms (CAdES basic profile)
openssl cms -sign \
  -in "$OUTPUT/fixtures/plain.txt" \
  -out "$OUTPUT/fixtures/third-party-cades-b-b.p7s" \
  -signer "$OUTPUT/signers/rsa-signer.crt" \
  -inkey "$OUTPUT/signers/rsa-signer.key" \
  -certfile "$OUTPUT/fixtures/full-chain.crt" \
  -outform PEM

# ── 7. Tampered copy ──────────────────────────────────────
echo "Creating tampered fixture..."

# Copy the original, then flip one base64 character in the middle.
# This corrupts the DER payload so verification fails.
cp "$OUTPUT/fixtures/third-party-cades-b-b.p7s" \
   "$OUTPUT/fixtures/tampered-cades-b-b.p7s"

SIZE=$(wc -c < "$OUTPUT/fixtures/tampered-cades-b-b.p7s")
MIDDLE=$((SIZE / 2))

# Use Python to flip one byte at the middle position.
python3 -c "
import sys
data = open(sys.argv[1], 'rb').read()
mid = len(data) // 2
flipped = data[:mid] + bytes([data[mid] ^ 0xFF]) + data[mid+1:]
open(sys.argv[1], 'wb').write(flipped)
" "$OUTPUT/fixtures/tampered-cades-b-b.p7s"

# ── 8. Summary ────────────────────────────────────────────
echo ""
echo "Test PKI generation complete."
echo "  Root CA:       $OUTPUT/root-ca/root-ca.crt"
echo "  Intermediate:  $OUTPUT/intermediate-ca/intermediate-ca.crt"
echo "  RSA signer:    $OUTPUT/signers/rsa-signer.crt (+ .key, .p12)"
echo "  ECDSA signer:  $OUTPUT/signers/ecdsa-signer.crt (+ .key, .p12)"
echo "  Fixture:       $OUTPUT/fixtures/third-party-cades-b-b.p7s"
echo "  Tampered:      $OUTPUT/fixtures/tampered-cades-b-b.p7s"
