#!/usr/bin/env bash
# Regenerates the test PKI and the third-party CAdES B-B fixture next to this script.
# Everything here is fictitious; no test uses a real certificate.
set -euo pipefail

cd "$(dirname "$0")"

DAYS=36500
P12_PASSWORD=rades
SUBJECT_BASE="/O=rades test"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

rm -f ./*.crt ./*.key ./*.p12 ./*.der ./content.txt

ca_ext() {
  printf 'basicConstraints=critical,CA:TRUE,pathlen:%s\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$1"
}

signer_ext() {
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,nonRepudiation,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
}

issue() { # name common-name extensions parent
  local name=$1 cn=$2 ext=$3 parent=$4
  printf '%s\n' "$ext" >"$work/$name.ext"
  openssl req -new -key "$name.key" -subj "$SUBJECT_BASE/CN=$cn" -out "$work/$name.csr"
  openssl x509 -req -in "$work/$name.csr" -CA "$parent.crt" -CAkey "$parent.key" \
    -CAcreateserial -CAserial "$work/serial" -sha384 -days "$DAYS" \
    -extfile "$work/$name.ext" -out "$name.crt" 2>/dev/null
}

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out root.key 2>/dev/null
openssl req -new -x509 -key root.key -sha384 -days "$DAYS" \
  -subj "$SUBJECT_BASE/CN=rades test root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out root.crt

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out intermediate.key 2>/dev/null
issue intermediate "rades test intermediate CA" "$(ca_ext 0)" root

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signer-rsa.key 2>/dev/null
issue signer-rsa "rades test signer RSA" "$(signer_ext)" intermediate

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out signer-ecdsa.key 2>/dev/null
issue signer-ecdsa "rades test signer ECDSA" "$(signer_ext)" intermediate

cat intermediate.crt root.crt >"$work/chain.pem"

for signer in signer-rsa signer-ecdsa; do
  openssl pkcs12 -export -inkey "$signer.key" -in "$signer.crt" \
    -certfile "$work/chain.pem" -name "$signer" \
    -passout "pass:$P12_PASSWORD" -out "$signer.p12"
done

for signer in signer-rsa signer-ecdsa; do
  openssl verify -x509_strict -CAfile root.crt -untrusted intermediate.crt "$signer.crt" >/dev/null ||
    { echo "chain of $signer does not verify up to the root" >&2; exit 1; }
done

printf 'rades test content\n' >content.txt
openssl cms -sign -binary -cades -md sha256 -nodetach -outform DER \
  -in content.txt -signer signer-rsa.crt -inkey signer-rsa.key \
  -certfile "$work/chain.pem" -out cades-bb.p7m

openssl cms -verify -binary -inform DER -in cades-bb.p7m -CAfile root.crt -out /dev/null 2>/dev/null ||
  { echo "the CAdES B-B fixture does not verify" >&2; exit 1; }

offset=$(LC_ALL=C grep -obUa 'rades test content' cades-bb.p7m | cut -d: -f1 | head -n1)
cp cades-bb.p7m cades-bb-tampered.p7m
printf 'X' | dd of=cades-bb-tampered.p7m bs=1 seek="$offset" conv=notrunc 2>/dev/null

if openssl cms -verify -binary -inform DER -in cades-bb-tampered.p7m -CAfile root.crt -out /dev/null 2>/dev/null; then
  echo "the tampered fixture still verifies" >&2
  exit 1
fi

echo "test PKI and CAdES B-B fixture regenerated"
