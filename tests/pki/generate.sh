#!/usr/bin/env bash
# Creates whatever is missing of the test PKI and the third-party CAdES B-B fixture next to this script,
# keeping every existing key and certificate; `--fresh` deletes them all first.
# Everything here is fictitious; no test uses a real certificate.
set -euo pipefail

cd "$(dirname "$0")"

DAYS=36500
P12_PASSWORD=rades
SUBJECT_BASE="/O=rades test"

case "${1:-}" in
  "") ;;
  --fresh) rm -f ./*.crt ./*.key ./*.p12 ./*.p7m ./content.txt ;;
  *) echo "usage: $0 [--fresh]" >&2; exit 2 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ca_ext() {
  printf 'basicConstraints=critical,CA:TRUE,pathlen:%s\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$1"
}

signer_ext() {
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,nonRepudiation,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
}

key() { # name genpkey-options...
  local name=$1
  shift
  [[ -e "$name.key" ]] || openssl genpkey "$@" -out "$name.key" 2>/dev/null
}

issue() { # name common-name extensions parent
  local name=$1 cn=$2 ext=$3 parent=$4
  [[ -e "$name.crt" ]] && return
  printf '%s\n' "$ext" >"$work/$name.ext"
  openssl req -new -key "$name.key" -subj "$SUBJECT_BASE/CN=$cn" -out "$work/$name.csr"
  openssl x509 -req -in "$work/$name.csr" -CA "$parent.crt" -CAkey "$parent.key" \
    -CAcreateserial -CAserial "$work/serial" -sha384 -days "$DAYS" \
    -extfile "$work/$name.ext" -out "$name.crt" 2>/dev/null
}

key root -algorithm EC -pkeyopt ec_paramgen_curve:P-384
[[ -e root.crt ]] || openssl req -new -x509 -key root.key -sha384 -days "$DAYS" \
  -subj "$SUBJECT_BASE/CN=rades test root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out root.crt

key intermediate -algorithm EC -pkeyopt ec_paramgen_curve:P-384
issue intermediate "rades test intermediate CA" "$(ca_ext 0)" root

key signer-rsa -algorithm RSA -pkeyopt rsa_keygen_bits:3072
issue signer-rsa "rades test signer RSA" "$(signer_ext)" intermediate

key signer-ecdsa -algorithm EC -pkeyopt ec_paramgen_curve:P-256
issue signer-ecdsa "rades test signer ECDSA" "$(signer_ext)" intermediate

cat intermediate.crt root.crt >"$work/chain.pem"

for signer in signer-rsa signer-ecdsa; do
  [[ -e "$signer.p12" ]] || openssl pkcs12 -export -inkey "$signer.key" -in "$signer.crt" \
    -certfile "$work/chain.pem" -name "$signer" \
    -passout "pass:$P12_PASSWORD" -out "$signer.p12"
done

for signer in signer-rsa signer-ecdsa; do
  openssl verify -x509_strict -CAfile root.crt -untrusted intermediate.crt "$signer.crt" >/dev/null ||
    { echo "chain of $signer does not verify up to the root" >&2; exit 1; }
done

[[ -e content.txt ]] || printf 'rades test content\n' >content.txt
[[ -e cades-bb.p7m ]] || openssl cms -sign -binary -cades -md sha256 -nodetach -outform DER \
  -in content.txt -signer signer-rsa.crt -inkey signer-rsa.key \
  -certfile "$work/chain.pem" -out cades-bb.p7m

openssl cms -verify -binary -inform DER -in cades-bb.p7m -CAfile root.crt -out /dev/null 2>/dev/null ||
  { echo "the CAdES B-B fixture does not verify" >&2; exit 1; }

if [[ ! -e cades-bb-tampered.p7m ]]; then
  offset=$(LC_ALL=C grep -obUa 'rades test content' cades-bb.p7m | cut -d: -f1 | head -n1)
  cp cades-bb.p7m cades-bb-tampered.p7m
  printf 'X' | dd of=cades-bb-tampered.p7m bs=1 seek="$offset" conv=notrunc 2>/dev/null
fi

if openssl cms -verify -binary -inform DER -in cades-bb-tampered.p7m -CAfile root.crt -out /dev/null 2>/dev/null; then
  echo "the tampered fixture still verifies" >&2
  exit 1
fi

echo "test PKI and CAdES B-B fixture complete"
