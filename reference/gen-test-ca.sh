#!/usr/bin/env bash
# Test CA hiyerarşisi üretir: root → intermediate → leaf signer.
# Çıktı: reference/fixtures/test-chain.p12 (leaf + chain, şifre testpass)
#        reference/fixtures/test-chain-root.pem (trust anchor)
#
# Leaf'ta KeyUsage=digitalSignature+nonRepudiation, AIA (OCSP) + CDP.
# MA3 CAdES path validation'ı geçmek için tasarlanmış.
#
# Kullanım:
#   cd reference && bash gen-test-ca.sh

set -euo pipefail
cd "$(dirname "$0")/fixtures"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

PASS="testpass"

# ---- Root CA (self-signed) ----
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	-subj "/C=TR/O=tr-xades test/CN=tr-xades Test Root CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash" \
	-keyout "$TMP/root.key" -out "$TMP/root.crt" 2>/dev/null

# ---- Intermediate CA (root ile imzalı) ----
openssl req -newkey rsa:2048 -sha256 -nodes \
	-subj "/C=TR/O=tr-xades test/CN=tr-xades Test Intermediate CA" \
	-keyout "$TMP/int.key" -out "$TMP/int.csr" 2>/dev/null

cat > "$TMP/int.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in "$TMP/int.csr" -CA "$TMP/root.crt" -CAkey "$TMP/root.key" \
	-CAcreateserial -sha256 -days 1825 -extfile "$TMP/int.ext" \
	-out "$TMP/int.crt" 2>/dev/null

# ---- Leaf signer (intermediate ile imzalı) ----
openssl req -newkey rsa:2048 -sha256 -nodes \
	-subj "/C=TR/O=tr-xades test/CN=Test Signer" \
	-keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" 2>/dev/null

cat > "$TMP/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=clientAuth,emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
authorityInfoAccess=OCSP;URI:http://ocsp.example.test/ocsp
crlDistributionPoints=URI:http://crl.example.test/test.crl
EOF

openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/int.crt" -CAkey "$TMP/int.key" \
	-CAcreateserial -sha256 -days 1095 -extfile "$TMP/leaf.ext" \
	-out "$TMP/leaf.crt" 2>/dev/null

# ---- PFX paketi (leaf + chain, şifre testpass) ----
cat "$TMP/int.crt" "$TMP/root.crt" > "$TMP/chain.pem"

openssl pkcs12 -export -name "test-signer" \
	-in "$TMP/leaf.crt" -inkey "$TMP/leaf.key" \
	-certfile "$TMP/chain.pem" \
	-password "pass:$PASS" -out test-chain.p12 2>/dev/null

# Trust anchor (root) + okunabilir chain
cp "$TMP/root.crt" test-chain-root.pem
cat "$TMP/leaf.crt" "$TMP/int.crt" "$TMP/root.crt" > test-chain-full.pem

echo "done:"
echo "  reference/fixtures/test-chain.p12        (leaf+chain, şifre $PASS)"
echo "  reference/fixtures/test-chain-root.pem   (trust anchor)"
echo "  reference/fixtures/test-chain-full.pem   (okunabilir leaf→int→root)"
echo ""
openssl x509 -in "$TMP/leaf.crt" -noout -subject -issuer
