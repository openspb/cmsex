#!/usr/bin/env bash
# Generates the test material in test/fixtures/generated: keys and
# certificates made with OpenSSL, and CMS messages written by OpenSSL 3,
# LibreSSL, GnuTLS, Python (cryptography) and Java (jarsigner) with them.
# Nothing comes from elsewhere.
#
# The generated files are versioned, because the generators are not all
# available in CI. Run again only to change the set; every key, certificate
# and message changes with it, and test/cmsex/generated_test.exs may need
# its expectations updated.
#
# Tools, all overridable:
#   O3        OpenSSL 3.x
#   LRE       LibreSSL (the openssl of macOS)
#   CERTTOOL  certtool of GnuTLS (gnutls-certtool on macOS)
#   PY        Python 3 with the "cryptography" package
#   JDK_BIN   the bin directory of a JDK, 17 or later (jar, jarsigner, keytool)
set -euo pipefail

O3=${O3:-/opt/homebrew/opt/openssl@3/bin/openssl}
LRE=${LRE:-/usr/bin/openssl}
CERTTOOL=${CERTTOOL:-/opt/homebrew/bin/gnutls-certtool}
PY=${PY:-python3}
JDK_BIN=${JDK_BIN:-/opt/homebrew/opt/openjdk/bin}

out="$(cd "$(dirname "$0")/../fixtures" && pwd)/generated"
rm -rf "$out"
mkdir -p "$out"
cd "$out"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The content of every message: text with CRLF, a bare LF and bytes that
# are not ASCII, so that a tool that changes line endings shows.
printf 'Cmsex test content\r\nsecond line\nlast line \xc3\xa7\xc3\xa3o\r\n' > content.txt

cat > "$work/ext.cnf" <<'EOF'
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[noski]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
subjectKeyIdentifier=none
authorityKeyIdentifier=none
EOF

# A config whose names come out as PrintableString, not UTF8String.
cat > "$work/printable.cnf" <<'EOF'
[req]
distinguished_name=dn
string_mask=default
prompt=no
[dn]
O=Cmsex
CN=Cmsex Printable CA
EOF

genkey() {
  case $2 in
    rsapss)
      $O3 genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 \
        -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 \
        -pkeyopt rsa_pss_keygen_saltlen:32 -out "$1" 2>/dev/null
      ;;
    rsa*) $O3 genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${2#rsa}" -out "$1" 2>/dev/null ;;
    P-*) $O3 genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -pkeyopt ec_param_enc:named_curve -out "$1" ;;
    ed25519 | ed448) $O3 genpkey -algorithm "$2" -out "$1" ;;
  esac
}

# The CAs: an RSA-3072 one for most leaves, one with a name in UTF8String
# that is not ASCII and one with a name in PrintableString.
genkey "$work/ca.key" rsa3072
$O3 req -x509 -key "$work/ca.key" -out ca.crt -days 7300 -subj "/O=Cmsex/CN=Cmsex Test CA" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
genkey "$work/ca_utf8.key" P-256
$O3 req -x509 -utf8 -key "$work/ca_utf8.key" -out ca_utf8.crt -days 7300 \
  -subj "/O=Cmsex/CN=Autoridade de Teste Ção" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
genkey "$work/ca_printable.key" P-256
$O3 req -x509 -config "$work/printable.cnf" -key "$work/ca_printable.key" -out ca_printable.crt \
  -days 7300 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign

# leaf NAME KEY_KIND [CA [EXTENSIONS [x509 options...]]]
leaf() {
  local name=$1 kind=$2 ca=${3:-ca} ext=${4:-leaf}
  shift $(($# < 4 ? $# : 4))
  genkey "$name.key" "$kind"
  $O3 req -new -utf8 -key "$name.key" -subj "/O=Cmsex/CN=Cmsex Test $name" -out "$work/$name.csr"
  $O3 x509 -req -in "$work/$name.csr" -CA "$ca.crt" -CAkey "$work/$ca.key" -out "$name.crt" \
    -days 7300 -extfile "$work/ext.cnf" -extensions "$ext" "$@" 2>/dev/null
}

leaf rsa2048 rsa2048
leaf rsa3072 rsa3072
leaf rsa1024 rsa1024
leaf rsapss rsapss
leaf p256 P-256
leaf p384 P-384
leaf p521 P-521
leaf ed25519 ed25519
leaf ed448 ed448
leaf noski P-256 ca noski
leaf serial20 P-256 ca leaf -set_serial 0xF1E2D3C4B5A6978869504132231405F6E7D8C9BA
leaf utf8 P-256 ca_utf8
leaf printable P-256 ca_printable

# An empty CRL of the CA, for a certs-only message with a CRL.
touch "$work/index.txt"
echo 01 > "$work/crlnumber"
cat > "$work/crl.cnf" <<EOF
[ca]
default_ca=d
[d]
database=$work/index.txt
crlnumber=$work/crlnumber
default_md=sha256
default_crl_days=7300
EOF
$O3 ca -gencrl -config "$work/crl.cnf" -keyfile "$work/ca.key" -cert ca.crt -out "$work/ca.crl" 2>/dev/null
$O3 crl -in "$work/ca.crl" -outform DER -out ca.crl

# OpenSSL 3. Every message is signed in binary mode, over content.txt.
o3() {
  local out=$1 signer=$2
  shift 2
  $O3 cms -sign -binary -in content.txt -signer "$signer.crt" -inkey "$signer.key" \
    -outform DER -out "$out.p7s" "$@"
}

o3 o3_rsa rsa2048 -nodetach
o3 o3_rsa_detached rsa2048
o3 o3_rsa_noattr rsa2048 -nodetach -noattr
o3 o3_rsa_nosmimecap rsa2048 -nodetach -nosmimecap
o3 o3_rsa_keyid rsa2048 -nodetach -keyid
o3 o3_rsa_sha384 rsa2048 -nodetach -md sha384
o3 o3_rsa_sha1 rsa2048 -nodetach -md sha1
o3 o3_rsa_nocerts rsa2048 -nodetach -nocerts
o3 o3_rsa_chain rsa2048 -nodetach -certfile ca.crt
o3 o3_rsa3072_sha512 rsa3072 -nodetach -md sha512
o3 o3_rsa1024 rsa1024 -nodetach
o3 o3_pss rsa2048 -nodetach -keyopt rsa_padding_mode:pss
o3 o3_pss_sha384_saltmax rsa2048 -nodetach -md sha384 -keyopt rsa_padding_mode:pss \
  -keyopt rsa_pss_saltlen:max
o3 o3_rsapss_key rsapss -nodetach -keyopt rsa_padding_mode:pss
# Without -keyopt, OpenSSL signs with the RSASSA-PSS key but names the
# signature rsaEncryption; it does not verify this message itself.
o3 o3_rsapss_key_pkcs1 rsapss -nodetach
o3 o3_p256 p256 -nodetach
o3 o3_p384 p384 -nodetach -md sha384
o3 o3_p521 p521 -nodetach -md sha512
# OpenSSL has no default digest for EdDSA. Out of RFC 8419: Ed25519 with
# SHA-256, and Ed448 with SHA-512 and with SHAKE256 without the length.
o3 o3_ed25519 ed25519 -nodetach -md sha512
o3 o3_ed25519_sha256 ed25519 -nodetach -md sha256
o3 o3_ed448_sha512 ed448 -nodetach -md sha512
o3 o3_ed448_shake256 ed448 -nodetach -md shake256
o3 o3_noski noski -nodetach
o3 o3_serial20 serial20 -nodetach
o3 o3_utf8 utf8 -nodetach
o3 o3_printable printable -nodetach
# Indefinite lengths. With -stream and DER, the content is always inside.
o3 o3_stream rsa2048 -nodetach -stream
o3 o3_two_signers rsa2048 -nodetach -signer p256.crt -inkey p256.key
$O3 cms -resign -binary -inform DER -in o3_rsa.p7s -signer p256.crt -inkey p256.key -nodetach \
  -outform DER -out o3_resign.p7s
$O3 smime -sign -binary -nodetach -in content.txt -signer rsa2048.crt -inkey rsa2048.key \
  -outform DER -out o3_pkcs7.p7s
$O3 crl2pkcs7 -nocrl -certfile rsa2048.crt -certfile ca.crt -outform DER -out o3_certs_only.p7c
$O3 crl2pkcs7 -in ca.crl -inform DER -certfile ca.crt -outform DER -out o3_certs_crl.p7c

# LibreSSL
lre() {
  local out=$1 signer=$2
  shift 2
  $LRE cms -sign -binary -in content.txt -signer "$signer.crt" -inkey "$signer.key" \
    -outform DER -out "$out.p7s" "$@"
}

lre lre_rsa rsa2048 -nodetach
lre lre_rsa_detached rsa2048
lre lre_rsa_noattr rsa2048 -nodetach -noattr
lre lre_rsa_keyid rsa2048 -nodetach -keyid
lre lre_rsa_sha512 rsa2048 -nodetach -md sha512
# LibreSSL signs ECDSA with SHA-1 unless told otherwise.
lre lre_p256 p256 -nodetach
lre lre_p256_sha256 p256 -nodetach -md sha256
lre lre_stream rsa2048 -nodetach -stream
$LRE smime -sign -binary -nodetach -in content.txt -signer rsa2048.crt -inkey rsa2048.key \
  -outform DER -out lre_pkcs7.p7s

# GnuTLS: no signed attributes, unless --p7-time.
gt() {
  local out=$1 signer=$2
  shift 2
  $CERTTOOL --p7-sign --load-privkey "$signer.key" --load-certificate "$signer.crt" \
    --infile content.txt --outder --outfile "$out.p7s" "$@" >/dev/null 2>&1
}

gt gt_rsa rsa2048
gt gt_rsa_time rsa2048 --p7-time
gt gt_rsa_sha384 rsa2048 --p7-time --hash SHA384
gt gt_rsapss_key rsapss --p7-time
gt gt_p256 p256
gt gt_p384_time p384 --p7-time --hash SHA384
gt gt_ed25519 ed25519
gt gt_ed25519_time ed25519 --p7-time
gt gt_ed448 ed448
$CERTTOOL --p7-detached-sign --load-privkey rsa2048.key --load-certificate rsa2048.crt \
  --infile content.txt --outder --outfile gt_rsa_detached.p7s >/dev/null 2>&1

# Python cryptography: RSA, RSASSA-PSS and ECDSA, always in binary mode.
$PY -I - "$out" <<'EOF'
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs7

O = pkcs7.PKCS7Options
data = open("content.txt", "rb").read()


def signer(name):
    cert = x509.load_pem_x509_certificate(open(name + ".crt", "rb").read())
    key = serialization.load_pem_private_key(open(name + ".key", "rb").read(), None)
    return cert, key


def sign(out, signers, options=()):
    builder = pkcs7.PKCS7SignatureBuilder().set_data(data)
    for name, hash_algorithm, rsa_padding in signers:
        cert, key = signer(name)
        builder = builder.add_signer(cert, key, hash_algorithm, rsa_padding=rsa_padding)
    der = builder.sign(serialization.Encoding.DER, [O.Binary, *options])
    open(out + ".p7s", "wb").write(der)


pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
rsa = [("rsa2048", hashes.SHA256(), None)]
sign("py_rsa", rsa)
sign("py_rsa_nocap", rsa, [O.NoCapabilities])
sign("py_rsa_noattr", rsa, [O.NoAttributes])
sign("py_rsa_detached", rsa, [O.DetachedSignature])
sign("py_rsa_nocerts", rsa, [O.NoCerts])
sign("py_pss", [("rsa2048", hashes.SHA256(), pss)])
sign("py_p256", [("p256", hashes.SHA256(), None)])
sign("py_p384", [("p384", hashes.SHA384(), None)])
sign("py_two_signers", rsa + [("p256", hashes.SHA512(), None)])
EOF

# Java: a signed JAR keeps, in META-INF, a SignedData detached over the
# signature file (.SF). The keystores, made from the material above, stay
# for the interop tests, with a truststore of the CA; their password is
# "keystore".
for k in rsa2048 p256 ed25519 ed448; do
  $O3 pkcs12 -export -in "$k.crt" -inkey "$k.key" -certfile ca.crt -name signer \
    -out "keystore_$k.p12" -passout pass:keystore
done
"$JDK_BIN/keytool" -importcert -noprompt -alias ca -file ca.crt -keystore truststore.p12 \
  -storetype PKCS12 -storepass keystore >/dev/null 2>&1
mkdir "$work/jar"
cp content.txt "$work/jar/"
"$JDK_BIN/jar" --create --file "$work/app.jar" -C "$work/jar" content.txt
jsign() {
  local out=$1 signer=$2 ext=$3
  shift 3
  "$JDK_BIN/jarsigner" -keystore "keystore_$signer.p12" -storetype PKCS12 -storepass keystore \
    -signedjar "$work/$out.jar" "$@" "$work/app.jar" signer >/dev/null 2>&1
  mkdir "$work/$out"
  (cd "$work/$out" && "$JDK_BIN/jar" --extract --file "$work/$out.jar")
  cp "$work/$out/META-INF/SIGNER.SF" "$out.sf"
  cp "$work/$out/META-INF/SIGNER.$ext" "$out.p7s"
}

jsign java_rsa rsa2048 RSA
jsign java_pss rsa2048 RSA -sigalg RSASSA-PSS
jsign java_ec p256 EC
jsign java_ed25519 ed25519 EC
jsign java_ed448 ed448 EC

cat > INFO.txt <<EOF
Made by test/support/gen_fixtures.sh on $(date -u +%Y-%m-%d), with:

  $($O3 version)
  $($LRE version)
  $($CERTTOOL --version | head -1)
  $($PY -I -c 'import cryptography; print("Python cryptography", cryptography.__version__)')
  $("$JDK_BIN/jarsigner" -version 2>&1 | head -1)
EOF

echo "fixtures written to $out"
