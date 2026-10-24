#!/usr/bin/env bash
# Generates the test material in test/fixtures/encrypted: a CA and
# recipients made with OpenSSL, and EnvelopedData, AuthEnvelopedData,
# EncryptedData and DigestedData messages written for them by OpenSSL 3,
# LibreSSL and Python (cryptography). Nothing comes from elsewhere.
#
# The signed material of test/fixtures/generated has its own script,
# gen_fixtures.sh, and stays as it is when this one runs. As there, the
# files are versioned; run again only to change the set, and update
# test/cmsex/encrypted_test.exs with it.
#
# The secrets of the messages, which the tests know too:
#   KEK and content keys  000102...0F (16 bytes), ...17 (24), ...1F (32)
#   KEK identifier        "cmsex kek"
#   password              "cmsex password"
#
# Tools, all overridable:
#   O3   OpenSSL 3.x, with its legacy provider for RC2
#   LRE  LibreSSL (the openssl of macOS)
#   PY   Python 3 with the "cryptography" package
set -euo pipefail

O3=${O3:-/opt/homebrew/opt/openssl@3/bin/openssl}
LRE=${LRE:-/usr/bin/openssl}
PY=${PY:-python3}

out="$(cd "$(dirname "$0")/../fixtures" && pwd)/encrypted"
rm -rf "$out"
mkdir -p "$out"
cd "$out"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

K16=000102030405060708090A0B0C0D0E0F
K24=${K16}1011121314151617
K32=${K16}101112131415161718191A1B1C1D1E1F
KID=$(printf 'cmsex kek' | xxd -p)
PASSWORD="cmsex password"

# The content of every message, as in test/fixtures/generated.
printf 'Cmsex test content\r\nsecond line\nlast line \xc3\xa7\xc3\xa3o\r\n' > content.txt

cat > "$work/ext.cnf" <<'EOF'
[transport]
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[agreement]
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyAgreement
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF

$O3 genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
  -out "$work/ca.key"
$O3 req -x509 -key "$work/ca.key" -out ca.crt -days 7300 -subj "/O=Cmsex/CN=Cmsex Encryption CA" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign

# recipient NAME KEY_KIND EXTENSIONS
recipient() {
  local name=$1 kind=$2 ext=$3
  case $kind in
    rsa*) $O3 genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${kind#rsa}" -out "$name.key" 2>/dev/null ;;
    *) $O3 genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$kind" -pkeyopt ec_param_enc:named_curve \
      -out "$name.key" ;;
  esac
  $O3 req -new -key "$name.key" -subj "/O=Cmsex/CN=Cmsex Recipient $name" -out "$work/$name.csr"
  $O3 x509 -req -in "$work/$name.csr" -CA ca.crt -CAkey "$work/ca.key" -out "$name.crt" \
    -days 7300 -extfile "$work/ext.cnf" -extensions "$ext" 2>/dev/null
}

recipient rsa2048 rsa2048 transport
recipient rsa3072 rsa3072 transport
recipient p256 P-256 agreement
recipient p384 P-384 agreement
recipient p521 P-521 agreement
recipient bp256 brainpoolP256r1 agreement
recipient bp384 brainpoolP384r1 agreement

# message NAME TOOL OPERATION ARGS...: a message of content.txt, in binary
# mode and DER.
message() {
  local name=$1 tool=$2 operation=$3
  shift 3
  $tool cms "$operation" -binary -in content.txt -outform DER -out "$name.p7m" "$@"
}

o3() { message "o3_$1" "$O3" -encrypt "${@:2}"; }
oaep() { echo -keyopt rsa_padding_mode:oaep; }

# OpenSSL 3: PKCS #1 v1.5 unless told otherwise, and the X9.63 KDF with
# SHA-1 for ECDH.
o3 rsa_v15 -aes256 rsa2048.crt
o3 rsa_v15_aes128 -aes128 rsa2048.crt
o3 rsa_v15_aes192 -aes192 rsa2048.crt
o3 rsa_v15_des3 -des3 rsa2048.crt
o3 rsa_v15_rc2_40 -rc2-40-cbc -provider legacy -provider default rsa2048.crt
o3 rsa_v15_rc2_128 -rc2-cbc -provider legacy -provider default rsa2048.crt
o3 rsa_keyid -aes128 -keyid rsa2048.crt
o3 rsa_oaep -aes128 -recip rsa2048.crt $(oaep)
o3 rsa_oaep_sha256 -aes128 -recip rsa2048.crt $(oaep) -keyopt rsa_oaep_md:sha256 \
  -keyopt rsa_mgf1_md:sha256
o3 rsa_oaep_sha512 -aes256 -recip rsa2048.crt $(oaep) -keyopt rsa_oaep_md:sha512 \
  -keyopt rsa_mgf1_md:sha512
o3 rsa_oaep_mixed -aes128 -recip rsa2048.crt $(oaep) -keyopt rsa_oaep_md:sha384 \
  -keyopt rsa_mgf1_md:sha1
o3 rsa_oaep_label -aes128 -recip rsa2048.crt $(oaep) -keyopt rsa_oaep_label:636d736578
o3 rsa_oaep_keyid -aes128 -keyid -recip rsa2048.crt $(oaep)
o3 rsa_gcm128 -aes-128-gcm rsa2048.crt
o3 rsa_gcm192 -aes-192-gcm rsa2048.crt
o3 rsa_gcm256 -aes-256-gcm rsa2048.crt
# Indefinite lengths, and the ciphertext in segments.
o3 rsa_stream -aes128 -stream rsa2048.crt
o3 rsa_stream_gcm -aes-256-gcm -stream rsa2048.crt
o3 p256 -aes128 p256.crt
o3 p256_keyid -aes128 -keyid p256.crt
o3 p256_sha224kdf -aes128 -recip p256.crt -keyopt ecdh_kdf_md:sha224
o3 p256_sha256kdf -aes128 -recip p256.crt -keyopt ecdh_kdf_md:sha256
o3 p256_cofactor -aes128 -recip p256.crt -keyopt ecdh_cofactor_mode:1
o3 p256_wrap256 -aes128 -aes256-wrap p256.crt
o3 p256_gcm -aes-256-gcm p256.crt
# The Triple-DES key wrap of RFC 3217 carries a Triple-DES key. OpenSSL
# also wraps an AES key with it, which that RFC does not define.
o3 p256_des3_wrap -des3 -des3-wrap p256.crt
o3 p256_des3_wrap_aes -aes128 -des3-wrap p256.crt
o3 p384_sha384kdf -aes256 -recip p384.crt -keyopt ecdh_kdf_md:sha384
o3 p521_sha512kdf -aes256 -recip p521.crt -keyopt ecdh_kdf_md:sha512
o3 bp256 -aes128 bp256.crt
o3 bp384_sha384kdf -aes256 -recip bp384.crt -keyopt ecdh_kdf_md:sha384
o3 kek128 -aes128 -secretkey $K16 -secretkeyid "$KID"
o3 kek192 -aes128 -secretkey $K24 -secretkeyid "$KID"
o3 kek256 -aes256 -secretkey $K32 -secretkeyid "$KID"
o3 kek_gcm -aes-128-gcm -secretkey $K16 -secretkeyid "$KID"
# PBKDF2 with HMAC-SHA1 and 2048 iterations; the key wrap with the cipher
# of the content, or -kekcipher.
o3 pwri -aes256 -pwri_password "$PASSWORD"
o3 pwri_kek_aes128 -aes256 -pwri_password "$PASSWORD" -kekcipher aes-128-cbc
o3 pwri_kek_des3 -aes256 -pwri_password "$PASSWORD" -kekcipher des-ede3-cbc
o3 pwri_gcm -aes-256-gcm -pwri_password "$PASSWORD" -kekcipher aes-256-cbc
o3 mixed -aes256 -secretkey $K16 -secretkeyid "$KID" -pwri_password "$PASSWORD" rsa2048.crt \
  p256.crt p384.crt
$O3 smime -encrypt -binary -in content.txt -outform DER -out o3_pkcs7.p7m -aes128 rsa2048.crt
message o3_encrypted128 "$O3" -EncryptedData_encrypt -aes128 -secretkey $K16
message o3_encrypted256 "$O3" -EncryptedData_encrypt -aes256 -secretkey $K32
message o3_encrypted_des3 "$O3" -EncryptedData_encrypt -des3 -secretkey $K24
message o3_digest_sha256 "$O3" -digest_create -md sha256
message o3_digest_sha512 "$O3" -digest_create -md sha512
message o3_digest_sha1 "$O3" -digest_create -md sha1
message o3_digest_stream "$O3" -digest_create -md sha384 -stream

# LibreSSL: no ECDH, and no AuthEnvelopedData. Given AES-GCM, it writes an
# EnvelopedData with a bare IV of zeros as the parameters and no
# ciphertext, which it does not decrypt itself.
lre() { message "lre_$1" "$LRE" -encrypt "${@:2}"; }

lre rsa_v15 -aes128 rsa2048.crt
lre rsa_v15_des3 -des3 rsa2048.crt
lre rsa_oaep -aes256 -recip rsa2048.crt $(oaep)
lre rsa_stream -aes128 -stream rsa2048.crt
lre rsa_gcm -aes-256-gcm rsa2048.crt
lre kek -aes128 -secretkey $K16 -secretkeyid "$KID"
lre pwri -aes256 -pwri_password "$PASSWORD"
message lre_encrypted "$LRE" -EncryptedData_encrypt -aes128 -secretkey $K16
message lre_digest "$LRE" -digest_create -md sha256

# Python cryptography: PKCS #1 v1.5 and AES-CBC, the only ones it writes.
$PY -I - <<'EOF'
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import pkcs7

data = open("content.txt", "rb").read()


def certificate(name):
    return x509.load_pem_x509_certificate(open(name + ".crt", "rb").read())


def encrypt(out, recipients, cipher):
    builder = pkcs7.PKCS7EnvelopeBuilder().set_data(data)
    for name in recipients:
        builder = builder.add_recipient(certificate(name))
    builder = builder.set_content_encryption_algorithm(cipher)
    der = builder.encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    open(out + ".p7m", "wb").write(der)


encrypt("py_aes128", ["rsa2048"], algorithms.AES128)
encrypt("py_aes256", ["rsa2048"], algorithms.AES256)
encrypt("py_two", ["rsa3072", "rsa2048"], algorithms.AES128)
EOF

cat > INFO.txt <<EOF
Made by test/support/gen_encrypted.sh on $(date -u +%Y-%m-%d), with:

  $($O3 version)
  $($LRE version)
  $($PY -I -c 'import cryptography; print("Python cryptography", cryptography.__version__)')
EOF

echo "fixtures written to $out"
