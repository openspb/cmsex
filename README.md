# Cmsex

[![Hex.pm](https://img.shields.io/hexpm/v/cmsex.svg)](https://hex.pm/packages/cmsex)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/cmsex)
[![CI](https://github.com/openspb/cmsex/actions/workflows/ci.yml/badge.svg)](https://github.com/openspb/cmsex/actions/workflows/ci.yml)

Signs, verifies, encrypts and decrypts CMS messages (RFC 5652) in pure
Elixir: the `.p7s` signatures, `.p7m` encrypted files and `.p7b` certificate
bundles of S/MIME, signed documents and many other systems.

* **No NIF and no `openssl` binary.** Everything runs on top of `:crypto` and
  `:public_key`, which come with OTP.
* **Signatures.** RSA (PKCS #1 v1.5 and PSS), ECDSA on the NIST and
  brainpool curves, Ed25519 and Ed448; the content inside the message or
  detached, and read as a stream; signers checked against the roots you
  trust; more signers, countersignatures and time-stamps added without
  breaking the signatures already there.
* **Encryption.** EnvelopedData and AuthEnvelopedData for certificates
  (RSA-OAEP, ECDH, X25519, X448), shared keys and passwords, with AES-CBC,
  AES-GCM, AES-CCM or ChaCha20-Poly1305. EncryptedData, DigestedData and
  AuthenticatedData too.
* **Checked against other implementations.** The test suite has OpenSSL,
  LibreSSL, GnuTLS and Java's `jarsigner` verify what it signs, and OpenSSL
  decrypt what it encrypts; it reads what they and Python's `cryptography`
  write, and the examples of RFC 4134 and RFC 9216.
* **Safe with untrusted input.** Bounded parsing, no atoms made from the
  input, SHA-1 and short RSA keys refused by default, decryption errors that
  tell nothing about the secrets (RFC 3218), and no key or password in
  `inspect/1` or in error messages.

> **Status: v0.1.** The API is expected to stay, but may still change
> before 1.0.

## Installation

```elixir
def deps do
  [{:cmsex, "~> 0.1"}]
end
```

Elixir 1.16 or later, OTP 26 or later. No other dependencies.

## Usage

The examples use the keys and certificates of RFC 9216, which anyone can
use for tests: Alice and Bob, under a sample RSA certification authority.
They run as a test of the project, in this order.

### Signing

```elixir
alice = %{certificate: File.read!("alice.crt"), key: File.read!("alice.key")}
pdf = File.read!("contract.pdf")

{:ok, p7s} = Cmsex.sign(pdf, alice, detached: true)
File.write!("contract.pdf.p7s", p7s)
```

The certificate is X.509 in DER. The key is PKCS #8, PKCS #1 or SEC 1 in
DER, or a key record of `:public_key`. From PEM files:

```elixir
[{:Certificate, certificate, _}] = :public_key.pem_decode(File.read!("alice.pem"))
[{:PrivateKeyInfo, key, _}] = :public_key.pem_decode(File.read!("alice.key.pem"))
alice = %{certificate: certificate, key: key}
```

And from a `.pfx` file, with the [pkcs12](https://hex.pm/packages/pkcs12)
package:

```elixir
p12 = PKCS12.decode!(File.read!("alice.pfx"), "password")
alice = %{certificate: p12.certificate, key: p12.private_key, chain: p12.ca_certificates}
```

`:chain` holds the intermediate certificates, which go in the message with
the signer's own. The defaults are SHA-256, PKCS #1 v1.5 for RSA, and signed
attributes with the signing time and the CMSAlgorithmProtection attribute
(RFC 6211), which binds the algorithms to the signature. A list of signers
signs with each. The options choose PSS, another hash, the subject key
identifier, more attributes, or none at all: see `Cmsex.sign/3` and
`Cmsex.Signer`. The message is DER; `Cmsex.PEM.encode/2` makes it PEM.

### Verifying

```elixir
root = File.read!("ca.crt")

case Cmsex.verify(File.read!("contract.pdf.p7s"), content: pdf, trust: [root]) do
  {:ok, %Cmsex.Verified{signers: [signer]}} -> signer.certificate
  {:error, %Cmsex.Error{reason: :digest_mismatch}} -> raise "the document changed"
  {:error, %Cmsex.Error{reason: :untrusted}} -> raise "not signed by anyone we trust"
  {:error, error} -> raise error
end
```

Every function that takes a message takes it in DER, BER or PEM. Errors come
as `{:error, %Cmsex.Error{reason: reason}}`, and the bang variants, such as
`Cmsex.verify!/2`, raise them; `Cmsex.Error` lists the reasons. By default
every signer must verify; `signers: :any` needs one, and
`Cmsex.verify_each/2` gives the result of each.

### Trust

A valid signature is not trust. Without `:trust`, `{:ok, verified}` only
says that the key of a certificate signed the content, and that certificate
may have come in the message itself, from anyone. With `:trust`, the path
from each signer to one of the roots is built from the certificates of the
message and of the `:certificates` option, and validated by
`:public_key.pkix_path_validation/3` at the current time. The key usage of
the signer must allow signatures.

```elixir
{:ok, verified} = Cmsex.verify(p7s, content: pdf, trust: [root])
[%{certificate: certificate, path: [^root, certificate], signing_time: time}] = verified.signers
```

Two things are left to the application:

* **Revocation.** The library does not fetch CRLs or ask OCSP responders.
  `:path_validation` takes the options of `:public_key.pkix_path_validation/3`,
  such as a `:verify_fun` that checks revocation.
* **Time.** The signing time is what the signer claims, never the time at
  which the path is validated. A signature that must outlive its
  certificate needs a time-stamp from a time-stamping authority
  (RFC 3161), checked on its own.

### Large content

```elixir
stream = File.stream!("backup.tar", 1_048_576)
{:ok, p7s} = Cmsex.sign({:stream, stream}, alice)
{:ok, _verified} = Cmsex.verify(p7s, content: {:stream, stream})
```

A stream is read once, in its chunks, for all the digests, and makes a
detached message. A digest computed elsewhere goes as
`{:digest, :sha256, digest}`. EdDSA without signed attributes signs the
whole content, so it needs the content in memory.

### Certificate bundles

```elixir
{:ok, p7b} = Cmsex.certs_only([alice.certificate, root])
File.write!("chain.p7b", Cmsex.PEM.encode(p7b, :pkcs7))

{:ok, [_alice, _root]} = Cmsex.certificates(File.read!("chain.p7b"))
```

`Cmsex.certificates/2` also gives the certificates of a signed message.

### More signers, countersignatures and time-stamps

```elixir
bob = %{certificate: File.read!("bob.crt"), key: File.read!("bob.key")}
{:ok, p7s} = Cmsex.sign(pdf, alice, detached: true)

# Bob signs the same document
{:ok, p7s} = Cmsex.add_signer(p7s, bob, content: pdf)

# and countersigns the signature of Alice, the first signer
{:ok, p7s} = Cmsex.countersign(p7s, 0, bob)

{:ok, %{signers: [%{countersignatures: [_bob]}, _bob_signer]}} =
  Cmsex.verify(p7s, content: pdf, trust: [root], countersignatures: true)
```

These functions keep the bytes of everything they do not change, so every
signature of the message still verifies, here and in other tools, and the
positions of the signers stay the same. A time-stamp goes in the same way,
as an unsigned attribute over the signature value:

```elixir
{:ok, %Cmsex.SignedData{signer_infos: [alice_info | _]}} = Cmsex.decode(p7s)
token = MyApp.TSA.time_stamp(Cmsex.SignerInfo.signature(alice_info))

attribute = Cmsex.Attribute.new(:time_stamp_token, [token])
{:ok, p7s} = Cmsex.add_unsigned_attribute(p7s, 0, attribute)
```

### Keys in an HSM or a KMS

The key of a signer can be a function, called with what to sign:

```elixir
alice = %{
  certificate: File.read!("alice.crt"),
  key: fn %{digest: digest} -> MyApp.KMS.sign("alice", digest) end
}

{:ok, _p7s} = Cmsex.sign(pdf, alice)
```

It gets the digest, the hash and the scheme, and returns
`{:ok, signature}`; the signature is checked against the certificate before
the message is written. `Cmsex.decrypt/2` takes a function as the key too.
See `Cmsex.Signer`.

### Encrypting

```elixir
bob_encryption = File.read!("bob-encryption.crt")
{:ok, p7m} = Cmsex.encrypt(pdf, bob_encryption, cipher: :aes256_gcm)

credentials = [key: File.read!("bob-encryption.key"), certificate: bob_encryption]
{:ok, %Cmsex.Decrypted{content: ^pdf}} = Cmsex.decrypt(p7m, credentials)
```

A message can have many recipients, of three kinds: the holder of a
certificate, with RSA-OAEP for an RSA key and ephemeral-static ECDH for an
EC, X25519 or X448 key; whoever holds a key shared by other means; and
whoever knows a password.

```elixir
backup_key = :crypto.strong_rand_bytes(32)

recipients = [
  bob_encryption,
  Cmsex.Recipient.kek(backup_key, "backup key 2026"),
  Cmsex.Recipient.password("correct horse battery staple")
]

{:ok, p7m} = Cmsex.encrypt(pdf, recipients, cipher: :aes256_gcm)

{:ok, %{content: ^pdf}} = Cmsex.decrypt(p7m, kek: {"backup key 2026", backup_key})
{:ok, %{content: ^pdf}} = Cmsex.decrypt(p7m, password: "correct horse battery staple")
```

The default cipher is AES-256-CBC, in an EnvelopedData, because every
reader of CMS knows it. CBC has no integrity check: a changed message can
decrypt to garbage instead of failing. An authenticated cipher, such as
`:aes256_gcm`, makes an AuthEnvelopedData (RFC 5083), where any change
fails; use it when the recipients can read it, or sign the content.

Whatever goes wrong with the secrets, a wrong key, a key that does not
unwrap, a padding or a tag that does not check, gives the same
`:decryption_failed`, on purpose. The content to encrypt is a binary.

### Digests and MACs

```elixir
{:ok, digested} = Cmsex.digest(pdf)
{:ok, %Cmsex.DigestedData{content: ^pdf}} = Cmsex.verify_digest(digested)

mac_key = :crypto.strong_rand_bytes(32)
{:ok, authenticated} = Cmsex.mac(pdf, Cmsex.Recipient.kek(mac_key, "partner key 1"))
{:ok, %Cmsex.Authenticated{content: ^pdf}} =
  Cmsex.verify_mac(authenticated, kek: {"partner key 1", mac_key})
```

A digest only shows that the content was not changed by accident: whoever
changes it can write a new digest. A MAC shows that the content comes from
someone who had the MAC key. With a shared key or a password, that is
someone who holds it; with a certificate as the recipient, it is anyone who
has the certificate. To show who wrote the content, sign it.

### Messages from untrusted sources

The input of `verify/2`, `decrypt/2`, `decode/2` and the others can come
from anyone. Parsing is bounded: the depth of the encoding, the number of
elements, signers, certificates, attributes and recipients have limits,
which the options lower:

```elixir
{:ok, _verified} =
  Cmsex.verify(p7s,
    content: pdf,
    trust: [root],
    max_elements: 10_000,
    max_certificates: 16,
    max_signers: 4
  )
```

A password recipient sets its own PBKDF2 iteration count, so
`Cmsex.decrypt/2` refuses more than `:max_iterations` (2,000,000, about a
quarter of a second on a laptop). Bound the size of the messages you
accept, and put a timeout around the call. See [SECURITY.md](SECURITY.md)
for the threat model.

`Cmsex.decode/2` reads a message without verifying or decrypting it, and
returns its structure: `Cmsex.SignedData`, `Cmsex.EnvelopedData`,
`Cmsex.EncryptedData`, `Cmsex.DigestedData` or `Cmsex.AuthenticatedData`.

## What it reads

| | |
|---|---|
| Signatures | RSA PKCS #1 v1.5 (rsaEncryption and the combined OIDs), RSASSA-PSS (RFC 4056), ECDSA on P-256, P-384, P-521 and the brainpool curves, Ed25519 and Ed448 (RFC 8419) |
| Digests | SHA-224, SHA-256, SHA-384, SHA-512, SHAKE256 for Ed448, and SHA-1 with `allow_sha1: true`; never MD5 |
| Signed data | content inside or detached, with or without signed attributes, signers by issuer and serial number or by subject key identifier, countersignatures, certificate bundles, and the PKCS #7 messages whose content is not an OCTET STRING |
| Attributes | content-type, message-digest, signing-time, CMSAlgorithmProtection (RFC 6211), signing-certificate and signing-certificate-v2 (RFC 5035), countersignature; the others come as `Cmsex.Attribute` |
| Content encryption | AES-128/192/256 in CBC (RFC 3565), GCM and CCM (RFC 5084), ChaCha20-Poly1305 (RFC 8103), Triple-DES, and RC2 when `:crypto` has it |
| Recipients | RSAES-OAEP (RFC 3560) and RSA PKCS #1 v1.5; ephemeral-static ECDH on the NIST and brainpool curves (RFC 5753), X25519 and X448 (RFC 8418), with the KDF of ANSI X9.63 or HKDF; shared keys with AES key wrap (RFC 3394, RFC 5649) or the Triple-DES and RC2 key wraps (RFC 3217); passwords with PBKDF2 (RFC 3211) |
| Digests and MACs | DigestedData; AuthenticatedData with HMAC-SHA-1 to HMAC-SHA-512, with and without authenticated attributes |
| Encoding | DER and BER (indefinite lengths, segmented strings, as `openssl cms -stream` writes); PEM with the `CMS` or the `PKCS7` label |

Not supported: DSA signatures (`:unsupported_algorithm`), compressed data
(RFC 3274), KEMRecipientInfo (RFC 9629) and OtherRecipientInfo.

The fixtures of the test suite are messages signed by OpenSSL 3, LibreSSL,
GnuTLS, Python's `cryptography` and Java's `jarsigner`, and encrypted by
OpenSSL 3, LibreSSL and Python, for each algorithm they write; the examples
of RFC 4134; and a negative corpus of changed and malformed messages, each
with the error it must give. CI runs it on OTP 26 to 29, and on an OpenSSL 3
without the legacy provider.

## What it writes

| | Default | Options |
|---|---|---|
| SignedData | SHA-256; RSA PKCS #1 v1.5, ECDSA, Ed25519 with SHA-512 and Ed448 with SHAKE256 (RFC 8419); content-type, message-digest, signing-time and CMSAlgorithmProtection attributes; issuer and serial number | RSASSA-PSS, SHA-224/384/512, subject key identifier, more attributes, no signing time, no attributes, detached |
| EnvelopedData | AES-256-CBC; RSA-OAEP with SHA-256; ECDH with the X9.63 KDF of the size of the curve, X25519 and X448 with HKDF, and AES key wrap; shared keys with AES key wrap; passwords with PBKDF2-HMAC-SHA-256, 600,000 iterations, and AES-256 | AES-128/192-CBC, the OAEP hash, the KDF and the key wrap, AES key wrap with padding, the iterations |
| AuthEnvelopedData | with an authenticated cipher: AES-GCM, AES-CCM or ChaCha20-Poly1305, and a tag of 16 bytes | the tag size, authenticated attributes |
| EncryptedData | AES-256-CBC, with a key you give | AES-128/192-CBC |
| DigestedData | SHA-256 | SHA-224/384/512 |
| AuthenticatedData | HMAC-SHA-256 | HMAC-SHA-224/384/512, authenticated attributes |

It never writes SHA-1 or MD5, RSA PKCS #1 v1.5 key transport (RFC 3218),
Triple-DES or RC2. The output is DER, with the versions of RFC 5652, and
random keys, IVs and salts from `:crypto.strong_rand_bytes/1`.

The test suite has other implementations read what it writes. OpenSSL 3,
LibreSSL and GnuTLS's `certtool` verify its signatures with each algorithm,
inside and detached, with both identifiers, with and without signed
attributes, with one and two signers, and after `add_signer/3`,
`countersign/4` and `add_unsigned_attribute/4`; `jarsigner` verifies them as
the signatures of JAR files. What they do not verify:

* LibreSSL 3.3, that of macOS: EdDSA.
* OpenSSL: Ed25519 without signed attributes, and Ed448 at all.
* GnuTLS: Ed448 with signed attributes.
* `jarsigner`: signers identified by subject key identifier.

OpenSSL 3 decrypts what it encrypts, except X25519 and X448, which OpenSSL
does not decrypt even from its own messages, the HKDF of RFC 8418, AES key
wrap with padding for a shared key, AES-CCM, ChaCha20-Poly1305, and AES-GCM
with a 12-byte tag. LibreSSL has neither ECDH nor AuthEnvelopedData. Python's
`cryptography` decrypts only RSA PKCS #1 v1.5, which Cmsex does not write.

## Performance

On an Apple M-series laptop, OTP 27 with OpenSSL 3.6, the median of many
calls (`mix run bench/sign.exs`, `bench/verify.exs` and `bench/encrypt.exs`).

Signing and verifying 1 KiB:

| Algorithm | Sign | Verify | Verify with `:trust` |
|---|---|---|---|
| RSA-2048 | 0.87 ms | 0.061 ms | 0.19 ms |
| RSA-3072 | 2.2 ms | 0.083 ms | 0.21 ms |
| P-256 | 0.074 ms | 0.096 ms | 0.24 ms |
| P-384 | 0.31 ms | 0.35 ms | 0.49 ms |
| Ed25519 | 0.12 ms | 0.12 ms | 0.26 ms |
| Ed448 | 0.21 ms | 0.18 ms | 0.32 ms |

A message with three signers (RSA-2048, P-256 and Ed25519) and ten
certificates verifies in 0.36 ms, and in 0.79 ms with `:trust`. Reading the
RSA-2048 message with `decode/2` takes 0.017 ms; reading and the checks take
about as long as the RSA operation itself (0.025 ms), and with the other
algorithms, and with a path to validate, the public-key operations take most
of the time.

A 100 MiB stream signs and verifies in 46 ms with P-256, in chunks of
64 KiB or of 1 MiB alike: the time of SHA-256.

Encrypting and decrypting 1 KiB:

| Recipient | Encrypt | Decrypt |
|---|---|---|
| RSA-2048, OAEP | 0.050 ms | 0.87 ms |
| RSA-3072, OAEP | 0.074 ms | 2.2 ms |
| P-256, ECDH | 0.11 ms | 0.11 ms |
| P-384, ECDH | 0.39 ms | 0.40 ms |
| X25519 | 0.13 ms | 0.12 ms |
| X448 | 0.29 ms | 0.28 ms |
| Shared key | 0.012 ms | 0.012 ms |
| Password, 600,000 iterations | 70 ms | 70 ms |

And 100 MiB, with a shared key:

| Cipher | Encrypt | Decrypt |
|---|---|---|
| AES-256-CBC | 105 ms | 18 ms |
| AES-256-GCM | 17 ms | 15 ms |
| AES-256-CCM | 125 ms | 124 ms |
| ChaCha20-Poly1305 | 60 ms | 58 ms |

CBC encrypts one block after the other, and decrypts them in parallel. An
HMAC-SHA-256 over a 100 MiB stream, with `mac/3` or `verify_mac/2`, takes
45 ms.

The work is in `:crypto`, on OpenSSL. The digests of a stream are updated
chunk by chunk, so each call stays short; PBKDF2 runs on a dirty scheduler.

## Development

```
mix test
mix precommit   # format, warnings, Credo and tests, before a commit
mix dialyzer
```

The fixtures are made by the project, and committed because CI does not
have every generator:

* `test/fixtures/generated`: keys and certificates, and messages signed by
  OpenSSL 3, LibreSSL, GnuTLS, Python and a JDK, made by
  `test/support/gen_fixtures.sh`;
* `test/fixtures/encrypted`: recipients, and messages encrypted by OpenSSL 3,
  LibreSSL, Python and Cmsex itself, made by `test/support/gen_encrypted.sh`;
* `test/fixtures/rfc4134` and `test/fixtures/rfc9216`: the examples of those
  RFCs, taken from their text by `test/support/extract_rfc4134.exs` and
  `test/support/extract_rfc9216.exs`.

The interop tests (`mix test --only interop`) run the tools they find on the
system and skip the others; `test/support/interop.ex` lists the variables
that point to them, and `CMSEX_REQUIRE_INTEROP` makes a missing one fail.
CI runs them with OpenSSL 3, GnuTLS, Python and a JDK. The fuzz tests run
with `mix test --only fuzz`, `FUZZ_ROUNDS` times (5,000 by default).

## References

* [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652), Cryptographic Message Syntax (CMS)
* [RFC 5083](https://www.rfc-editor.org/rfc/rfc5083), AuthEnvelopedData
* [RFC 3370](https://www.rfc-editor.org/rfc/rfc3370), [RFC 5754](https://www.rfc-editor.org/rfc/rfc5754), [RFC 3565](https://www.rfc-editor.org/rfc/rfc3565), [RFC 5084](https://www.rfc-editor.org/rfc/rfc5084), [RFC 8103](https://www.rfc-editor.org/rfc/rfc8103), algorithms in CMS
* [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055), [RFC 4056](https://www.rfc-editor.org/rfc/rfc4056), [RFC 3560](https://www.rfc-editor.org/rfc/rfc3560), RSASSA-PSS and RSAES-OAEP
* [RFC 5753](https://www.rfc-editor.org/rfc/rfc5753), [RFC 8418](https://www.rfc-editor.org/rfc/rfc8418), [RFC 8419](https://www.rfc-editor.org/rfc/rfc8419), elliptic curves, X25519, X448, Ed25519 and Ed448 in CMS
* [RFC 3211](https://www.rfc-editor.org/rfc/rfc3211), [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394), [RFC 5649](https://www.rfc-editor.org/rfc/rfc5649), [RFC 3217](https://www.rfc-editor.org/rfc/rfc3217), passwords and key wraps
* [RFC 6211](https://www.rfc-editor.org/rfc/rfc6211), CMSAlgorithmProtection
* [RFC 5035](https://www.rfc-editor.org/rfc/rfc5035), signing-certificate-v2
* [RFC 3218](https://www.rfc-editor.org/rfc/rfc3218), the million message attack on PKCS #1 v1.5
* [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161), time-stamps
* [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468), PEM
* [RFC 4134](https://www.rfc-editor.org/rfc/rfc4134) and [RFC 9216](https://www.rfc-editor.org/rfc/rfc9216), examples

## License

Apache-2.0: see the `LICENSE` and `NOTICE` files.
