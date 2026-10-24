# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The first release.

### Added

- `Cmsex.decode/2`: reads any CMS message, in DER, BER or PEM, into the
  struct of its type, without verifying or decrypting it: `Cmsex.SignedData`,
  `Cmsex.EnvelopedData` (with AuthEnvelopedData), `Cmsex.EncryptedData`,
  `Cmsex.DigestedData` and `Cmsex.AuthenticatedData`.
- `Cmsex.certificates/2`: the certificates of a SignedData message, such as
  a `.p7b` bundle.
- `Cmsex.verify/2`: verifies the signers of a SignedData message, with the
  content inside, detached, as a stream or as a ready digest. RSA PKCS #1
  v1.5 and RSASSA-PSS, ECDSA on the NIST and brainpool curves, Ed25519 and
  Ed448. Signed attributes are checked: content-type, message-digest,
  CMSAlgorithmProtection, signing-certificate and signing-certificate-v2.
  `:trust` validates a path from each signer to the roots given, with the
  intermediate certificates of the message or of `:certificates`, and
  `:path_validation` passes options to `:public_key`. `signers: :any`
  takes one valid signer; `countersignatures: true` verifies the
  countersignatures too.
- `Cmsex.verify_each/2`, the result of each signer, and
  `Cmsex.verify_countersignature/3`, one countersignature on its own.
- `Cmsex.sign/3`: signs with one or more `Cmsex.Signer`, a key in DER, a
  key record of `:public_key`, or a function, for a key in an HSM or a KMS.
  The content inside or detached, a stream, or a ready digest; SHA-224 to
  SHA-512, PSS, the signer identified by issuer and serial number or by
  subject key identifier, more signed and unsigned attributes, no
  attributes at all.
- `Cmsex.certs_only/2`: a certificate bundle, with revocation lists.
- `Cmsex.add_signer/3`, `Cmsex.countersign/4` and
  `Cmsex.add_unsigned_attribute/4`: change a SignedData message without
  breaking the signatures already in it, such as to add a time-stamp
  token.
- `Cmsex.encrypt/3`: an EnvelopedData message, or an AuthEnvelopedData
  with an authenticated cipher, for any number of recipients
  (`Cmsex.Recipient`): certificates with RSA-OAEP, ECDH on the NIST and
  brainpool curves, X25519 and X448, with the KDF of X9.63 or HKDF; shared
  keys with AES key wrap, with or without padding; passwords with PBKDF2.
  AES-CBC, AES-GCM, AES-CCM and ChaCha20-Poly1305; unprotected and
  authenticated attributes.
- `Cmsex.encrypt_with_key/3`: an EncryptedData message, with a key the
  parties share.
- `Cmsex.decrypt/2`: decrypts EnvelopedData, AuthEnvelopedData and
  EncryptedData with a private key and its certificate, a shared key, a
  password or the content-encryption key. Reads RSA PKCS #1 v1.5 key
  transport, Triple-DES and RC2 too, and the Triple-DES and RC2 key wraps.
  Every failure that depends on a secret is `:decryption_failed`, and a
  PKCS #1 v1.5 padding that does not check is handled as RFC 3218 asks.
- `Cmsex.digest/2` and `Cmsex.verify_digest/2`: DigestedData.
- `Cmsex.mac/3` and `Cmsex.verify_mac/2`: AuthenticatedData with HMAC, with
  and without authenticated attributes, for the recipients of `encrypt/3`.
- Every function that writes a message has a `!` form that raises, and
  every reader takes DER, BER and PEM.
- `Cmsex.PEM`: PEM with the `CMS` and `PKCS7` labels.
- `Cmsex.Attribute`: builds and reads attributes, such as content-hint and
  signing-certificate-v2.
- `Cmsex.KeyWrap`: the AES key wrap of RFC 3394 and RFC 5649.
- `Cmsex.OID`: the names of the OIDs the library knows.
- `Cmsex.Error`: one exception for every error, with a reason, a detail
  and the signer it concerns.
- Limits on what a message may hold: `:max_depth`, `:max_elements`,
  `:max_signers`, `:max_certificates`, `:max_attributes`,
  `:max_recipients` and `:max_iterations`.
- SHA-1 is refused unless `allow_sha1: true`, MD5 always, and RSA keys
  shorter than `:min_rsa_bits` (2048).
