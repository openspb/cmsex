# Security

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" tab, "Report a vulnerability"). You should get
an answer within a week. Fixes are released for the latest minor version.

## Threat model

The library is meant to read messages from anyone: a signature that comes
with a document, an encrypted file from a partner, a certificate bundle
from a server. The attacker controls every byte of the message and wants:

* a forged or changed message accepted as valid;
* the result to name the wrong signer, or to cover other content than the
  one the caller holds;
* a weaker algorithm than the signer used;
* to learn the content of an encrypted message, or the key of a recipient,
  from how decryption fails;
* to stop or slow down the process: CPU, memory, atoms.

Out of the model: an attacker who holds the private key of a signer or of a
recipient, or who chooses the roots given to `:trust`; and flaws of the
OpenSSL that `:crypto` uses, which does the operations with private keys.

When it writes, the input comes from the application and is trusted; the
section on writing below covers what the written message protects.

### Malformed input

* Every function returns `{:error, %Cmsex.Error{}}` for any message it
  cannot read, and does not raise on malformed input. The fuzz tests feed
  changed and random messages to every reader, to decryption and MACs with
  each kind of credentials, and to every function that changes a message,
  to check that.
* Parsing is bounded. `:max_depth` (32) limits the nesting of the encoding,
  `:max_elements` (100,000) the elements at all levels, `:max_signers` (64),
  `:max_certificates` (256), `:max_attributes` (64) and `:max_recipients`
  (64) what the message may hold. Every length is checked against the input
  before it is read, and nothing is allocated from a declared length.
* Nothing from the message becomes an atom. Unknown algorithms, attributes
  and content types are reported by their OID, as a tuple.
* The memory used is the input and what the caller walks through. The
  content and the certificates of the result are parts of the input binary,
  which they keep alive: copy them with `:binary.copy/1` to keep a small
  part of a large message. Bound the size of the messages you accept; the
  library does not.

### Signatures

* A valid signature is not trust. Without `:trust`, `{:ok, verified}` only
  says that the key of a certificate signed the content, and that
  certificate may have come in the message itself, from the attacker. With
  `:trust`, each signer needs a path to one of the roots, validated by
  `:public_key.pkix_path_validation/3` at the current time, and a key usage,
  if any, that allows digitalSignature or nonRepudiation.
* By default every signer must verify (`signers: :all`), so a message with
  one valid signer and one forged is refused. A message without signers,
  such as a certificate bundle, is `:no_signers`, never a success.
* Algorithm substitution: the CMSAlgorithmProtection attribute (RFC 6211)
  is written by default, and checked when present; a combined signature
  OID must name the digest algorithm of the signer; the parameters of
  RSASSA-PSS must match those of a PSS key (RFC 4056).
* SHA-1 is refused unless `allow_sha1: true`, since collisions with a
  chosen prefix are practical; it is never used to sign. MD5 is always
  refused. RSA keys shorter than `:min_rsa_bits` (2048) are refused.
* Content confusion: content given for a message that carries its own is
  `:unexpected_content`, and the result holds the content that was
  verified, never another. The content-type attribute is checked against
  the type of the content, so that a time-stamp token, for example, is not
  taken as plain data.
* When several certificates match the identifier of a signer, as a forged
  one with the issuer and serial number of the real one, each is tried, and
  the result names the one that verified.
* The RSA signature check is the one of `:crypto`, which compares the whole
  encoding of the DigestInfo. The negative corpus has a forgery for e = 3
  with garbage after the DigestInfo, which must fail.
* The signing-time attribute is what the signer claims. It is returned as
  such, and never used as the time of the path validation.
* Unsigned attributes, countersignatures and time-stamps among them, are
  not covered by the signature: anyone can add, remove or change them.
  Countersignatures are verified only with `countersignatures: true`;
  time-stamp tokens are not verified by this library.

### Decryption

* **Uniform errors.** Everything that depends on a secret fails with the
  same `:decryption_failed`: a wrong key, a key wrap whose integrity check
  fails, a CBC padding or a tag that does not check, a changed message.
  What does not depend on a secret is told apart: a malformed message, an
  unsupported algorithm, a limit, no recipient for the credentials given.
* **RSA PKCS #1 v1.5.** The library reads this key transport and never
  writes it. A padding that does not check gives a random key of the
  expected size, as RFC 3218, 2.3 asks, so the failure comes from the
  content, as with a good padding of a wrong key, and in about the same
  time. The test suite checks both: the error, and the times, against the
  time saved by stopping at the padding. The padding is checked with masks,
  over every byte, rather than with branches; the BEAM gives no guarantee
  of constant time, which is why the times are measured. With the key in an
  HSM, given as a function, a padding that does not check should give
  `:error`, which becomes a random key too; how long the HSM takes to say
  so is up to it.
* **CBC has no integrity.** An EnvelopedData or EncryptedData with
  AES-CBC, the default because every reader knows it, can be changed: a
  changed IV changes the first block of the content in a way the attacker
  chooses, and other changes decrypt to garbage instead of failing. The
  library gives no padding oracle, but an application that reacts
  differently to the garbage, such as by failing to parse it, may become
  one. Use an authenticated cipher, which makes an AuthEnvelopedData where
  any change fails, or sign the content.
* **No origin.** Anyone who has the certificate of a recipient can encrypt
  to it, so a message that decrypts says nothing about who sent it. Sign
  the content when that matters.
* **Passwords.** The sender chooses the PBKDF2 iteration count, so
  `Cmsex.decrypt/2` refuses more than `:max_iterations` (2,000,000) before
  any derivation. Whoever has a message encrypted to a password can try
  passwords offline, as fast as PBKDF2 allows; the library writes 600,000
  iterations of HMAC-SHA-256 by default, as recent guidance asks, but only
  a long random password protects such a message well.
* **Key agreement.** The public key of the sender must be on the curve of
  the recipient, and an X25519 or X448 shared secret of zeros, from a key
  of low order, is refused (RFC 7748, 6).
* What is not protected: the unprotected attributes of an EnvelopedData,
  the unauthenticated attributes of an AuthEnvelopedData, the identifiers
  of the recipients and of shared keys, and the certificates of the
  OriginatorInfo, which are not validated.

### MACs

* An AuthenticatedData MAC shows that the content comes from someone who
  had the MAC key, and nothing more. With a shared key or a password, that
  is someone who holds it; with a certificate as the recipient, RSA or
  ephemeral ECDH, anyone who has the certificate can write such a message
  (RFC 5652, 14). Sign the content to show who wrote it.
* The MAC is compared in constant time, with `:crypto.hash_equals/2`, and a
  MAC that does not check gives the same `:invalid_mac` as a key that does
  not unwrap. A MAC key shorter than 16 bytes is not taken.
* A DigestedData shows that the content was not changed by accident.
  Whoever changes the content can write a new digest.

### Secrets in memory

* `inspect/1` leaves out the key of `Cmsex.Signer`, the key and the
  password of `Cmsex.Recipient`, and the content of `Cmsex.Decrypted`.
  Neither a `Cmsex.Error` nor the message of an `ArgumentError` shows key
  material, a password or the content: an argument of the wrong kind is
  named by its kind only.
* Keys, passwords and decrypted content are binaries like any other. The
  BEAM copies binaries and frees them when the garbage collector decides;
  there is no way to wipe them. Keep them in as few processes as possible,
  and do not log the results with tools that bypass `inspect/1`.
* A key given as a function stays where it is, in an HSM, a token or a
  KMS; only the digest to sign, or the value to decrypt, goes to it.

### Side channels

The operations with private keys run in `:crypto`, on OpenSSL. MACs,
digests and the integrity checks of the key wraps are compared with
`:crypto.hash_equals/2`. The AES key wrap
(RFC 3394, RFC 5649), the key wraps of RFC 3211 and RFC 3217 and the
PKCS #1 v1.5 padding check are written in Elixir over `:crypto`, with the
care above, but without any guarantee of constant time.

### What the library does not check

* Revocation. Give a `:verify_fun` in `:path_validation` to check CRLs or
  OCSP.
* Extended key usage and certificate policies of a signer, which depend on
  the application; `:path_validation` takes them too.
* Time-stamps, and so when a signature was made: the time is the current
  one, and the signing-time attribute is a claim.
* What the content means, such as the MIME structure of S/MIME.

### Writing

* Content-encryption keys, MAC keys, IVs, nonces, salts and ephemeral keys
  come from `:crypto.strong_rand_bytes/1` and `:crypto.generate_key/2`,
  the random generator of OpenSSL. Each message has a new
  content-encryption key, so a random GCM nonce is never used twice with
  the same key.
* It never writes SHA-1, MD5, RSA PKCS #1 v1.5 key transport, Triple-DES or
  RC2, and signs with RSA keys of at least `:min_rsa_bits`.
* The library checks that the private key of a signer is the key of its
  certificate, not that the certificate is valid or trusted. A signature
  made by a function is verified against the certificate before the
  message is written, unless `verify_signature: false`, so that a faulty
  HSM or KMS does not produce messages that do not verify.
* `Cmsex.encrypt_with_key/3` uses the key it is given, for as many
  messages as the caller wants, with a new IV for each. `Cmsex.Recipient.kek/3`
  with `Cmsex.encrypt/3` is often the better choice: a new key for each
  message, an authenticated cipher if wanted, and the identifier of the key
  in the message.
* As when reading, keys and passwords are binaries in the memory of the
  calling process, which the BEAM cannot wipe.
