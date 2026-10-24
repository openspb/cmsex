defmodule Cmsex do
  @moduledoc """
  Cryptographic Message Syntax (CMS, RFC 5652) in pure Elixir.
  """

  alias Cmsex.{
    Attribute,
    Authenticate,
    Authenticated,
    AuthenticatedData,
    Decrypt,
    Decrypted,
    DigestedData,
    Digesting,
    EncryptedData,
    Envelope,
    EnvelopedData,
    Error,
    Message,
    Options,
    PEM,
    Recipient,
    Sign,
    SignedData,
    Signer,
    Update,
    Verified,
    Verify
  }

  @decode_options Options.limits() ++ [:max_recipients]

  @verify_options Options.limits() ++
                    [
                      :content,
                      :certificates,
                      :signers,
                      :trust,
                      :path_validation,
                      :countersignatures,
                      :allow_sha1,
                      :min_rsa_bits,
                      :ed25519_digest
                    ]

  @doc """
  Reads a CMS message without verifying or decrypting it, for inspection
  and for the libraries built on this one. The message may be in DER, BER
  or PEM. Returns the struct of its type:

    * `Cmsex.SignedData` - signed content, or a certificate bundle;
    * `Cmsex.EnvelopedData` - encrypted content, for EnvelopedData and
      AuthEnvelopedData;
    * `Cmsex.EncryptedData` - content encrypted with a key managed by
      other means;
    * `Cmsex.DigestedData` - content with its digest;
    * `Cmsex.AuthenticatedData` - content with a MAC.

  Options, the limits on what the message may hold:

    * `:max_depth` - nesting of the encoding (32).
    * `:max_elements` - encoded elements at all levels (100,000).
    * `:max_signers` - signers, and countersignatures of one signer (64).
    * `:max_certificates` - certificates, and revocation lists (256).
    * `:max_attributes` - attributes in one set (64).
    * `:max_recipients` - recipients, and encrypted keys of one key
      agreement recipient (64).

  A ContentInfo of another type, such as a bare `:data`, gives
  `:unsupported_content_type`.
  """
  @spec decode(binary(), keyword()) ::
          {:ok,
           SignedData.t()
           | EnvelopedData.t()
           | EncryptedData.t()
           | DigestedData.t()
           | AuthenticatedData.t()}
          | {:error, Error.t()}
  def decode(cms, opts \\ []) do
    opts = Options.take!(opts, @decode_options)
    with {:ok, der} <- PEM.input(cms), do: Message.parse(der, opts)
  end

  @doc "Like `decode/2`, but raises `Cmsex.Error`."
  @spec decode!(binary(), keyword()) ::
          SignedData.t()
          | EnvelopedData.t()
          | EncryptedData.t()
          | DigestedData.t()
          | AuthenticatedData.t()
  def decode!(cms, opts \\ []) do
    case decode(cms, opts) do
      {:ok, message} -> message
      {:error, error} -> raise error
    end
  end

  @doc """
  The X.509 certificates of a SignedData message, in DER, in the order of
  the message: the certificates of a `.p7b` bundle, or those a signer
  included. Takes the options of `decode/2`.
  """
  @spec certificates(binary(), keyword()) :: {:ok, [binary()]} | {:error, Error.t()}
  def certificates(cms, opts \\ []) do
    opts = Options.take!(opts, Options.limits())

    with {:ok, der} <- PEM.input(cms),
         {:ok, signed_data} <- SignedData.parse(der, opts),
         do: {:ok, signed_data.certificates}
  end

  @doc "Like `certificates/2`, but raises `Cmsex.Error`."
  @spec certificates!(binary(), keyword()) :: [binary()]
  def certificates!(cms, opts \\ []) do
    case certificates(cms, opts) do
      {:ok, certificates} -> certificates
      {:error, error} -> raise error
    end
  end

  @doc """
  Verifies the signers of a SignedData message, in DER, BER or PEM.

  A valid signature is not trust. Without `:trust`, `{:ok, verified}` only
  says that the key of a certificate signed the content, and that
  certificate may have come in the message itself, from anyone. Give the
  roots you trust in `:trust` to know who signed.

  For each signer, the checks are those of RFC 5652, 5.6: a certificate
  that matches its identifier, from `:certificates` or from the message;
  algorithms that are allowed and agree with each other and with the key;
  the content-type, message-digest and CMSAlgorithmProtection attributes;
  the signing-certificate attributes, when present; the signature; and,
  with `:trust`, the certificate path. When several certificates match the
  identifier, each is tried, and the one that verified is returned.

  Options:

    * `:content` - the content of a detached message: a binary,
      `{:stream, enumerable}`, or `{:digest, hash, digest}`, already
      hashed. A stream is read once for all the digests, and once more
      only for an EdDSA signer without signed attributes, which signs the
      whole content and so needs it in memory; a digest is not enough for
      that signer (`:content_required`). Content given for a message that
      carries its own is `:unexpected_content`.
    * `:certificates` - certificates in DER to find the signers in, tried
      before those of the message (`[]`).
    * `:signers` - `:all` (the default) fails at the first signer that does
      not verify; `:any` needs one, and returns only those that verified.
    * `:trust` - root certificates in DER. The path of each signer is built
      from the certificates at hand and validated by
      `:public_key.pkix_path_validation/3`, at the current time; the
      signer's key usage, if any, must allow digitalSignature or
      nonRepudiation. A failure is `:untrusted`, with the reason in
      `detail`.
    * `:path_validation` - options for `:public_key.pkix_path_validation/3`,
      such as a `:verify_fun` that checks revocation (`[]`).
    * `:countersignatures` - also verify the countersignatures of each
      signer (`false`).
    * `:allow_sha1` - accept SHA-1 (`false`). MD5 is never accepted.
    * `:min_rsa_bits` - the shortest RSA key accepted (2048).
    * `:ed25519_digest` - `:lenient` (the default) accepts an Ed25519 signer
      whose digest algorithm is a SHA-2 other than SHA-512, and says so in
      its `:deviations`; `:strict` refuses it.
    * the limits of `decode/2`.

  The signing-time attribute is returned as the signer's claim; it is never
  the time at which the path is validated.
  """
  @spec verify(binary(), keyword()) :: {:ok, Verified.t()} | {:error, Error.t()}
  def verify(cms, opts \\ []) do
    opts = Options.take!(opts, @verify_options)
    with {:ok, der} <- PEM.input(cms), do: Verify.verify(der, opts)
  end

  @doc "Like `verify/2`, but raises `Cmsex.Error`."
  @spec verify!(binary(), keyword()) :: Verified.t()
  def verify!(cms, opts \\ []) do
    case verify(cms, opts) do
      {:ok, verified} -> verified
      {:error, error} -> raise error
    end
  end

  @doc """
  The result of each signer, rather than the first failure. Takes the
  options of `verify/2`, except `:signers`.

      {:ok, signed_data, [{signer_info, {:ok, signer}}, {signer_info, {:error, error}}]}

  An error that is not about one signer, such as a malformed message, a
  missing content or a message without signers, is returned as
  `{:error, error}`.
  """
  @spec verify_each(binary(), keyword()) ::
          {:ok, SignedData.t(),
           [{Cmsex.SignerInfo.t(), {:ok, Verified.signer()} | {:error, Error.t()}}]}
          | {:error, Error.t()}
  def verify_each(cms, opts \\ []) do
    opts = Options.take!(opts, @verify_options -- [:signers])
    with {:ok, der} <- PEM.input(cms), do: Verify.verify_each(der, opts)
  end

  @doc """
  Verifies one countersignature (RFC 5652, 11.4) on its own: the one at
  `position`, such as `[0, 0]` for the first countersignature of the first
  signer (see `t:position/0`), against the signature value of the
  SignerInfo it countersigns, which is not verified here.

  This is for a countersignature whose signer cannot be verified, such as
  one in an algorithm the library leaves out, or when only the
  countersignature matters. `verify/2` with `countersignatures: true`
  checks the signers and their countersignatures together.

  Returns the countersigner as in `t:Cmsex.Verified.signer/0`. Takes the
  options of `verify/2`, except `:content` and `:signers`; with
  `countersignatures: true`, the countersignatures below this one are
  verified too. A position the message does not have raises
  `ArgumentError`.
  """
  @spec verify_countersignature(binary(), [non_neg_integer(), ...], keyword()) ::
          {:ok, Verified.signer()} | {:error, Error.t()}
  def verify_countersignature(cms, position, opts \\ []) do
    unless match?([_, _ | _], position) and Enum.all?(position, &(is_integer(&1) and &1 >= 0)),
      do:
        raise(
          ArgumentError,
          "expected the position of a countersignature, a list of two or more integers, " <>
            "got: #{inspect(position)}"
        )

    opts = Options.take!(opts, @verify_options -- [:content, :signers])

    with {:ok, der} <- PEM.input(cms),
         do: Verify.verify_countersignature(der, position, opts)
  end

  @doc """
  Signs `content` and returns a SignedData message in DER (use
  `Cmsex.PEM.encode/2` for PEM).

  `signers` is one signer or a list of them, each a `Cmsex.Signer`, or a
  map or keyword list with its fields: at least the certificate and the
  private key.

      signer = %{certificate: cert_der, key: key_der, chain: [ca_der]}
      {:ok, cms} = Cmsex.sign(content, signer)
      {:ok, p7s} = Cmsex.sign(content, signer, detached: true)

  The content is a binary, `{:stream, enumerable}` read once to compute the
  digests, or `{:digest, hash, digest}` already computed, which every
  signer must use. A stream or a digest makes a detached message with
  signed attributes.

  Each signer gets the content-type and message-digest attributes, the
  signing time and the CMSAlgorithmProtection attribute (RFC 6211) unless
  turned off, and its own attributes; see `Cmsex.Signer`. The algorithms
  are checked with the policy of `verify/2`, and SHA-1 is never used.

  Options:

    * `:detached` - leave the content out of the message (`false` for a
      binary; a stream or a digest is always detached).
    * `:content_type` - the type of the content (`:data`), a name of
      `Cmsex.OID` or an OID tuple. Another type needs signed attributes.
    * `:no_attributes` - sign without signed attributes (`false`): only
      for id-data given as a binary, and only for a verifier that cannot
      read them, since nothing then binds the algorithms or the time.
    * `:certificates` - `:signers` (the certificate and `:chain` of each
      signer, the default), `:none`, or a list of DER certificates.
    * `:crls` - revocation lists in DER (`[]`).
    * `:min_rsa_bits` - the shortest RSA key accepted (2048).
    * `:digest`, `:rsa_padding`, `:identifier`, `:signing_time` and
      `:algorithm_protection` - defaults for the signers that leave them
      out; see `Cmsex.Signer`.

  The versions are those of RFC 5652, 5.1 and 5.3. Errors that belong to
  one signer carry its position in `:signer`.
  """
  @spec sign(
          binary() | {:stream, Enumerable.t()} | {:digest, atom(), binary()},
          Signer.t() | map() | keyword() | [Signer.t() | map() | keyword()],
          keyword()
        ) :: {:ok, binary()} | {:error, Error.t()}
  def sign(content, signers, opts \\ []), do: Sign.sign(content, signers, opts)

  @doc "Like `sign/3`, but raises `Cmsex.Error`."
  @spec sign!(
          binary() | {:stream, Enumerable.t()} | {:digest, atom(), binary()},
          Signer.t() | map() | keyword() | [Signer.t() | map() | keyword()],
          keyword()
        ) :: binary()
  def sign!(content, signers, opts \\ []) do
    case sign(content, signers, opts) do
      {:ok, cms} -> cms
      {:error, error} -> raise error
    end
  end

  @doc """
  A SignedData message with certificates and revocation lists and no
  signers (RFC 5652, 5.2), as in a `.p7b` file: version 1, no digest
  algorithms, id-data without content. Takes the option `:crls`, a list of
  DER revocation lists.

  Other tools read a `.p7b` in PEM mostly with the `PKCS7` label:
  `Cmsex.PEM.encode(p7b, :pkcs7)`. `certificates/2` reads it back.
  """
  @spec certs_only([binary()], keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def certs_only(certificates, opts \\ []), do: Sign.certs_only(certificates, opts)

  @doc "Like `certs_only/2`, but raises `Cmsex.Error`."
  @spec certs_only!([binary()], keyword()) :: binary()
  def certs_only!(certificates, opts \\ []) do
    case certs_only(certificates, opts) do
      {:ok, p7b} -> p7b
      {:error, error} -> raise error
    end
  end

  ## Encryption

  @doc """
  Encrypts `content`, a binary, for `recipients`, and returns an
  EnvelopedData message in DER, or an AuthEnvelopedData (RFC 5083) when the
  cipher is an authenticated one, such as AES-GCM.

  `recipients` is one recipient or a list of them, each a
  `Cmsex.Recipient` or a certificate in DER, which is taken as
  `Cmsex.Recipient.certificate/2` with the defaults: RSA-OAEP for an RSA
  key, ephemeral-static ECDH for an EC key, X25519 or X448.

      {:ok, cms} = Cmsex.encrypt(content, alice_cert_der)

      {:ok, cms} =
        Cmsex.encrypt(content, [
          alice_cert_der,
          Cmsex.Recipient.kek(shared_key, "backup key 1"),
          Cmsex.Recipient.password("correct horse battery staple")
        ], cipher: :aes256_gcm)

  The content-encryption key is random, new for each message, and wrapped
  for each recipient. Every recipient is checked before anything is
  encrypted; an error that belongs to one carries its position in
  `:recipient`. A certificate whose keyUsage does not allow
  keyEncipherment (RSA) or keyAgreement (the others) is
  `:invalid_recipient` with detail `:key_usage`; a key that cannot encrypt,
  such as Ed25519 or RSASSA-PSS, is `:invalid_recipient` with `:key_type`.

  Options:

    * `:cipher` - `:aes256_cbc` (the default), `:aes128_cbc` or
      `:aes192_cbc` for EnvelopedData (RFC 3565); `:aes128_gcm`,
      `:aes192_gcm`, `:aes256_gcm`, the same with `_ccm` (RFC 5084), or
      `:chacha20_poly1305` (RFC 8103) for AuthEnvelopedData.
    * `:tag_size` - the size of the tag of an authenticated cipher, in
      bytes (16): 12 to 16 for GCM, an even number from 4 to 16 for CCM,
      16 for ChaCha20-Poly1305.
    * `:content_type` - the type of the content (`:data`), a name of
      `Cmsex.OID` or an OID tuple.
    * `:detached` - leave the encrypted content out of the message
      (`false`); the result is then `{:ok, {cms, encrypted_content}}`, and
      `decrypt/2` takes the encrypted content in `:content`.
    * `:unprotected_attributes` - a list of `Cmsex.Attribute` that nothing
      protects: the unprotectedAttrs of EnvelopedData, the unauthAttrs of
      AuthEnvelopedData (`[]`).
    * `:authenticated_attributes` - for an authenticated cipher, a list of
      `Cmsex.Attribute` that the tag covers (`[]`). The content-type
      attribute is written by the library, with them or for a content type
      other than `:data`; the message-digest attribute is not written
      (RFC 5083, 2.1).
    * `:certificates` and `:crls` - certificates and revocation lists in
      DER for the OriginatorInfo (`[]`).
    * `:min_rsa_bits` - the shortest RSA key accepted (2048).

  The versions are those of RFC 5652, 6.1 and of the RecipientInfos.
  """
  @spec encrypt(binary(), Recipient.t() | binary() | [Recipient.t() | binary()], keyword()) ::
          {:ok, binary() | {binary(), binary()}} | {:error, Error.t()}
  def encrypt(content, recipients, opts \\ []), do: Envelope.encrypt(content, recipients, opts)

  @doc "Like `encrypt/3`, but raises `Cmsex.Error`."
  @spec encrypt!(binary(), Recipient.t() | binary() | [Recipient.t() | binary()], keyword()) ::
          binary() | {binary(), binary()}
  def encrypt!(content, recipients, opts \\ []) do
    case encrypt(content, recipients, opts) do
      {:ok, cms} -> cms
      {:error, error} -> raise error
    end
  end

  @doc """
  Encrypts `content` with `key`, a content-encryption key the parties
  manage by other means, and returns an EncryptedData message in DER
  (RFC 5652, 8). There are no recipients, and nothing in the message says
  which key it is: `decrypt/2` takes it in `:content_key`.

  Options: `:cipher`, a CBC one, as in `encrypt/3` (`:aes256_cbc`), since
  EncryptedData has no place for a tag; `:content_type`; `:detached`; and
  `:unprotected_attributes`. A key that is not of the size of the cipher
  raises `ArgumentError`.

  To share a key for many messages, `Cmsex.Recipient.kek/3` with
  `encrypt/3` is often the better choice: a new key for each message,
  with an authenticated cipher if wanted, and the identifier of the key in
  the message.
  """
  @spec encrypt_with_key(binary(), binary(), keyword()) ::
          {:ok, binary() | {binary(), binary()}}
  def encrypt_with_key(content, key, opts \\ []),
    do: Envelope.encrypt_with_key(content, key, opts)

  @doc "Like `encrypt_with_key/3`, but returns the message alone."
  @spec encrypt_with_key!(binary(), binary(), keyword()) :: binary() | {binary(), binary()}
  def encrypt_with_key!(content, key, opts \\ []) do
    {:ok, cms} = encrypt_with_key(content, key, opts)
    cms
  end

  @doc """
  Decrypts an EnvelopedData, AuthEnvelopedData or EncryptedData message,
  in DER, BER or PEM.

      {:ok, %Cmsex.Decrypted{content: content}} =
        Cmsex.decrypt(cms, key: key_der, certificate: cert_der)

      {:ok, decrypted} = Cmsex.decrypt(cms, password: "correct horse battery staple")

  The credentials, one or more of:

    * `:key` and `:certificate` - a private key and its certificate, in
      DER (PKCS #8, PKCS #1 or SEC 1 for the key, which may also be a key
      record of `:public_key`). The certificate finds the recipient: a
      KeyTransRecipientInfo for RSA, a KeyAgreeRecipientInfo for EC, X25519
      and X448, by issuer and serial number or subject key identifier. The
      key may also be a function of one argument, for a key kept in an
      HSM, which gets a map and returns `{:ok, bytes}` or `{:error, term}`:
        * `%{operation: :decrypt, padding: :oaep, ciphertext:, hash:,
          mgf_hash:, label:}` - RSAES-OAEP decryption;
        * `%{operation: :decrypt, padding: :pkcs1, ciphertext:}` - RSA
          PKCS #1 v1.5 decryption, which should itself follow RFC 3218;
        * `%{operation: :agree, curve:, public_key:}` - the ECDH, X25519 or
          X448 shared secret with the public key of the sender.
    * `:kek` - `{key_identifier, key}`, for a KEKRecipientInfo with that
      identifier.
    * `:password` - for a PasswordRecipientInfo, taken as bytes.
    * `:content_key` - the content-encryption key itself: the key of an
      EncryptedData, or of any message, which skips the recipients.

  The recipients that the credentials name are tried in the order of the
  message, and the first that gives a key decrypts the content. Errors:

    * `:invalid_key`, `:invalid_certificate` and
      `:key_certificate_mismatch` - for the credentials.
    * `:recipient_not_found` - no recipient for the credentials.
    * `:unsupported_algorithm`, `:not_available`, `:malformed`, or
      `:limit_exceeded` with detail `:max_iterations` - what can be told
      without the secrets.
    * `:decryption_failed` - anything else: a wrong key, a key wrap, a
      padding or a tag that does not check, a message that was changed.
      Nothing tells these apart, on purpose. For RSA PKCS #1 v1.5, which
      the library reads but never writes, a padding that does not check
      gives a random key, so that the failure comes from the content, as
      RFC 3218 asks.
    * `:content_required` and `:unexpected_content` - as in `verify/2`.
    * for AuthEnvelopedData, `:missing_attribute`, `:invalid_attribute`
      and `:content_type_mismatch`, about the content-type attribute,
      once the tag has checked.

  EnvelopedData and EncryptedData use CBC, which has no integrity check: a
  changed ciphertext, or rarely a wrong key, can decrypt to garbage rather
  than fail. AuthEnvelopedData detects both; sign the content, or use an
  authenticated cipher, when that matters.

  Other options:

    * `:content` - the encrypted content of a detached message, a binary.
    * `:max_iterations` - the most PBKDF2 iterations accepted for a
      password (2,000,000), since the sender chooses them.
    * the limits of `decode/2`.

  Without any credentials, `ArgumentError`.
  """
  @spec decrypt(binary(), keyword()) :: {:ok, Decrypted.t()} | {:error, Error.t()}
  def decrypt(cms, opts \\ []), do: Decrypt.decrypt(cms, opts)

  @doc "Like `decrypt/2`, but raises `Cmsex.Error`."
  @spec decrypt!(binary(), keyword()) :: Decrypted.t()
  def decrypt!(cms, opts \\ []) do
    case decrypt(cms, opts) do
      {:ok, decrypted} -> decrypted
      {:error, error} -> raise error
    end
  end

  ## Digests and MACs

  @doc """
  Returns a DigestedData message in DER (RFC 5652, 7): `content` and its
  digest.

      {:ok, cms} = Cmsex.digest(content)
      {:ok, %Cmsex.DigestedData{content: ^content}} = Cmsex.verify_digest(cms)

  A digest shows that the content was not changed by accident, and
  nothing more: whoever changes the content can write a new digest. To
  show who wrote it, sign it, or use `mac/3`.

  The content is a binary, `{:stream, enumerable}` read once, or
  `{:digest, hash, digest}` already computed; a stream or a digest makes
  a detached message.

  Options:

    * `:digest` - `:sha256` (the default), `:sha224`, `:sha384` or
      `:sha512`. A ready digest gives its own hash.
    * `:content_type` - the type of the content (`:data`), a name of
      `Cmsex.OID` or an OID tuple.
    * `:detached` - leave the content out of the message (`false` for a
      binary).

  The version is 0 for `:data` and 2 for another type (RFC 5652, 7).
  """
  @spec digest(binary() | {:stream, Enumerable.t()} | {:digest, atom(), binary()}, keyword()) ::
          {:ok, binary()}
  def digest(content, opts \\ []), do: Digesting.digest(content, opts)

  @doc "Like `digest/2`, but returns the message alone."
  @spec digest!(binary() | {:stream, Enumerable.t()} | {:digest, atom(), binary()}, keyword()) ::
          binary()
  def digest!(content, opts \\ []) do
    {:ok, cms} = digest(content, opts)
    cms
  end

  @doc """
  Checks the digest of a DigestedData message, in DER, BER or PEM, and
  returns the message as `decode/2` reads it, whose `:content` is the
  content, or `nil` for a detached message.

  Options:

    * `:content` - the content of a detached message: a binary,
      `{:stream, enumerable}` or `{:digest, hash, digest}`.
    * `:allow_sha1` - take a SHA-1 digest (`false`). MD5 is never taken.
    * the limits of `decode/2`.

  Errors: `:digest_mismatch`, `:weak_algorithm`, `:unsupported_algorithm`,
  `:content_required` and `:unexpected_content`, and those of reading.
  A message of another type is `:unsupported_content_type`.
  """
  @spec verify_digest(binary(), keyword()) :: {:ok, DigestedData.t()} | {:error, Error.t()}
  def verify_digest(cms, opts \\ []), do: Digesting.verify_digest(cms, opts)

  @doc "Like `verify_digest/2`, but raises `Cmsex.Error`."
  @spec verify_digest!(binary(), keyword()) :: DigestedData.t()
  def verify_digest!(cms, opts \\ []) do
    case verify_digest(cms, opts) do
      {:ok, digested} -> digested
      {:error, error} -> raise error
    end
  end

  @doc """
  Returns an AuthenticatedData message in DER (RFC 5652, 9): `content`, in
  the clear, with an HMAC over it, and the MAC key, random and new for
  each message, wrapped for each of `recipients` as in `encrypt/3`.

      {:ok, cms} = Cmsex.mac(content, Cmsex.Recipient.kek(shared_key, "key 1"))
      {:ok, %Cmsex.Authenticated{content: ^content}} =
        Cmsex.verify_mac(cms, kek: {"key 1", shared_key})

  A MAC tells a recipient that the content comes from someone who had the
  MAC key, and that nobody changed it since. How much that says depends
  on the recipients: with a KEK or a password, the sender is someone who
  holds it; with a certificate, RSA or ephemeral ECDH, anyone who has the
  certificate can write such a message, and it shows nothing about who
  did (RFC 5652, 14). To show who wrote the content, sign it.

  The content is a binary, `{:stream, enumerable}` read once, or
  `{:digest, hash, digest}` already computed; a stream or a digest makes
  a detached message.

  Options:

    * `:mac` - `:hmac_sha256` (the default), `:hmac_sha384`,
      `:hmac_sha512` or `:hmac_sha224` (RFC 4231). The key is as long as
      the hash, and 32 bytes for SHA-224.
    * `:content_type` - the type of the content (`:data`), a name of
      `Cmsex.OID` or an OID tuple.
    * `:detached` - leave the content out of the message (`false` for a
      binary).
    * `:authenticated_attributes` - a list of `Cmsex.Attribute` that the
      MAC covers (`[]`). With them, for a content type other than
      `:data`, and for a ready digest, the MAC is over the attributes,
      among which the library writes the content-type and the
      message-digest attributes (RFC 5652, 9.2).
    * `:digest` - the hash of the message-digest attribute: that of the
      HMAC unless given, `:sha224`, `:sha256`, `:sha384` or `:sha512`; for
      a ready digest, its hash.
    * `:unauthenticated_attributes` - a list of `Cmsex.Attribute` that
      nothing covers (`[]`).
    * `:certificates` and `:crls` - certificates and revocation lists in
      DER for the OriginatorInfo (`[]`).
    * `:min_rsa_bits` - the shortest RSA key accepted (2048).

  Recipients are checked as in `encrypt/3`, and an error that belongs to
  one carries its position in `:recipient`.
  """
  @spec mac(
          binary() | {:stream, Enumerable.t()} | {:digest, atom(), binary()},
          Recipient.t() | binary() | [Recipient.t() | binary()],
          keyword()
        ) :: {:ok, binary()} | {:error, Error.t()}
  def mac(content, recipients, opts \\ []), do: Authenticate.mac(content, recipients, opts)

  @doc "Like `mac/3`, but raises `Cmsex.Error`."
  @spec mac!(
          binary() | {:stream, Enumerable.t()} | {:digest, atom(), binary()},
          Recipient.t() | binary() | [Recipient.t() | binary()],
          keyword()
        ) :: binary()
  def mac!(content, recipients, opts \\ []) do
    case mac(content, recipients, opts) do
      {:ok, cms} -> cms
      {:error, error} -> raise error
    end
  end

  @doc """
  Checks the MAC of an AuthenticatedData message, in DER, BER or PEM.

  The credentials are those of `decrypt/2`, with `:mac_key`, the MAC key
  itself, in place of `:content_key`. The recipients are tried as in
  `decrypt/2`; a key shorter than 16 bytes is not taken, since whoever
  sees the MAC could find it.

  With authenticated attributes, the MAC is over them, and once it has
  checked, so are the content-type attribute, against the content, and
  the message-digest attribute, against the digest of the content.

  Errors:

    * `:invalid_mac` - the MAC does not check, or the key of the
      recipient does not unwrap; nothing tells these apart.
    * `:digest_mismatch`, `:content_type_mismatch`, `:missing_attribute`
      and `:invalid_attribute` - about the authenticated attributes, once
      the MAC has checked. Content other than `:data` needs them.
    * `:weak_algorithm` - a digest of SHA-1 without `allow_sha1: true`,
      or MD5. HMAC-SHA1, the MAC of RFC 3370, is taken.
    * those of `decrypt/2` for the credentials and the recipients, and
      `:content_required` and `:unexpected_content`.

  Other options:

    * `:content` - the content of a detached message: a binary,
      `{:stream, enumerable}`, or `{:digest, hash, digest}` when the
      message has authenticated attributes with that hash.
    * `:allow_sha1` (`false`), `:max_iterations` (2,000,000), and the
      limits of `decode/2`.
  """
  @spec verify_mac(binary(), keyword()) :: {:ok, Authenticated.t()} | {:error, Error.t()}
  def verify_mac(cms, opts \\ []), do: Authenticate.verify_mac(cms, opts)

  @doc "Like `verify_mac/2`, but raises `Cmsex.Error`."
  @spec verify_mac!(binary(), keyword()) :: Authenticated.t()
  def verify_mac!(cms, opts \\ []) do
    case verify_mac(cms, opts) do
      {:ok, authenticated} -> authenticated
      {:error, error} -> raise error
    end
  end

  ## Changing a message

  @typedoc """
  The position of a signer: an integer for a signer of the message, in
  the order of `decode/2`, or a list for a countersignature, where `[0, 1]`
  is the second countersignature of the first signer, counted across all
  its countersignature attributes. `Cmsex.Error` gives positions the same
  way.
  """
  @type position :: non_neg_integer() | [non_neg_integer(), ...]

  @changes """
  The message may be in DER, BER or PEM, and comes back in DER as far as
  it was: what does not change keeps its bytes and its place, the other
  SignerInfos, the signed part of each, the certificates and attributes
  already there, and what is added goes after them. So every signature of
  the message still verifies, and the positions of the signers and
  countersignatures stay the same from one change to the next. The SETs
  are not sorted again; an encapsulated content in BER is written in DER,
  which changes no signature.
  """

  @doc """
  Adds signers to a SignedData message, over the content the message
  signs. #{@changes}
  `signers` is one signer or a list, as in `sign/3`. The new SignerInfos
  go after the others; their digest algorithms join digestAlgorithms, and
  the version of the message goes up to 3 when RFC 5652, 5.1 asks for it.

  A detached message needs its content in `:content`, a binary,
  `{:stream, enumerable}` or `{:digest, hash, digest}`. It must be the
  content the signers there signed: their message digests are checked
  before anything is signed, and a difference is `:digest_mismatch` with
  the position of that signer. A message with its content refuses
  `:content` (`:unexpected_content`).

  Options: `:content`, the limits of `decode/2`, and the options of
  `sign/3` that are about the signers: `:certificates` (those of the new
  signers are added to the message by default; `:none`; or a list of DER
  certificates), `:crls`, `:no_attributes`, `:min_rsa_bits`, `:digest`,
  `:rsa_padding`, `:identifier`, `:signing_time` and
  `:algorithm_protection`. The content type is that of the message.
  """
  @spec add_signer(
          binary(),
          Signer.t() | map() | keyword() | [Signer.t() | map() | keyword()],
          keyword()
        ) :: {:ok, binary()} | {:error, Error.t()}
  def add_signer(cms, signers, opts \\ []) do
    with {:ok, der} <- PEM.input(cms), do: Update.add_signer(der, signers, opts)
  end

  @doc "Like `add_signer/3`, but raises `Cmsex.Error`."
  @spec add_signer!(
          binary(),
          Signer.t() | map() | keyword() | [Signer.t() | map() | keyword()],
          keyword()
        ) :: binary()
  def add_signer!(cms, signers, opts \\ []), do: bang(add_signer(cms, signers, opts))

  @doc """
  Countersigns a signer of a message, or a countersignature: a new
  SignerInfo over the signature value of the one at `position`, added to
  it as a countersignature attribute (RFC 5652, 11.4). #{@changes}
  The countersignature goes at the end of the last countersignature
  attribute of that signer, or in a new attribute at the end. Its signed
  attributes are the message digest of the signature value, the signing
  time and CMSAlgorithmProtection, unless turned off, and those of the
  countersigner; never content-type. With `no_attributes: true` it signs
  the signature value itself. `verify/2` checks it with
  `countersignatures: true`.

  `countersigners` is one signer or a list, as in `sign/3`. Options: the
  limits of `decode/2`, and `:certificates`, `:crls`, `:no_attributes`,
  `:min_rsa_bits`, `:digest`, `:rsa_padding`, `:identifier`,
  `:signing_time` and `:algorithm_protection`, as in `add_signer/3`.

  A position the message does not have raises `ArgumentError`.
  """
  @spec countersign(
          binary(),
          position(),
          Signer.t() | map() | keyword() | [Signer.t() | map() | keyword()],
          keyword()
        ) :: {:ok, binary()} | {:error, Error.t()}
  def countersign(cms, position, countersigners, opts \\ []) do
    with {:ok, der} <- PEM.input(cms),
         do: Update.countersign(der, position, countersigners, opts)
  end

  @doc "Like `countersign/4`, but raises `Cmsex.Error`."
  @spec countersign!(
          binary(),
          position(),
          Signer.t() | map() | keyword() | [Signer.t() | map() | keyword()],
          keyword()
        ) :: binary()
  def countersign!(cms, position, countersigners, opts \\ []),
    do: bang(countersign(cms, position, countersigners, opts))

  @doc """
  Adds unsigned attributes, one `Cmsex.Attribute` or a list, to the signer
  or countersignature at `position`. #{@changes}
  The attributes go after the unsigned attributes the signer has. This is
  how a signature time-stamp enters a message (RFC 3161, appendix A): the
  token is over `Cmsex.SignerInfo.signature/1`, and goes in a
  `:time_stamp_token` attribute.

      {:ok, %{signer_infos: [signer_info]}} = Cmsex.decode(cms)
      token = time_stamp(Cmsex.SignerInfo.signature(signer_info))
      attribute = Cmsex.Attribute.new(:time_stamp_token, [token])
      {:ok, cms} = Cmsex.add_unsigned_attribute(cms, 0, attribute)

  Options: the limits of `decode/2`. A position the message does not have
  raises `ArgumentError`.
  """
  @spec add_unsigned_attribute(binary(), position(), Attribute.t() | [Attribute.t()], keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def add_unsigned_attribute(cms, position, attributes, opts \\ []) do
    attributes = attributes!(attributes)

    with {:ok, der} <- PEM.input(cms),
         do: Update.add_unsigned_attribute(der, position, attributes, opts)
  end

  @doc "Like `add_unsigned_attribute/4`, but raises `Cmsex.Error`."
  @spec add_unsigned_attribute!(
          binary(),
          position(),
          Attribute.t() | [Attribute.t()],
          keyword()
        ) :: binary()
  def add_unsigned_attribute!(cms, position, attributes, opts \\ []),
    do: bang(add_unsigned_attribute(cms, position, attributes, opts))

  defp attributes!(%Attribute{} = attribute), do: [attribute]

  defp attributes!([_ | _] = attributes) do
    if Enum.all?(attributes, &match?(%Attribute{}, &1)),
      do: attributes,
      else: bad_attributes!()
  end

  defp attributes!(_other), do: bad_attributes!()

  @spec bad_attributes!() :: no_return()
  defp bad_attributes!,
    do: raise(ArgumentError, "expected a Cmsex.Attribute or a list of them")

  defp bang({:ok, cms}), do: cms
  defp bang({:error, error}), do: raise(error)
end
