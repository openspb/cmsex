defmodule Cmsex do
  @moduledoc """
  Cryptographic Message Syntax (CMS, RFC 5652) in pure Elixir.
  """

  alias Cmsex.{Error, Options, PEM, Sign, SignedData, Signer, Verified, Verify}

  @decode_options Options.limits()

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
  Reads a SignedData message without verifying it, for inspection and for
  the libraries built on this one. The message may be in DER, BER or PEM.

  Options, the limits on what the message may hold:

    * `:max_depth` - nesting of the encoding (32).
    * `:max_elements` - encoded elements at all levels (100,000).
    * `:max_signers` - signers, and countersignatures of one signer (64).
    * `:max_certificates` - certificates, and revocation lists (256).
    * `:max_attributes` - signed, and unsigned, attributes of one signer
      (64).

  A ContentInfo of another type gives `:unsupported_content_type`.
  """
  @spec decode(binary(), keyword()) :: {:ok, SignedData.t()} | {:error, Error.t()}
  def decode(cms, opts \\ []) do
    opts = Options.take!(opts, @decode_options)
    with {:ok, der} <- PEM.input(cms), do: SignedData.parse(der, opts)
  end

  @doc "Like `decode/2`, but raises `Cmsex.Error`."
  @spec decode!(binary(), keyword()) :: SignedData.t()
  def decode!(cms, opts \\ []) do
    case decode(cms, opts) do
      {:ok, signed_data} -> signed_data
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
    with {:ok, signed_data} <- decode(cms, opts), do: {:ok, signed_data.certificates}
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
end
