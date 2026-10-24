defmodule Cmsex do
  @moduledoc """
  Cryptographic Message Syntax (CMS, RFC 5652) in pure Elixir.
  """

  alias Cmsex.{
    Attribute,
    AuthenticatedData,
    DigestedData,
    EncryptedData,
    EnvelopedData,
    Error,
    Message,
    Options,
    PEM,
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
