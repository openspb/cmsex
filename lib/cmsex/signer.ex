defmodule Cmsex.Signer do
  @moduledoc """
  A signer for `Cmsex.sign/3`: a certificate, its private key, and how to
  sign. `Cmsex.sign/3` also takes it as a plain map or keyword list with
  the same fields, and turns it into this struct, whose `Inspect` leaves
  the key out.

  Fields:

    * `:certificate` - the certificate of the signer, in DER. Required.
    * `:key` - the private key, required: PKCS #8 in DER (such as the
      `private_key` of a PKCS #12 file), a key record of `:public_key`
      (`RSAPrivateKey`, `ECPrivateKey`, Ed25519 and Ed448 included, or a
      decoded `PrivateKeyInfo`), or a function, for a key that never
      leaves an HSM, a token or a KMS (see below).
    * `:chain` - more certificates in DER that go in the message with
      this signer's, such as its intermediates (`[]`).
    * `:digest` - `:sha256`, `:sha224`, `:sha384` or `:sha512`. The default
      is SHA-256; SHA-512 for Ed25519 (RFC 8419); the hash of the key for
      an RSASSA-PSS key with parameters; the hash of a ready digest given
      as the content. Ed448 always takes SHAKE256 (RFC 8419).
    * `:rsa_padding` - `:pkcs1` (PKCS #1 v1.5, the default) or `:pss`
      (RSASSA-PSS, with MGF1 of the same hash and a salt of the size of
      the hash).
    * `:identifier` - `:issuer_and_serial` (the default) or
      `:subject_key_identifier`, which needs that extension in the
      certificate.
    * `:signing_time` - `true` (now, the default), `false`, or a
      `DateTime`.
    * `:algorithm_protection` - the CMSAlgorithmProtection attribute
      (RFC 6211), which binds the algorithms to the signature (`true`).
    * `:signed_attributes` - more signed attributes, as `Cmsex.Attribute`
      structs, such as `Cmsex.Attribute.signing_certificate_v2/2` (`[]`).
      The content-type and message-digest attributes are always written
      by `Cmsex.sign/3`, and so are signing-time and CMSAlgorithmProtection
      unless turned off; none of them may be repeated here.
    * `:unsigned_attributes` - unsigned attributes, as `Cmsex.Attribute`
      structs (`[]`).
    * `:verify_signature` - with a function as the key, verify what it
      returns against the certificate before writing the message (`true`).

  `:digest`, `:rsa_padding`, `:identifier`, `:signing_time` and
  `:algorithm_protection` left out take the value of the option of the
  same name of `Cmsex.sign/3`, or else the default.

  ## A key as a function

  The function is called once per signature with a map:

    * `:tbs` - the bytes to sign.
    * `:hash` - the hash of the signature, or `nil` for EdDSA.
    * `:digest` - the hash of `:tbs` for RSA and ECDSA, which is what a
      KMS usually signs; `nil` for EdDSA, which signs `:tbs` itself.
    * `:scheme` - `:rsa_pkcs1`, `:rsa_pss`, `:ecdsa`, `:ed25519` or
      `:ed448`.
    * `:pss` - for RSASSA-PSS, `%{hash, mgf_hash, salt_length,
      trailer_field}`; `nil` otherwise.

  It returns `{:ok, signature}` or `{:error, reason}`. An ECDSA signature
  is the DER `Ecdsa-Sig-Value`; for RSA PKCS #1 v1.5 the function signs the
  digest and builds the DigestInfo itself, as any KMS does. An error, or a
  signature that does not verify, is `:signer_failed`.
  """

  alias Cmsex.Attribute

  @type key :: binary() | tuple() | (map() -> {:ok, binary()} | {:error, term()})

  @type t :: %__MODULE__{
          certificate: binary(),
          key: key(),
          chain: [binary()],
          digest: :sha224 | :sha256 | :sha384 | :sha512 | nil,
          rsa_padding: :pkcs1 | :pss | nil,
          identifier: :issuer_and_serial | :subject_key_identifier | nil,
          signing_time: boolean() | DateTime.t() | nil,
          algorithm_protection: boolean() | nil,
          signed_attributes: [Attribute.t()],
          unsigned_attributes: [Attribute.t()],
          verify_signature: boolean()
        }

  @derive {Inspect, except: [:key]}
  @enforce_keys [:certificate, :key]
  defstruct [
    :certificate,
    :key,
    chain: [],
    digest: nil,
    rsa_padding: nil,
    identifier: nil,
    signing_time: nil,
    algorithm_protection: nil,
    signed_attributes: [],
    unsigned_attributes: [],
    verify_signature: true
  ]

  @fields [
    :certificate,
    :key,
    :chain,
    :digest,
    :rsa_padding,
    :identifier,
    :signing_time,
    :algorithm_protection,
    :signed_attributes,
    :unsigned_attributes,
    :verify_signature
  ]

  @doc """
  A signer from a map, a keyword list or a signer, with its fields
  checked. A field that is unknown, missing, given twice or of the wrong
  kind raises `ArgumentError`; whether the key and the certificate can be read is
  checked by `Cmsex.sign/3`.
  """
  @spec new!(t() | map() | keyword()) :: t()
  def new!(%__MODULE__{} = signer), do: check!(signer)

  def new!(fields) when is_map(fields) or is_list(fields) do
    unless is_map(fields) or Keyword.keyword?(fields),
      do: raise(ArgumentError, "expected a signer as a map or keyword list")

    for {key, _value} <- fields, key not in @fields do
      raise ArgumentError, "unknown signer field #{inspect(key)}"
    end

    for key <- [:certificate, :key], not Enum.any?(fields, &match?({^key, _}, &1)) do
      raise ArgumentError, "a signer needs #{inspect(key)}"
    end

    if is_list(fields), do: Cmsex.Options.unique!(fields, "signer field")

    __MODULE__ |> struct(fields) |> check!()
  end

  def new!(other),
    do:
      raise(
        ArgumentError,
        "expected a signer as a map or keyword list, got #{Cmsex.Options.kind(other)}"
      )

  defp check!(%__MODULE__{} = signer) do
    key = signer.key

    ensure!(is_binary(signer.certificate), ":certificate must be DER", :hidden)

    ensure!(
      is_binary(key) or is_tuple(key) or is_function(key, 1),
      ":key must be DER, a key record or a function of one argument",
      :hidden
    )

    ensure!(binaries?(signer.chain), ":chain must be a list of DER certificates", :hidden)

    ensure!(
      signer.digest in [nil, :sha224, :sha256, :sha384, :sha512],
      ":digest must be :sha224, :sha256, :sha384 or :sha512",
      signer.digest
    )

    ensure!(
      signer.rsa_padding in [nil, :pkcs1, :pss],
      ":rsa_padding must be :pkcs1 or :pss",
      signer.rsa_padding
    )

    ensure!(
      signer.identifier in [nil, :issuer_and_serial, :subject_key_identifier],
      ":identifier must be :issuer_and_serial or :subject_key_identifier",
      signer.identifier
    )

    ensure!(
      signer.signing_time in [nil, true, false] or match?(%DateTime{}, signer.signing_time),
      ":signing_time must be a boolean or a DateTime",
      signer.signing_time
    )

    ensure!(
      signer.algorithm_protection in [nil, true, false],
      ":algorithm_protection must be a boolean",
      signer.algorithm_protection
    )

    for field <- [:signed_attributes, :unsigned_attributes] do
      value = Map.fetch!(signer, field)

      ensure!(
        is_list(value) and Enum.all?(value, &match?(%Attribute{}, &1)),
        "#{inspect(field)} must be a list of Cmsex.Attribute",
        value
      )
    end

    ensure!(
      is_boolean(signer.verify_signature),
      ":verify_signature must be a boolean",
      signer.verify_signature
    )

    signer
  end

  # The key and the certificates are never shown.
  defp ensure!(true, _message, _value), do: :ok
  defp ensure!(false, message, :hidden), do: raise(ArgumentError, message)

  defp ensure!(false, message, value),
    do: raise(ArgumentError, "#{message}, got: #{inspect(value, limit: 5)}")

  defp binaries?(list), do: is_list(list) and Enum.all?(list, &is_binary/1)
end
