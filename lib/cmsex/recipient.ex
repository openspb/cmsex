defmodule Cmsex.Recipient do
  @moduledoc """
  A recipient for `Cmsex.encrypt/3` and `Cmsex.mac/3`: who can decrypt the
  message, or check its MAC, and how the key reaches them (RFC 5652, 6.2).
  Build it with one of the functions here; both functions also take a
  certificate in DER as a recipient of `certificate/2` with the defaults.

    * `certificate/2` - the holder of the private key of a certificate:
      RSA-OAEP key transport for an RSA key (RFC 3560), ephemeral-static
      ECDH for an EC key (RFC 5753), and X25519 or X448 (RFC 8418).
    * `kek/3` - whoever holds a symmetric key-encryption key, shared by
      other means, wrapped with AES key wrap (RFC 3394, RFC 5649).
    * `password/2` - whoever knows a password, through PBKDF2 and the
      key wrap of RFC 3211.

  The certificate is read, and its key checked, by `Cmsex.encrypt/3`; the
  functions here check the options, and raise `ArgumentError` for one that
  is unknown or of the wrong kind. `Inspect` leaves the key and the
  password out.
  """

  @type t :: %__MODULE__{
          type: :certificate | :kek | :password,
          certificate: binary() | nil,
          key_id: binary() | nil,
          secret: binary() | nil,
          options: map()
        }

  @derive {Inspect, except: [:secret]}
  @enforce_keys [:type]
  defstruct [:type, :certificate, :key_id, :secret, options: %{}]

  @digests [:sha1, :sha224, :sha256, :sha384, :sha512]

  @key_agreements [
    :std_dh_sha256kdf,
    :std_dh_sha384kdf,
    :std_dh_sha512kdf,
    :std_dh_hkdf_sha256,
    :std_dh_hkdf_sha384,
    :std_dh_hkdf_sha512
  ]

  @key_wraps [
    :aes128_wrap,
    :aes192_wrap,
    :aes256_wrap,
    :aes128_wrap_pad,
    :aes192_wrap_pad,
    :aes256_wrap_pad
  ]

  @prfs [:hmac_sha224, :hmac_sha256, :hmac_sha384, :hmac_sha512]

  @kek_ciphers [:aes128_cbc, :aes192_cbc, :aes256_cbc]

  @doc """
  The holder of the certificate `certificate`, in DER.

  The key of the certificate chooses the way:

    * RSA: KeyTransRecipientInfo with RSAES-OAEP (RFC 3560), MGF1 of the
      same hash and no label. PKCS #1 v1.5 is never written (RFC 3218);
      `Cmsex.decrypt/2` still reads it. An RSASSA-PSS key is for
      signatures only, and is refused.
    * EC (P-256, P-384, P-521 and the brainpool curves): KeyAgreeRecipientInfo
      with an ephemeral key on the curve of the certificate and the
      ANSI X9.63 KDF (RFC 5753).
    * X25519 and X448: KeyAgreeRecipientInfo with an ephemeral key and
      HKDF (RFC 8418).

  A keyUsage extension in the certificate must allow keyEncipherment for
  RSA, and keyAgreement for the others.

  Options:

    * `:identifier` - `:issuer_and_serial` (the default) or
      `:subject_key_identifier`, which needs that extension in the
      certificate.
    * `:oaep_digest` - the hash of RSAES-OAEP and of its MGF1: `:sha256`
      (the default), `:sha384`, `:sha512`, `:sha224`, or `:sha1`, for a
      recipient that can only do the defaults of RFC 3560.
    * `:key_agreement` - the scheme of ECDH: `:std_dh_sha256kdf`,
      `:std_dh_sha384kdf` or `:std_dh_sha512kdf` (X9.63), or
      `:std_dh_hkdf_sha256`, `:std_dh_hkdf_sha384` or
      `:std_dh_hkdf_sha512` (HKDF, RFC 8418). The default is X9.63 with
      SHA-256 for P-256, SHA-384 for P-384 and SHA-512 for P-521, the
      hash of the size of the curve for brainpool, HKDF with SHA-256 for
      X25519 (as RFC 8551 asks) and HKDF with SHA-512 for X448.
    * `:key_wrap` - the key wrap of key agreement: `:aes128_wrap`,
      `:aes192_wrap` or `:aes256_wrap` (RFC 3394), or the same with
      `_pad` (RFC 5649). The default is AES key wrap of the size of the
      content-encryption key, as RFC 8551 asks, and AES-256 for a key
      longer than that.
    * `:ukm` - user keying material for key agreement, mixed into the
      key-encryption key (RFC 5753, 3.1.1), or `nil` (the default).
  """
  @spec certificate(binary(), keyword()) :: t()
  def certificate(certificate, opts \\ []) when is_binary(certificate) do
    options =
      take!(opts, %{
        identifier: :issuer_and_serial,
        oaep_digest: :sha256,
        key_agreement: nil,
        key_wrap: nil,
        ukm: nil
      })

    ensure!(
      options.identifier in [:issuer_and_serial, :subject_key_identifier],
      ":identifier must be :issuer_and_serial or :subject_key_identifier",
      options.identifier
    )

    ensure!(
      options.oaep_digest in @digests,
      ":oaep_digest must be a SHA hash",
      options.oaep_digest
    )

    ensure!(
      options.key_agreement in [nil | @key_agreements],
      ":key_agreement must be one of #{inspect(@key_agreements)}",
      options.key_agreement
    )

    ensure!(
      options.key_wrap in [nil | @key_wraps],
      ":key_wrap must be one of #{inspect(@key_wraps)}",
      options.key_wrap
    )

    ensure!(
      options.ukm == nil or (is_binary(options.ukm) and options.ukm != <<>>),
      ":ukm must be a non-empty binary",
      options.ukm
    )

    %__MODULE__{type: :certificate, certificate: certificate, options: options}
  end

  @doc """
  Whoever holds the key-encryption key `key`, of 16, 24 or 32 bytes,
  known by `key_id` (KEKRecipientInfo, RFC 5652, 6.2.3). The message
  carries `key_id`, and the content-encryption key wrapped with AES key
  wrap of the size of `key`.

  Options:

    * `:key_wrap` - `:aes128_wrap`, `:aes192_wrap` or `:aes256_wrap`
      (RFC 3394, the default), or the same with `_pad` (RFC 5649); its
      size must be that of `key`.
    * `:date` - a `DateTime` that tells keys of the same `key_id` apart.
    * `:other` - `{oid, value}`, an OtherKeyAttribute: an OID, a name of
      `Cmsex.OID`, and its value encoded in DER, or `nil`.
  """
  @spec kek(binary(), binary(), keyword()) :: t()
  def kek(key, key_id, opts \\ []) when is_binary(key) and is_binary(key_id) do
    ensure!(
      byte_size(key) in [16, 24, 32],
      "a key-encryption key must be 16, 24 or 32 bytes",
      :hidden
    )

    ensure!(key_id != <<>>, "the key identifier must not be empty", :hidden)

    options = take!(opts, %{key_wrap: nil, date: nil, other: nil})
    key_wrap = options.key_wrap || :"aes#{byte_size(key) * 8}_wrap"

    ensure!(key_wrap in @key_wraps, ":key_wrap must be one of #{inspect(@key_wraps)}", key_wrap)

    ensure!(
      wrap_size(key_wrap) == byte_size(key),
      ":key_wrap must be of the size of the key",
      key_wrap
    )

    ensure!(
      options.date == nil or match?(%DateTime{}, options.date),
      ":date must be a DateTime",
      options.date
    )

    ensure!(
      other?(options.other),
      ":other must be {oid, der_value} or {oid, nil}",
      options.other
    )

    %__MODULE__{
      type: :kek,
      key_id: key_id,
      secret: key,
      options: %{options | key_wrap: key_wrap}
    }
  end

  @doc """
  Whoever knows `password` (PasswordRecipientInfo, RFC 3211): the
  key-encryption key comes from PBKDF2 (RFC 8018), and wraps the
  content-encryption key with id-alg-PWRI-KEK. The password is taken as
  given, as bytes; normalize it before, if it may come typed in different
  ways.

  Options:

    * `:iterations` - of PBKDF2 (600,000). `Cmsex.decrypt/2` refuses more
      than its `:max_iterations` (2,000,000).
    * `:salt` - 16 random bytes unless given; at least 8.
    * `:prf` - the pseudorandom function of PBKDF2: `:hmac_sha256` (the
      default), `:hmac_sha224`, `:hmac_sha384` or `:hmac_sha512`.
    * `:kek_cipher` - the cipher of the key wrap: `:aes256_cbc` (the
      default), `:aes192_cbc` or `:aes128_cbc`.
  """
  @spec password(binary(), keyword()) :: t()
  def password(password, opts \\ []) when is_binary(password) do
    ensure!(password != <<>>, "the password must not be empty", :hidden)

    options =
      take!(opts, %{iterations: 600_000, salt: nil, prf: :hmac_sha256, kek_cipher: :aes256_cbc})

    ensure!(
      is_integer(options.iterations) and options.iterations > 0,
      ":iterations must be a positive integer",
      options.iterations
    )

    ensure!(
      options.salt == nil or (is_binary(options.salt) and byte_size(options.salt) >= 8),
      ":salt must be at least 8 bytes",
      options.salt
    )

    ensure!(options.prf in @prfs, ":prf must be one of #{inspect(@prfs)}", options.prf)

    ensure!(
      options.kek_cipher in @kek_ciphers,
      ":kek_cipher must be one of #{inspect(@kek_ciphers)}",
      options.kek_cipher
    )

    %__MODULE__{type: :password, secret: password, options: options}
  end

  @type key_wrap ::
          :aes128_wrap
          | :aes192_wrap
          | :aes256_wrap
          | :aes128_wrap_pad
          | :aes192_wrap_pad
          | :aes256_wrap_pad

  @doc false
  # The size of the key of a key wrap, in bytes.
  @spec wrap_size(key_wrap()) :: 16 | 24 | 32
  def wrap_size(name) when name in [:aes128_wrap, :aes128_wrap_pad], do: 16
  def wrap_size(name) when name in [:aes192_wrap, :aes192_wrap_pad], do: 24
  def wrap_size(name) when name in [:aes256_wrap, :aes256_wrap_pad], do: 32

  defp other?(nil), do: true

  defp other?({oid, value}) when is_atom(oid) or is_tuple(oid) do
    _ = oid |> Cmsex.OID.oid() |> Cmsex.OID.encode()
    value == nil or (is_binary(value) and match?({:ok, _}, Cmsex.DER.decode(value)))
  rescue
    ArgumentError -> false
  end

  defp other?(_other), do: false

  defp take!(opts, defaults) do
    unless Keyword.keyword?(opts),
      do: raise(ArgumentError, "expected a keyword list of options, got: #{inspect(opts)}")

    for {key, _value} <- opts, not is_map_key(defaults, key) do
      raise ArgumentError, "unknown option #{inspect(key)}"
    end

    Map.merge(defaults, Map.new(opts))
  end

  # The key and the password are never shown.
  defp ensure!(true, _message, _value), do: :ok
  defp ensure!(false, message, :hidden), do: raise(ArgumentError, message)

  defp ensure!(false, message, value),
    do: raise(ArgumentError, "#{message}, got: #{inspect(value, limit: 5)}")
end
