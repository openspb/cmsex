defmodule Cmsex.Algorithm do
  @moduledoc false
  # AlgorithmIdentifier: reading, writing, comparison "modulo encoding"
  # (RFC 6211), and the rules that tie the digest, the signature and the key
  # of a signer together (RFC 3370, RFC 4055, RFC 4056, RFC 5754, RFC 8419).
  #
  # An identifier read from a message is `{oid, params}`, where `params` is
  # the DER element of the parameters, or `nil` when they are absent.

  alias Cmsex.{DER, Digest, OID}

  @type t :: {tuple(), DER.element() | nil}
  @type pss :: %{
          hash: Digest.hash(),
          mgf_hash: Digest.hash(),
          salt_length: non_neg_integer(),
          trailer_field: pos_integer()
        }
  @type scheme :: :rsa_pkcs1 | :rsa_pss | :ecdsa | :ed25519 | :ed448

  @sha2 [:sha224, :sha256, :sha384, :sha512]
  @hmacs %{
    hmac_sha1: :sha1,
    hmac_with_sha1: :sha1,
    hmac_sha224: :sha224,
    hmac_sha256: :sha256,
    hmac_sha384: :sha384,
    hmac_sha512: :sha512
  }
  @hmac_ids %{
    sha224: :hmac_sha224,
    sha256: :hmac_sha256,
    sha384: :hmac_sha384,
    sha512: :hmac_sha512
  }
  @ecdsa %{
    sha224: :ecdsa_with_sha224,
    sha256: :ecdsa_with_sha256,
    sha384: :ecdsa_with_sha384,
    sha512: :ecdsa_with_sha512
  }

  ## Reading

  @doc "Reads an AlgorithmIdentifier."
  @spec read(DER.element()) :: {:ok, t()} | :error
  def read({0x30, _, _} = element) do
    case DER.children(element) do
      [oid] -> with {:ok, oid} <- DER.oid(oid), do: {:ok, {oid, nil}}
      [oid, params] -> with {:ok, oid} <- DER.oid(oid), do: {:ok, {oid, params}}
      _ -> :error
    end
  end

  def read(_element), do: :error

  @doc """
  The hash of a digest AlgorithmIdentifier. SHA-2 and the others take
  absent or NULL parameters (RFC 5754, 2); id-shake256-len takes 512
  (RFC 8419, 2.3).
  """
  @spec digest(t()) :: {:ok, Digest.hash()} | {:error, Cmsex.Error.reason(), term()}
  def digest({oid, params}) do
    case {OID.name(oid), params} do
      {:shake256_len, {0x02, <<2, 0>>, _}} -> {:ok, :shake256_len}
      {:shake256_len, _} -> {:error, :unsupported_algorithm, oid}
      {:shake256, nil} -> {:ok, :shake256}
      {name, params} when name in [:md5, :sha1 | @sha2] -> null_or_absent(name, params, oid)
      _ -> {:error, :unsupported_algorithm, oid}
    end
  end

  @doc """
  The hash of an HMAC AlgorithmIdentifier: hMAC-SHA1 (RFC 3370, 6.1),
  hmacWithSHA1, and the HMAC of SHA-2 (RFC 4231, 3.1); the parameters
  absent or NULL, as both RFCs ask readers to take.
  """
  @spec mac(t()) :: {:ok, Digest.hash()} | {:error, Cmsex.Error.reason(), term()}
  def mac({oid, params}) do
    case Map.fetch(@hmacs, OID.name(oid)) do
      {:ok, hash} -> null_or_absent(hash, params, oid)
      :error -> {:error, :unsupported_algorithm, oid}
    end
  end

  defp null_or_absent(name, nil, _oid), do: {:ok, name}
  defp null_or_absent(name, {0x05, <<>>, _}, _oid), do: {:ok, name}
  defp null_or_absent(_name, _params, oid), do: {:error, :malformed, oid}

  @doc """
  What a signature AlgorithmIdentifier says: the scheme, the hash it names,
  if any, and the PSS parameters.
  """
  @spec signature(t()) ::
          {:ok, %{scheme: scheme(), hash: Digest.hash() | nil, pss: pss() | nil}}
          | {:error, Cmsex.Error.reason(), term()}
  def signature({oid, params}) do
    case {OID.name(oid), params} do
      {:rsassa_pss, nil} ->
        {:error, :malformed, oid}

      {:rsassa_pss, params} ->
        with {:ok, pss} <- pss_params(params),
             do: {:ok, %{scheme: :rsa_pss, hash: pss.hash, pss: pss}}

      {name, params} ->
        case combined(name) do
          {:ok, scheme, hash} -> check_params(scheme, hash, params, oid)
          :error -> {:error, :unsupported_algorithm, oid}
        end
    end
  end

  defp combined(:rsa_encryption), do: {:ok, :rsa_pkcs1, nil}
  defp combined(:md5_with_rsa_encryption), do: {:ok, :rsa_pkcs1, :md5}
  defp combined(:sha1_with_rsa_encryption), do: {:ok, :rsa_pkcs1, :sha1}
  defp combined(:sha224_with_rsa_encryption), do: {:ok, :rsa_pkcs1, :sha224}
  defp combined(:sha256_with_rsa_encryption), do: {:ok, :rsa_pkcs1, :sha256}
  defp combined(:sha384_with_rsa_encryption), do: {:ok, :rsa_pkcs1, :sha384}
  defp combined(:sha512_with_rsa_encryption), do: {:ok, :rsa_pkcs1, :sha512}
  defp combined(:ecdsa_with_sha1), do: {:ok, :ecdsa, :sha1}
  defp combined(:ecdsa_with_sha224), do: {:ok, :ecdsa, :sha224}
  defp combined(:ecdsa_with_sha256), do: {:ok, :ecdsa, :sha256}
  defp combined(:ecdsa_with_sha384), do: {:ok, :ecdsa, :sha384}
  defp combined(:ecdsa_with_sha512), do: {:ok, :ecdsa, :sha512}
  defp combined(:ed25519), do: {:ok, :ed25519, nil}
  defp combined(:ed448), do: {:ok, :ed448, nil}
  defp combined(_name), do: :error

  # RSA takes NULL, and absent is accepted (RFC 5754, 3.2). ECDSA and EdDSA
  # take none (RFC 5754, 3.3; RFC 8419, 2.4).
  defp check_params(:rsa_pkcs1, hash, params, oid) do
    with {:ok, _} <- null_or_absent(:rsa, params, oid),
         do: {:ok, %{scheme: :rsa_pkcs1, hash: hash, pss: nil}}
  end

  defp check_params(scheme, hash, nil, _oid), do: {:ok, %{scheme: scheme, hash: hash, pss: nil}}
  defp check_params(_scheme, _hash, _params, oid), do: {:error, :malformed, oid}

  @doc """
  RSASSA-PSS-params (RFC 4055, 3.1), with the defaults filled in: SHA-1,
  MGF1 with SHA-1, a salt of 20 bytes and the trailer field 1.
  """
  @spec pss_params(DER.element()) :: {:ok, pss()} | {:error, Cmsex.Error.reason(), term()}
  def pss_params({0x30, _, _} = element) do
    fields = DER.children(element)

    with {:ok, hash, fields} <- tagged(fields, 0xA0, &hash_field/1, :sha1),
         {:ok, mgf_hash, fields} <- tagged(fields, 0xA1, &mgf1_field/1, :sha1),
         {:ok, salt, fields} <- tagged(fields, 0xA2, &small_integer/1, 20),
         {:ok, trailer, []} <- tagged(fields, 0xA3, &small_integer/1, 1),
         true <- trailer == 1 do
      {:ok, %{hash: hash, mgf_hash: mgf_hash, salt_length: salt, trailer_field: trailer}}
    else
      {:error, _, _} = error -> error
      _ -> {:error, :malformed, OID.oid(:rsassa_pss)}
    end
  end

  def pss_params(_element), do: {:error, :malformed, OID.oid(:rsassa_pss)}

  @doc """
  RSAES-OAEP-params (RFC 4055, 4.1), with the defaults filled in: SHA-1,
  MGF1 with SHA-1 and an empty label.
  """
  @spec oaep_params(DER.element() | nil) ::
          {:ok, %{hash: Digest.hash(), mgf_hash: Digest.hash(), label: binary()}}
          | {:error, Cmsex.Error.reason(), term()}
  def oaep_params(nil), do: oaep_params({0x30, <<>>, <<0x30, 0>>})

  def oaep_params({0x30, _, _} = element) do
    fields = DER.children(element)

    with {:ok, hash, fields} <- tagged(fields, 0xA0, &hash_field/1, :sha1),
         {:ok, mgf_hash, fields} <- tagged(fields, 0xA1, &mgf1_field/1, :sha1),
         {:ok, label, []} <- tagged(fields, 0xA2, &p_source/1, <<>>) do
      {:ok, %{hash: hash, mgf_hash: mgf_hash, label: label}}
    else
      {:error, _, _} = error -> error
      _ -> {:error, :malformed, OID.oid(:rsaes_oaep)}
    end
  end

  def oaep_params(_element), do: {:error, :malformed, OID.oid(:rsaes_oaep)}

  defp tagged([{id, _, _} = field | rest], id, read, _default) do
    case DER.children(field) do
      [inner] -> with {:ok, value} <- read.(inner), do: {:ok, value, rest}
      _ -> :error
    end
  end

  defp tagged(fields, _id, _read, default), do: {:ok, default, fields}

  defp hash_field(element) do
    with {:ok, alg} <- read(element),
         {:ok, hash} when hash != :shake256 and hash != :shake256_len <- digest(alg) do
      {:ok, hash}
    else
      {:ok, _} -> :error
      other -> other
    end
  end

  defp mgf1_field(element) do
    case read(element) do
      {:ok, {oid, params}} when params != nil ->
        if OID.name(oid) == :mgf1, do: hash_field(params), else: :error

      _ ->
        :error
    end
  end

  defp p_source(element) do
    with {:ok, {oid, params}} <- read(element),
         :p_specified <- OID.name(oid),
         {0x04, label, _} <- params do
      {:ok, label}
    else
      _ -> :error
    end
  end

  defp small_integer(element) do
    case DER.integer(element) do
      {:ok, n} when n in 0..0xFFFF -> {:ok, n}
      _ -> :error
    end
  end

  @doc """
  An identifier in a canonical form, for comparison "modulo encoding"
  (RFC 6211, 2): absent and NULL parameters are the same, and so are PSS
  parameters left to their defaults and the same values written out.
  """
  @spec canonical(t()) :: term()
  def canonical({oid, params} = alg) do
    name = OID.name(oid)

    cond do
      name == :rsassa_pss ->
        case signature(alg) do
          {:ok, %{pss: pss}} -> {oid, pss}
          _ -> {oid, raw(params)}
        end

      params == nil or DER.null?(params) ->
        {oid, nil}

      true ->
        {oid, raw(params)}
    end
  end

  defp raw(nil), do: nil
  defp raw({_, _, raw}), do: raw

  ## Rules

  @doc """
  The checks of one signer, before any cryptography: whether its digest and
  signature algorithms are allowed, agree with each other and fit the key
  of the certificate. Returns the hash to compute the message-digest
  attribute, the scheme and what it takes, and the deviations tolerated.

  Options: `:allow_sha1` (false), `:min_rsa_bits` (2048), `:ed25519_digest`
  (`:lenient` or `:strict`) and `:signed_attributes?`.
  """
  @spec plan(Digest.hash(), map(), Cmsex.Certificate.public_key(), keyword()) ::
          {:ok, map()} | {:error, Cmsex.Error.reason(), term()}
  def plan(digest, %{scheme: scheme, hash: named, pss: pss}, public_key, opts) do
    with :ok <- allowed_digest(digest, opts),
         {:ok, sig_hash, deviations} <- signature_hash(scheme, named, pss, digest, opts),
         :ok <- allowed_digest(sig_hash, opts),
         :ok <- fits_key(scheme, pss, public_key, opts) do
      {:ok, %{digest: digest, scheme: scheme, hash: sig_hash, pss: pss, deviations: deviations}}
    end
  end

  @doc """
  Whether a digest may be used: never MD5, SHA-1 only with `allow_sha1:
  true`.
  """
  @spec allowed_digest(Digest.hash() | nil, keyword()) :: :ok | {:error, :weak_algorithm, atom()}
  def allowed_digest(nil, _opts), do: :ok
  def allowed_digest(:md5, _opts), do: {:error, :weak_algorithm, :md5}

  def allowed_digest(:sha1, opts) do
    if Keyword.get(opts, :allow_sha1, false), do: :ok, else: {:error, :weak_algorithm, :sha1}
  end

  def allowed_digest(_hash, _opts), do: :ok

  # The hash the signature itself uses. RSA with rsaEncryption takes the
  # digestAlgorithm; a combined OID must name the same (RFC 5754; RFC 8933
  # asks for one hash per signer); PSS must name it too (RFC 4056, 3).
  defp signature_hash(:rsa_pkcs1, nil, _pss, digest, _opts) when digest in [:md5, :sha1 | @sha2],
    do: {:ok, digest, []}

  defp signature_hash(scheme, named, _pss, digest, _opts)
       when scheme in [:rsa_pkcs1, :ecdsa, :rsa_pss] do
    cond do
      named == nil -> {:error, :algorithm_mismatch, {digest, scheme}}
      named == digest -> {:ok, digest, []}
      true -> {:error, :algorithm_mismatch, {digest, named}}
    end
  end

  # Ed25519 hashes with SHA-512 inside the signature. RFC 8419 asks for
  # SHA-512 as the digestAlgorithm too; another SHA-2 is tolerated unless
  # `ed25519_digest: :strict`, because one common tool writes it.
  defp signature_hash(:ed25519, nil, nil, :sha512, _opts), do: {:ok, nil, []}

  defp signature_hash(:ed25519, nil, nil, digest, opts) when digest in @sha2 do
    case Keyword.get(opts, :ed25519_digest, :lenient) do
      :lenient -> {:ok, nil, [:ed25519_digest]}
      :strict -> {:error, :algorithm_mismatch, {digest, :ed25519}}
    end
  end

  # Ed448: id-shake256-len (512) with signed attributes, id-shake256 without
  # (RFC 8419, 3).
  defp signature_hash(:ed448, nil, nil, digest, opts) do
    expected = if Keyword.get(opts, :signed_attributes?, true), do: :shake256_len, else: :shake256

    if digest == expected,
      do: {:ok, nil, []},
      else: {:error, :algorithm_mismatch, {digest, :ed448}}
  end

  defp signature_hash(scheme, _named, _pss, digest, _opts),
    do: {:error, :algorithm_mismatch, {digest, scheme}}

  defp fits_key(:rsa_pkcs1, _pss, {:rsa, n, _e}, opts), do: rsa_bits(n, opts)

  defp fits_key(:rsa_pss, _pss, {:rsa, n, _e}, opts), do: rsa_bits(n, opts)
  defp fits_key(:rsa_pss, _pss, {:rsa_pss, n, _e, nil}, opts), do: rsa_bits(n, opts)

  # RFC 4056, 3: a PSS key with parameters restricts the signature to them,
  # with defaults taken as written.
  defp fits_key(:rsa_pss, pss, {:rsa_pss, n, _e, key_pss}, opts) do
    if pss.hash == key_pss.hash and pss.mgf_hash == key_pss.mgf_hash and
         pss.salt_length >= key_pss.salt_length and pss.trailer_field == key_pss.trailer_field do
      rsa_bits(n, opts)
    else
      {:error, :algorithm_mismatch, :rsassa_pss}
    end
  end

  defp fits_key(:ecdsa, _pss, {:ec, curve, _point}, _opts) do
    if curve in Cmsex.Key.curves(), do: :ok, else: {:error, :unsupported_algorithm, curve}
  end

  defp fits_key(:ed25519, _pss, {:ed25519, _}, _opts), do: :ok
  defp fits_key(:ed448, _pss, {:ed448, _}, _opts), do: :ok
  defp fits_key(_scheme, _pss, {:unknown, oid}, _opts), do: {:error, :unsupported_algorithm, oid}
  defp fits_key(_scheme, _pss, _key, _opts), do: {:error, :key_mismatch, nil}

  defp rsa_bits(n, opts) do
    bits = rsa_size(n)
    if bits >= Keyword.get(opts, :min_rsa_bits, 2048), do: :ok, else: {:error, :weak_key, bits}
  end

  @doc "The size of an RSA modulus, in bits."
  @spec rsa_size(pos_integer()) :: non_neg_integer()
  def rsa_size(n) do
    <<first, _::binary>> = bytes = :binary.encode_unsigned(n)
    byte_size(bytes) * 8 - (8 - length(Integer.digits(first, 2)))
  end

  ## Writing

  @doc "A digest AlgorithmIdentifier, parameters absent (RFC 5754, 2)."
  @spec digest_identifier(Digest.hash()) :: DER.term_()
  def digest_identifier(:shake256_len), do: {:seq, [{:oid, :shake256_len}, {:int, 512}]}
  def digest_identifier(hash), do: {:seq, [{:oid, hash}]}

  @doc "An HMAC AlgorithmIdentifier of SHA-2, with NULL (RFC 4231, 3.1)."
  @spec mac_identifier(:sha224 | :sha256 | :sha384 | :sha512) :: DER.term_()
  def mac_identifier(hash), do: {:seq, [{:oid, Map.fetch!(@hmac_ids, hash)}, :null]}

  @doc """
  A signature AlgorithmIdentifier: rsaEncryption with NULL for RSA (what
  common tools write, and what RFC 3370 asks every verifier to take), PSS
  with its parameters, the combined OID for ECDSA, and the bare OID for
  EdDSA.
  """
  @spec signature_identifier(scheme(), Digest.hash() | nil) :: DER.term_()
  def signature_identifier(:rsa_pkcs1, _hash), do: {:seq, [{:oid, :rsa_encryption}, :null]}

  def signature_identifier(:rsa_pss, hash),
    do:
      pss_identifier(%{
        hash: hash,
        mgf_hash: hash,
        salt_length: Digest.size(hash),
        trailer_field: 1
      })

  def signature_identifier(:ecdsa, hash), do: {:seq, [{:oid, Map.fetch!(@ecdsa, hash)}]}

  def signature_identifier(:ed25519, _hash), do: {:seq, [{:oid, :ed25519}]}
  def signature_identifier(:ed448, _hash), do: {:seq, [{:oid, :ed448}]}

  @doc """
  An id-RSASSA-PSS AlgorithmIdentifier (RFC 4055, 3.1): the hash
  identifiers inside take NULL, and the fields equal to their defaults
  (SHA-1, a salt of 20 bytes, the trailer field 1) are left out, as DER
  asks.
  """
  @spec pss_identifier(pss()) :: DER.term_()
  def pss_identifier(%{hash: hash, mgf_hash: mgf_hash, salt_length: salt, trailer_field: trailer}) do
    fields =
      [
        hash != :sha1 && {:explicit, 0, {:seq, [{:oid, hash}, :null]}},
        mgf_hash != :sha1 &&
          {:explicit, 1, {:seq, [{:oid, :mgf1}, {:seq, [{:oid, mgf_hash}, :null]}]}},
        salt != 20 && {:explicit, 2, {:int, salt}},
        trailer != 1 && {:explicit, 3, {:int, trailer}}
      ]
      |> Enum.filter(& &1)

    {:seq, [{:oid, :rsassa_pss}, {:seq, fields}]}
  end

  @doc """
  RSAES-OAEP-params for a hash, with MGF1 of the same hash and no label.
  For SHA-1 every field is the default, and DER leaves them all out.
  """
  @spec oaep_identifier(Digest.hash()) :: DER.term_()
  def oaep_identifier(:sha1), do: {:seq, [{:oid, :rsaes_oaep}, {:seq, []}]}

  def oaep_identifier(hash) do
    hash_id = {:seq, [{:oid, hash}, :null]}

    {:seq,
     [
       {:oid, :rsaes_oaep},
       {:seq, [{:explicit, 0, hash_id}, {:explicit, 1, {:seq, [{:oid, :mgf1}, hash_id]}}]}
     ]}
  end
end
