defmodule Cmsex.Cipher do
  @moduledoc false
  # Content encryption (RFC 5652, 6.3; RFC 3565; RFC 3370, 5; RFC 5084;
  # RFC 8103): what a ContentEncryptionAlgorithmIdentifier says, the
  # identifier of a new one, and encryption and decryption.
  #
  # A cipher is a map: the name of its OID, the `:crypto` cipher, the size
  # of its key, the IV or nonce, and the size of the tag for the
  # authenticated ones (`nil` for CBC).

  alias Cmsex.{DER, OID}

  @type name ::
          :aes128_cbc
          | :aes192_cbc
          | :aes256_cbc
          | :aes128_gcm
          | :aes192_gcm
          | :aes256_gcm
          | :aes128_ccm
          | :aes192_ccm
          | :aes256_ccm
          | :chacha20_poly1305
          | :des_ede3_cbc
          | :rc2_cbc

  @type t :: %{
          name: name(),
          crypto: atom(),
          key_size: pos_integer(),
          iv: binary(),
          tag_size: pos_integer() | nil
        }

  # name => {`:crypto` cipher, key size, mode}
  @ciphers %{
    aes128_cbc: {:aes_128_cbc, 16, {:cbc, 16}},
    aes192_cbc: {:aes_192_cbc, 24, {:cbc, 16}},
    aes256_cbc: {:aes_256_cbc, 32, {:cbc, 16}},
    des_ede3_cbc: {:des_ede3_cbc, 24, {:cbc, 8}},
    aes128_gcm: {:aes_128_gcm, 16, :gcm},
    aes192_gcm: {:aes_192_gcm, 24, :gcm},
    aes256_gcm: {:aes_256_gcm, 32, :gcm},
    aes128_ccm: {:aes_128_ccm, 16, :ccm},
    aes192_ccm: {:aes_192_ccm, 24, :ccm},
    aes256_ccm: {:aes_256_ccm, 32, :ccm},
    chacha20_poly1305: {:chacha20_poly1305, 32, :chacha}
  }

  # The tag sizes each authenticated mode allows (RFC 5084, 3; RFC 8103, 3).
  @tag_sizes %{gcm: 12..16, ccm: [4, 6, 8, 10, 12, 14, 16], chacha: [16]}

  # RC2 (RFC 3370, 5.2): rc2ParameterVersion => key size. `:crypto` takes
  # the effective key bits from the size of the key, so only the sizes
  # where both agree are read: 40, 64 and 128 bits.
  @rc2_versions %{160 => 5, 120 => 8, 58 => 16}

  @doc "The names `new/2` takes."
  @spec names() :: [name()]
  def names, do: Map.keys(@ciphers)

  @doc "Whether a cipher, or a name, is an authenticated one."
  @spec aead?(t() | name()) :: boolean()
  def aead?(%{name: name}), do: aead?(name)
  def aead?(name), do: match?({:ok, {_, _, mode}} when is_atom(mode), Map.fetch(@ciphers, name))

  @doc """
  A new cipher, with a random IV or nonce: 16 bytes for AES-CBC, 8 for
  Triple-DES, 12 for GCM and ChaCha20-Poly1305, 7 for CCM (L = 8, as RFC
  5084 recommends). `tag_size` is for the authenticated ones.
  """
  @spec new(name(), pos_integer()) :: t()
  def new(name, tag_size \\ 16) do
    {crypto, key_size, mode} =
      case Map.fetch(@ciphers, name) do
        {:ok, cipher} -> cipher
        :error -> raise ArgumentError, "unknown content cipher: #{inspect(name)}"
      end

    iv_size =
      case mode do
        {:cbc, block_size} -> block_size
        :ccm -> 7
        _ -> 12
      end

    tag_size = if is_atom(mode), do: check_tag_size!(mode, tag_size)

    %{
      name: name,
      crypto: crypto,
      key_size: key_size,
      iv: :crypto.strong_rand_bytes(iv_size),
      tag_size: tag_size
    }
  end

  defp check_tag_size!(mode, tag_size) do
    if tag_size in @tag_sizes[mode],
      do: tag_size,
      else: raise(ArgumentError, "invalid tag size #{inspect(tag_size)} for #{mode}")
  end

  @doc "A random key for the cipher."
  @spec random_key(t()) :: binary()
  def random_key(%{key_size: size}), do: :crypto.strong_rand_bytes(size)

  ## AlgorithmIdentifier

  @doc """
  The AlgorithmIdentifier of a cipher. The tag size of GCM and CCM is left
  out when it is the default, 12.
  """
  @spec identifier(t()) :: DER.term_()
  def identifier(%{name: name, iv: iv} = cipher) do
    params =
      case mode(cipher) do
        {:cbc, _} when name == :rc2_cbc -> {:seq, [{:int, rc2_version(cipher)}, {:octets, iv}]}
        {:cbc, _} -> {:octets, iv}
        :chacha -> {:octets, iv}
        _ when cipher.tag_size == 12 -> {:seq, [{:octets, iv}]}
        _ -> {:seq, [{:octets, iv}, {:int, cipher.tag_size}]}
      end

    {:seq, [{:oid, name}, params]}
  end

  defp rc2_version(%{key_size: size}) do
    Enum.find_value(@rc2_versions, fn {version, s} -> if s == size, do: version end)
  end

  @doc """
  Reads a content-encryption AlgorithmIdentifier. Returns
  `:unsupported_algorithm` for an algorithm this library does not decrypt,
  `:malformed` for parameters that do not fit it, and `:not_available`
  when the `:crypto` of this system refuses it.
  """
  @spec read(Cmsex.Algorithm.t()) :: {:ok, t()} | {:error, Cmsex.Error.reason(), term()}
  def read({oid, params}) do
    name = OID.name(oid)

    result =
      case Map.fetch(@ciphers, name) do
        {:ok, {crypto, key_size, mode}} -> read_params(mode, params, name, crypto, key_size)
        :error when name == :rc2_cbc -> read_rc2(params)
        :error -> :unsupported
      end

    case result do
      {:ok, cipher} -> available(cipher)
      :unsupported -> {:error, :unsupported_algorithm, oid}
      :error -> {:error, :malformed, oid}
    end
  end

  defp read_params({:cbc, block_size}, params, name, crypto, key_size) do
    case params do
      {0x04, iv, _} when byte_size(iv) == block_size -> {:ok, cipher(name, crypto, key_size, iv)}
      _ -> :error
    end
  end

  defp read_params(:chacha, {0x04, <<_::binary-size(12)>> = nonce, _}, name, crypto, key_size),
    do: {:ok, %{cipher(name, crypto, key_size, nonce) | tag_size: 16}}

  defp read_params(mode, {0x30, _, _} = params, name, crypto, key_size)
       when mode in [:gcm, :ccm] do
    with {:ok, nonce, tag_size} <- aead_params(DER.children(params)),
         true <- nonce_size?(mode, byte_size(nonce)),
         true <- tag_size in @tag_sizes[mode] do
      {:ok, %{cipher(name, crypto, key_size, nonce) | tag_size: tag_size}}
    else
      _ -> :error
    end
  end

  defp read_params(_mode, _params, _name, _crypto, _key_size), do: :error

  # GCMParameters and CCMParameters: the nonce, and the tag size, 12 by
  # default.
  defp aead_params([{0x04, nonce, _}]), do: {:ok, nonce, 12}

  defp aead_params([{0x04, nonce, _}, size]) do
    case DER.integer(size) do
      {:ok, size} -> {:ok, nonce, size}
      :error -> :error
    end
  end

  defp aead_params(_fields), do: :error

  defp nonce_size?(:gcm, size), do: size >= 1
  defp nonce_size?(:ccm, size), do: size in 7..13

  defp read_rc2({0x30, _, _} = params) do
    with [version, {0x04, <<_::binary-size(8)>> = iv, _}] <- DER.children(params),
         {:ok, version} <- DER.integer(version) do
      case Map.fetch(@rc2_versions, version) do
        {:ok, key_size} -> {:ok, cipher(:rc2_cbc, :rc2_cbc, key_size, iv)}
        :error -> :unsupported
      end
    else
      _ -> :error
    end
  end

  defp read_rc2(_params), do: :error

  defp cipher(name, crypto, key_size, iv),
    do: %{name: name, crypto: crypto, key_size: key_size, iv: iv, tag_size: nil}

  defp available(%{crypto: crypto, name: name} = cipher) do
    if crypto in :crypto.supports(:ciphers),
      do: {:ok, cipher},
      else: {:error, :not_available, name}
  end

  ## Encryption

  @doc """
  Encrypts `plaintext` with `key`. CBC pads the plaintext (RFC 5652, 6.3)
  and returns no tag; the authenticated ciphers take `aad` and return the
  tag. Raises ArgumentError for a key of the wrong size.
  """
  @spec encrypt(t(), binary(), binary(), iodata()) :: {binary(), binary() | nil}
  def encrypt(cipher, key, plaintext, aad \\ <<>>) do
    unless byte_size(key) == cipher.key_size,
      do: raise(ArgumentError, "the key of #{cipher.name} must be #{cipher.key_size} bytes")

    case mode(cipher) do
      {:cbc, block_size} ->
        padding = block_size - rem(byte_size(plaintext), block_size)
        padded = [plaintext, :binary.copy(<<padding>>, padding)]
        {:crypto.crypto_one_time(cipher.crypto, key, cipher.iv, padded, true), nil}

      _ ->
        {ciphertext, tag} =
          :crypto.crypto_one_time_aead(
            cipher.crypto,
            key,
            cipher.iv,
            plaintext,
            aad,
            cipher.tag_size,
            true
          )

        {ciphertext, tag}
    end
  end

  @doc """
  Decrypts `ciphertext` with `key`. Returns `:error` for a key of the wrong
  size, a ciphertext that is not whole blocks, bad padding, or a tag that
  does not check or is not of the size the parameters say. Nothing tells
  these apart.
  """
  @spec decrypt(t(), binary(), binary(), iodata(), binary() | nil) :: {:ok, binary()} | :error
  def decrypt(cipher, key, ciphertext, aad \\ <<>>, tag \\ nil)

  def decrypt(%{key_size: size}, key, _ciphertext, _aad, _tag) when byte_size(key) != size,
    do: :error

  def decrypt(cipher, key, ciphertext, aad, tag) do
    case mode(cipher) do
      {:cbc, block_size} -> cbc_decrypt(cipher, key, ciphertext, block_size)
      _ -> aead_decrypt(cipher, key, ciphertext, aad, tag)
    end
  end

  defp cbc_decrypt(cipher, key, ciphertext, block_size) do
    if ciphertext != <<>> and rem(byte_size(ciphertext), block_size) == 0 do
      cipher.crypto
      |> :crypto.crypto_one_time(key, cipher.iv, ciphertext, false)
      |> unpad(block_size)
    else
      :error
    end
  end

  # `:crypto` takes a tag shorter than the one it would write, so its size
  # is checked here.
  defp aead_decrypt(cipher, key, ciphertext, aad, tag) do
    if is_binary(tag) and byte_size(tag) == cipher.tag_size do
      case :crypto.crypto_one_time_aead(
             cipher.crypto,
             key,
             cipher.iv,
             ciphertext,
             aad,
             tag,
             false
           ) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        :error -> :error
      end
    else
      :error
    end
  end

  # RFC 5652, 6.3: k - (l mod k) octets, all of that value.
  defp unpad(padded, block_size) do
    size = byte_size(padded)
    padding = :binary.last(padded)

    if padding in 1..block_size and
         binary_part(padded, size - padding, padding) == :binary.copy(<<padding>>, padding),
       do: {:ok, binary_part(padded, 0, size - padding)},
       else: :error
  end

  defp mode(%{name: :rc2_cbc}), do: {:cbc, 8}
  defp mode(%{name: name}), do: elem(Map.fetch!(@ciphers, name), 2)
end
