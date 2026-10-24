defmodule Cmsex.Key do
  @moduledoc false
  # Private keys and the operations of `:crypto` on them and on the public
  # keys of `Cmsex.Certificate`.
  #
  # A private key is one of:
  #
  #   {:rsa, crypto_key, n, e}       crypto_key = [e, n, d, p, q, dp, dq, qinv]
  #   {:ec, curve, private, point}   curve as in Cmsex.OID
  #   {:ed25519 | :ed448 | :x25519 | :x448, private, public}
  #
  # The RSA numbers go to `:crypto` as binaries, which it reads faster than
  # integers: a third of the time of an RSA-2048 verification went to that.

  alias Cmsex.{Algorithm, DER, Digest, OID}

  @type private_key ::
          {:rsa, [binary()], pos_integer(), pos_integer()}
          | {:ec, atom(), binary(), binary()}
          | {:ed25519 | :ed448 | :x25519 | :x448, binary(), binary()}

  @curves %{
    secp256r1: :secp256r1,
    secp384r1: :secp384r1,
    secp521r1: :secp521r1,
    brainpool_p256r1: :brainpoolP256r1,
    brainpool_p384r1: :brainpoolP384r1,
    brainpool_p512r1: :brainpoolP512r1
  }

  @doc "The named curves of ECDSA and ECDH."
  @spec curves() :: [atom()]
  def curves, do: Map.keys(@curves)

  @doc "The name `:crypto` uses for a curve."
  @spec crypto_curve(atom()) :: atom()
  def crypto_curve(curve), do: Map.fetch!(@curves, curve)

  ## Reading

  @doc """
  Reads a private key: a PrivateKeyInfo or OneAsymmetricKey (PKCS #8,
  RFC 5958), an RSAPrivateKey (PKCS #1) or an ECPrivateKey (RFC 5915), in
  DER, or a key record of `:public_key`.
  """
  @spec parse(term()) :: {:ok, private_key()} | :error
  def parse(der) when is_binary(der) do
    case DER.decode(der) do
      {:ok, {0x30, _, _} = seq} -> parse_sequence(DER.children(seq))
      _ -> :error
    end
  end

  def parse({:RSAPrivateKey, _v, n, e, d, p, q, dp, dq, qinv, _other}) do
    rsa([n, e, d, p, q, dp, dq, qinv])
  end

  def parse({:ECPrivateKey, _v, private, {:namedCurve, curve}, public, _attributes}),
    do: from_curve(OID.name(curve), private, public)

  def parse({:ECPrivateKey, _v, private, {:namedCurve, curve}, public}),
    do: from_curve(OID.name(curve), private, public)

  # An RSASSA-PSS key, as `:public_key` returns it.
  def parse({{:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key, _params}), do: parse(key)

  def parse(record)
      when is_tuple(record) and elem(record, 0) in [:PrivateKeyInfo, :OneAsymmetricKey] do
    parse(:public_key.der_encode(:PrivateKeyInfo, record))
  rescue
    _ -> :error
  end

  def parse(_other), do: :error

  # PKCS #8 / RFC 5958.
  defp parse_sequence([{0x02, _, _} = version, {0x30, _, _} = alg, {0x04, private, _} | _]) do
    with {:ok, v} when v in [0, 1] <- DER.integer(version),
         {:ok, {oid, params}} <- Algorithm.read(alg) do
      pkcs8(OID.name(oid), params, private)
    else
      _ -> :error
    end
  end

  # PKCS #1.
  defp parse_sequence([{0x02, _, _} = version | ints]) when length(ints) >= 8 do
    with {:ok, 0} <- DER.integer(version),
         values = Enum.map(Enum.take(ints, 8), &DER.integer/1),
         true <- Enum.all?(values, &match?({:ok, _}, &1)) do
      rsa(Enum.map(values, fn {:ok, v} -> v end))
    else
      _ -> :error
    end
  end

  # RFC 5915.
  defp parse_sequence([{0x02, _, _} = version, {0x04, private, _} | rest]) do
    with {:ok, 1} <- DER.integer(version) do
      sec1(private, rest, nil)
    end
  end

  defp parse_sequence(_fields), do: :error

  defp pkcs8(name, _params, private) when name in [:rsa_encryption, :rsassa_pss] do
    with {:ok, {0x30, _, _} = seq} <- DER.decode(private),
         [{0x02, _, _} | _] = fields <- DER.children(seq) do
      parse_sequence(fields)
    else
      _ -> :error
    end
  end

  defp pkcs8(:ec_public_key, {0x06, _, _} = curve, private) do
    with {:ok, curve} <- DER.oid(curve),
         {:ok, {0x30, _, _} = seq} <- DER.decode(private),
         [{0x02, _, _} = version, {0x04, key, _} | rest] <- DER.children(seq),
         {:ok, 1} <- DER.integer(version) do
      sec1(key, rest, OID.name(curve))
    else
      _ -> :error
    end
  end

  defp pkcs8(name, nil, private) when name in [:ed25519, :ed448, :x25519, :x448] do
    case DER.decode(private) do
      {:ok, {0x04, key, _}} -> from_curve(name, key, nil)
      _ -> :error
    end
  end

  defp pkcs8(_name, _params, _private), do: :error

  # The curve comes from the PKCS #8 algorithm, or else from the
  # parameters inside the ECPrivateKey.
  defp sec1(private, rest, curve) do
    case curve || Enum.find_value(rest, &curve_parameter/1) do
      nil -> :error
      curve -> from_curve(curve, private, nil)
    end
  end

  defp curve_parameter({0xA0, _, _} = tagged) do
    with [oid] <- DER.children(tagged),
         {:ok, oid} <- DER.oid(oid) do
      OID.name(oid)
    else
      _ -> nil
    end
  end

  defp curve_parameter(_field), do: nil

  defp rsa([n, e, d, p, q, dp, dq, qinv]) when n > 0 and e > 0 and d > 0,
    do: {:ok, {:rsa, Enum.map([e, n, d, p, q, dp, dq, qinv], &:binary.encode_unsigned/1), n, e}}

  defp rsa(_values), do: :error

  defp from_curve(name, private, _public) when name in [:ed25519, :ed448] do
    {public, _} = :crypto.generate_key(:eddsa, name, private)
    {:ok, {name, private, public}}
  rescue
    _ -> :error
  end

  defp from_curve(name, private, _public) when name in [:x25519, :x448] do
    {public, _} = :crypto.generate_key(:ecdh, name, private)
    {:ok, {name, private, public}}
  rescue
    _ -> :error
  end

  defp from_curve(name, private, _public) when is_map_key(@curves, name) do
    {public, _} = :crypto.generate_key(:ecdh, crypto_curve(name), private)
    {:ok, {:ec, name, private, public}}
  rescue
    _ -> :error
  end

  defp from_curve(_name, _private, _public), do: :error

  @doc "The public key of a private key, in the form of `Cmsex.Certificate`."
  @spec public(private_key()) :: Cmsex.Certificate.public_key()
  def public({:rsa, _key, n, e}), do: {:rsa, n, e}
  def public({:ec, curve, _private, point}), do: {:ec, curve, point}
  def public({type, _private, public}), do: {type, public}

  @doc """
  Whether a private key belongs to a public key. An RSA key matches a
  certificate of either RSA type.
  """
  @spec matches?(private_key(), Cmsex.Certificate.public_key()) :: boolean()
  def matches?({:rsa, _key, n, e}, {:rsa, n, e}), do: true
  def matches?({:rsa, _key, n, e}, {:rsa_pss, n, e, _params}), do: true
  def matches?({:ec, curve, _private, point}, {:ec, curve, point}), do: true

  # A compressed point (SEC 1, 2.3.3): the same x and the parity of y.
  def matches?({:ec, curve, _private, <<4, rest::binary>>}, {:ec, curve, <<prefix, x::binary>>})
      when prefix in [2, 3] do
    size = div(byte_size(rest), 2)
    <<own_x::binary-size(^size), y::binary-size(^size)>> = rest
    parity = :binary.last(y) |> rem(2)
    own_x == x and prefix == 2 + parity
  end

  def matches?({type, _private, public}, {type, public}), do: true
  def matches?(_key, _public), do: false

  @doc "The scheme a key signs with, given the RSA padding asked for."
  @spec scheme(private_key() | Cmsex.Certificate.public_key(), :pkcs1 | :pss) ::
          Algorithm.scheme() | nil
  def scheme(key, padding) do
    case {elem(key, 0), padding} do
      {:rsa, :pkcs1} -> :rsa_pkcs1
      {:rsa, :pss} -> :rsa_pss
      {:rsa_pss, _} -> :rsa_pss
      {:ec, _} -> :ecdsa
      {:ed25519, _} -> :ed25519
      {:ed448, _} -> :ed448
      _ -> nil
    end
  end

  ## Signatures

  @doc """
  Signs. `data` is the digest of what is signed for RSA and ECDSA, and the
  message itself for EdDSA.
  """
  @spec sign(private_key(), Algorithm.scheme(), Digest.hash() | nil, binary(), map() | nil) ::
          binary()
  def sign({:rsa, key, _n, _e}, :rsa_pkcs1, hash, digest, _pss),
    do: :crypto.sign(:rsa, Digest.crypto(hash), {:digest, digest}, key)

  def sign({:rsa, key, _n, _e}, :rsa_pss, hash, digest, pss),
    do: :crypto.sign(:rsa, Digest.crypto(hash), {:digest, digest}, key, pss_options(pss))

  def sign({:ec, curve, private, _point}, :ecdsa, hash, digest, _pss),
    do:
      :crypto.sign(:ecdsa, Digest.crypto(hash), {:digest, digest}, [private, crypto_curve(curve)])

  def sign({type, private, _public}, type, _hash, message, _pss) when type in [:ed25519, :ed448],
    do: :crypto.sign(:eddsa, :none, message, [private, type])

  @doc "Verifies a signature; any failure, malformed input included, is `false`."
  @spec verify(
          Cmsex.Certificate.public_key(),
          Algorithm.scheme(),
          Digest.hash() | nil,
          binary(),
          binary(),
          map() | nil
        ) ::
          boolean()
  def verify(public_key, scheme, hash, data, signature, pss) do
    do_verify(public_key, scheme, hash, data, signature, pss) == true
  rescue
    _ -> false
  end

  defp do_verify({:rsa, n, e}, :rsa_pkcs1, hash, digest, signature, _pss),
    do: :crypto.verify(:rsa, Digest.crypto(hash), {:digest, digest}, signature, rsa_public(n, e))

  defp do_verify(key, :rsa_pss, hash, digest, signature, pss)
       when elem(key, 0) in [:rsa, :rsa_pss] do
    [_, n, e | _] = Tuple.to_list(key)

    :crypto.verify(
      :rsa,
      Digest.crypto(hash),
      {:digest, digest},
      signature,
      rsa_public(n, e),
      pss_options(pss)
    )
  end

  defp do_verify({:ec, curve, point}, :ecdsa, hash, digest, signature, _pss),
    do:
      :crypto.verify(:ecdsa, Digest.crypto(hash), {:digest, digest}, signature, [
        point,
        crypto_curve(curve)
      ])

  defp do_verify({type, public}, type, _hash, message, signature, _pss)
       when type in [:ed25519, :ed448],
       do: :crypto.verify(:eddsa, :none, message, signature, [public, type])

  defp do_verify(_key, _scheme, _hash, _data, _signature, _pss), do: false

  @doc "An RSA public key as `:crypto` takes it."
  @spec rsa_public(pos_integer(), pos_integer()) :: [binary()]
  def rsa_public(n, e), do: [:binary.encode_unsigned(e), :binary.encode_unsigned(n)]

  defp pss_options(pss) do
    [
      rsa_padding: :rsa_pkcs1_pss_padding,
      rsa_pss_saltlen: pss.salt_length,
      rsa_mgf1_md: Digest.crypto(pss.mgf_hash)
    ]
  end
end
