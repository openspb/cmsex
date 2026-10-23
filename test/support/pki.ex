defmodule Cmsex.TestPKI do
  @moduledoc false
  # Keys and certificates made on the fly for the tests, with the DER
  # writer of the library. Keys are cached per test run, since RSA key
  # generation is slow.

  import Bitwise

  alias Cmsex.{DER, Digest, Key}

  @doc """
  A private key as a `:public_key` record (or `{public, private}` for the
  Montgomery curves), cached by name. Names: `:rsa1024`, `:rsa2048`,
  `:rsa3072`, `:p256`, `:p384`, `:p521`, `:brainpool256`, `:ed25519`,
  `:ed448`, `:x25519`, `:x448`, and any of them with a suffix, such as
  `{:rsa2048, :other}`, for a second key of the same kind.
  """
  def key(name) do
    case :persistent_term.get({__MODULE__, name}, nil) do
      nil ->
        key = generate(kind(name))
        :persistent_term.put({__MODULE__, name}, key)
        key

      key ->
        key
    end
  end

  defp kind({name, _suffix}), do: name
  defp kind(name), do: name

  defp generate(:rsa1024), do: :public_key.generate_key({:rsa, 1024, 65_537})
  defp generate(:rsa2048), do: :public_key.generate_key({:rsa, 2048, 65_537})
  defp generate(:rsa3072), do: :public_key.generate_key({:rsa, 3072, 65_537})
  defp generate(:rsa_e3), do: :public_key.generate_key({:rsa, 2048, 3})
  defp generate(:p256), do: :public_key.generate_key({:namedCurve, :secp256r1})
  defp generate(:p384), do: :public_key.generate_key({:namedCurve, :secp384r1})
  defp generate(:p521), do: :public_key.generate_key({:namedCurve, :secp521r1})
  defp generate(:brainpool256), do: :public_key.generate_key({:namedCurve, :brainpoolP256r1})
  defp generate(:ed25519), do: :public_key.generate_key({:namedCurve, :ed25519})
  defp generate(:ed448), do: :public_key.generate_key({:namedCurve, :ed448})
  defp generate(:x25519), do: :crypto.generate_key(:ecdh, :x25519)
  defp generate(:x448), do: :crypto.generate_key(:ecdh, :x448)

  @doc "A private key in PKCS #8 DER."
  def pkcs8({public, private}) when is_binary(public) do
    raise ArgumentError, "use montgomery_pkcs8/2 for #{byte_size(private)}-byte keys"
  end

  def pkcs8(record), do: :public_key.der_encode(:PrivateKeyInfo, record)

  @doc "An X25519 or X448 private key in PKCS #8 DER (RFC 8410)."
  def montgomery_pkcs8(type, {_public, private}) do
    DER.encode(
      {:seq, [{:int, 0}, {:seq, [{:oid, type}]}, {:octets, DER.encode({:octets, private})}]}
    )
  end

  @doc "The library's view of a test key."
  def private(name) do
    case key(name) do
      {public, private} when is_binary(public) ->
        type = if byte_size(public) == 32, do: :x25519, else: :x448
        {type, private, public}

      record ->
        {:ok, key} = Key.parse(record)
        key
    end
  end

  @doc """
  A certificate in DER for the key `name`. Options:

    * `:issuer` - `{issuer_certificate_der, issuer_key_name}`; self-signed
      if absent.
    * `:subject` - the common name (default: the key name).
    * `:string_type` - `:utf8` (default) or `:printable` for the names.
    * `:serial` - default: random, 16 bytes.
    * `:ski` - `true` (default), `false`, or the identifier.
    * `:key_usage` - a list of bit positions, or `nil` for no extension.
    * `:ca` - adds basicConstraints cA, keyCertSign and cRLSign.
    * `:pss_key` - writes an RSA key as id-RSASSA-PSS, with the parameters
      `%{hash: ..., salt_length: ...}`, or `true` for none.
    * `:not_before`, `:not_after`.
    * `:extensions` - extra extensions as DER terms.
  """
  def cert(name, opts \\ []) do
    key = private(name)

    subject =
      name_term(Keyword.get(opts, :subject, label(name)), Keyword.get(opts, :string_type, :utf8))

    {issuer_name, issuer_key, issuer_ski} =
      case Keyword.get(opts, :issuer) do
        nil ->
          {subject, key, nil}

        {issuer_der, issuer_key_name} ->
          {:ok, issuer} = Cmsex.Certificate.parse(issuer_der)
          {{:raw, issuer.subject}, private(issuer_key_name), issuer.subject_key_identifier}
      end

    spki = spki(key, Keyword.get(opts, :pss_key))
    ski = ski_value(Keyword.get(opts, :ski, true), spki)

    serial =
      Keyword.get_lazy(opts, :serial, fn ->
        :binary.decode_unsigned(:crypto.strong_rand_bytes(16)) >>> 1
      end)

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    not_before = Keyword.get(opts, :not_before, DateTime.add(now, -86_400))
    not_after = Keyword.get(opts, :not_after, DateTime.add(now, 3650 * 86_400))
    {sig_alg, scheme, hash} = cert_signature(issuer_key)

    extensions =
      [
        ski && ext(:subject_key_identifier, {:octets, ski}),
        issuer_ski && ext(:authority_key_identifier, {:seq, [{:primitive, 0x80, issuer_ski}]}),
        key_usage_ext(opts),
        Keyword.get(opts, :ca) && ext(:basic_constraints, {:seq, [{:bool, true}]}, true)
      ]
      |> Enum.reject(&(&1 in [nil, false]))
      |> Kernel.++(Keyword.get(opts, :extensions, []))

    tbs =
      DER.encode(
        {:seq,
         [
           {:explicit, 0, {:int, 2}},
           {:int, serial},
           sig_alg,
           issuer_name,
           {:seq, [{:time, not_before}, {:time, not_after}]},
           subject,
           {:raw, spki},
           {:explicit, 3, {:seq, extensions}}
         ]}
      )

    data = if scheme in [:ed25519, :ed448], do: tbs, else: Digest.hash(hash, tbs)
    signature = Key.sign(issuer_key, scheme, hash, data, nil)
    DER.encode({:seq, [{:raw, tbs}, sig_alg, {:bits, signature}]})
  end

  defp label({name, suffix}), do: "Test #{name} #{suffix}"
  defp label(name), do: "Test #{name}"

  defp name_term(cn, type) do
    {:seq,
     [
       {:set, [{:seq, [{:oid, {2, 5, 4, 6}}, {:printable, "BR"}]}]},
       {:set, [{:seq, [{:oid, {2, 5, 4, 10}}, {type, "cmsex tests"}]}]},
       {:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {type, cn}]}]}
     ]}
  end

  defp spki({:rsa, _key, n, e}, pss) do
    alg =
      case pss do
        nil -> {:seq, [{:oid, :rsa_encryption}, :null]}
        true -> {:seq, [{:oid, :rsassa_pss}]}
        %{hash: hash} = params -> pss_alg(hash, Map.get(params, :salt_length, Digest.size(hash)))
      end

    DER.encode({:seq, [alg, {:bits, DER.encode({:seq, [{:int, n}, {:int, e}]})}]})
  end

  defp spki({:ec, curve, _private, point}, _pss),
    do: DER.encode({:seq, [{:seq, [{:oid, :ec_public_key}, {:oid, curve}]}, {:bits, point}]})

  defp spki({type, _private, public}, _pss),
    do: DER.encode({:seq, [{:seq, [{:oid, type}]}, {:bits, public}]})

  defp pss_alg(hash, salt) do
    hash_id = {:seq, [{:oid, hash}, :null]}

    {:seq,
     [
       {:oid, :rsassa_pss},
       {:seq,
        [
          {:explicit, 0, hash_id},
          {:explicit, 1, {:seq, [{:oid, :mgf1}, hash_id]}},
          {:explicit, 2, {:int, salt}}
        ]}
     ]}
  end

  defp ski_value(false, _spki), do: nil

  defp ski_value(true, spki) do
    {:ok, el} = DER.decode(spki)
    [_, bits] = DER.children(el)
    {:ok, key} = DER.bit_string(bits)
    :crypto.hash(:sha, key)
  end

  defp ski_value(ski, _spki) when is_binary(ski), do: ski

  defp key_usage_ext(opts) do
    usage =
      cond do
        Keyword.has_key?(opts, :key_usage) -> Keyword.get(opts, :key_usage)
        Keyword.get(opts, :ca) -> [5, 6]
        true -> [0, 1]
      end

    usage && ext(:key_usage, {:named_bits, usage}, true)
  end

  defp ext(oid, value, critical \\ false) do
    {:seq,
     [{:oid, oid}] ++
       if(critical, do: [{:bool, true}], else: []) ++ [{:octets, DER.encode(value)}]}
  end

  defp cert_signature({:rsa, _, _, _}),
    do: {{:seq, [{:oid, :sha256_with_rsa_encryption}, :null]}, :rsa_pkcs1, :sha256}

  defp cert_signature({:ec, _, _, _}), do: {{:seq, [{:oid, :ecdsa_with_sha256}]}, :ecdsa, :sha256}
  defp cert_signature({:ed25519, _, _}), do: {{:seq, [{:oid, :ed25519}]}, :ed25519, nil}
  defp cert_signature({:ed448, _, _}), do: {{:seq, [{:oid, :ed448}]}, :ed448, nil}
end
