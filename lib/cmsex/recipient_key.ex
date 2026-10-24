defmodule Cmsex.RecipientKey do
  @moduledoc false
  # The content-encryption key and the recipients (RFC 5652, 6.2): wrapped
  # for each `Cmsex.Recipient` when writing, and recovered from a
  # RecipientInfo when decrypting. The same key may be the MAC key of an
  # AuthenticatedData.
  #
  # Decrypting reports two outcomes only: the key, or `:error`. What went
  # wrong (a wrong key, a key wrap or a padding that does not check) is not
  # told apart. RSA PKCS #1 v1.5 never fails here: a padding that does not
  # check gives a random key of the expected size (RFC 3218, 2.3), so that
  # the failure only shows when the content does not decrypt.

  import Bitwise

  alias Cmsex.{
    Algorithm,
    Certificate,
    Cipher,
    DER,
    Digest,
    KDF,
    Key,
    KeyWrap,
    LegacyWrap,
    OID,
    PasswordWrap,
    Recipient,
    RecipientInfo,
    Trust
  }

  @x963 %{
    std_dh_sha1kdf: :sha1,
    std_dh_sha224kdf: :sha224,
    std_dh_sha256kdf: :sha256,
    std_dh_sha384kdf: :sha384,
    std_dh_sha512kdf: :sha512,
    # The cofactor of the prime curves is 1, so cofactor ECDH is plain ECDH
    # on them (RFC 5753, 7.1.3).
    cofactor_dh_sha1kdf: :sha1,
    cofactor_dh_sha224kdf: :sha224,
    cofactor_dh_sha256kdf: :sha256,
    cofactor_dh_sha384kdf: :sha384,
    cofactor_dh_sha512kdf: :sha512
  }

  @hkdf %{std_dh_hkdf_sha256: :sha256, std_dh_hkdf_sha384: :sha384, std_dh_hkdf_sha512: :sha512}

  @aes_wraps [:aes128_wrap, :aes192_wrap, :aes256_wrap]
  @aes_wraps_pad [:aes128_wrap_pad, :aes192_wrap_pad, :aes256_wrap_pad]

  @prfs %{
    hmac_with_sha1: :sha1,
    hmac_sha224: :sha224,
    hmac_sha256: :sha256,
    hmac_sha384: :sha384,
    hmac_sha512: :sha512
  }

  ## Writing

  @doc """
  Checks a recipient before anything is encrypted: reads its certificate
  and chooses the way. Returns what `encrypt/2` takes, with the type and
  version of the RecipientInfo it will write.
  """
  @spec prepare(Recipient.t(), map()) :: {:ok, map()} | {:error, atom(), term()}
  def prepare(%Recipient{type: :certificate} = recipient, opts) do
    with {:ok, cert} <- certificate(recipient.certificate),
         {:ok, kind} <- kind(cert.public_key),
         :ok <- key_usage(cert, kind),
         :ok <- rsa_bits(kind, cert, opts),
         {:ok, rid} <- rid(recipient.options.identifier, cert, kind) do
      {type, version} =
        case {kind, rid} do
          {:rsa, {:primitive, 0x80, _}} -> {:key_transport, 2}
          {:rsa, _} -> {:key_transport, 0}
          _ -> {:key_agreement, 3}
        end

      {:ok,
       %{
         recipient: recipient,
         cert: cert,
         kind: kind,
         rid: rid,
         type: type,
         version: version
       }}
    end
  end

  def prepare(%Recipient{type: :kek} = recipient, _opts),
    do: {:ok, %{recipient: recipient, type: :kek, version: 4}}

  def prepare(%Recipient{type: :password} = recipient, _opts),
    do: {:ok, %{recipient: recipient, type: :password, version: 0}}

  defp certificate(der) do
    case Certificate.parse(der) do
      {:ok, cert} -> {:ok, cert}
      :error -> {:error, :invalid_certificate, nil}
    end
  end

  defp kind({:rsa, _n, _e}), do: {:ok, :rsa}

  defp kind({:ec, curve, _point}) do
    if curve in Key.curves(),
      do: {:ok, {:ec, curve}},
      else: {:error, :unsupported_algorithm, curve}
  end

  defp kind({type, _public}) when type in [:x25519, :x448], do: {:ok, type}
  defp kind({:unknown, oid}), do: {:error, :unsupported_algorithm, oid}
  defp kind(_signature_only), do: {:error, :invalid_recipient, :key_type}

  # RFC 5280, 4.2.1.3: keyEncipherment for key transport, keyAgreement for
  # key agreement.
  defp key_usage(%Certificate{key_usage: nil}, _kind), do: :ok

  defp key_usage(%Certificate{key_usage: usage}, kind) do
    needed = if kind == :rsa, do: :key_encipherment, else: :key_agreement
    if needed in usage, do: :ok, else: {:error, :invalid_recipient, :key_usage}
  end

  defp rsa_bits(:rsa, %Certificate{public_key: {:rsa, n, _e}}, opts) do
    bits = Algorithm.rsa_size(n)
    if bits >= opts.min_rsa_bits, do: :ok, else: {:error, :weak_key, bits}
  end

  defp rsa_bits(_kind, _cert, _opts), do: :ok

  # A KeyTransRecipientInfo names the certificate as rid; a
  # RecipientEncryptedKey, as rKeyId [0] IMPLICIT RecipientKeyIdentifier.
  defp rid(:issuer_and_serial, cert, _kind),
    do: {:ok, {:seq, [{:raw, cert.issuer}, {:int, cert.serial}]}}

  defp rid(:subject_key_identifier, %Certificate{subject_key_identifier: nil}, _kind),
    do: {:error, :invalid_certificate, :subject_key_identifier}

  defp rid(:subject_key_identifier, cert, :rsa),
    do: {:ok, {:primitive, 0x80, cert.subject_key_identifier}}

  defp rid(:subject_key_identifier, cert, _kind),
    do: {:ok, {:constructed, 0xA0, [{:octets, cert.subject_key_identifier}]}}

  @doc """
  The RecipientInfo of a prepared recipient, for the key `cek`. A public
  key that `:crypto` refuses, such as an EC point off the curve, gives
  `:invalid_recipient`.
  """
  @spec encrypt(map(), binary()) :: {:ok, DER.term_()} | {:error, atom(), term()}
  def encrypt(%{type: :key_transport, cert: cert} = prepared, cek) do
    {:rsa, n, e} = cert.public_key
    hash = prepared.recipient.options.oaep_digest

    encrypted_key =
      :crypto.public_encrypt(:rsa, cek, [e, n],
        rsa_padding: :rsa_pkcs1_oaep_padding,
        rsa_oaep_md: Digest.crypto(hash),
        rsa_mgf1_md: Digest.crypto(hash)
      )

    {:ok,
     {:seq,
      [
        {:int, prepared.version},
        prepared.rid,
        Algorithm.oaep_identifier(hash),
        {:octets, encrypted_key}
      ]}}
  rescue
    _ -> {:error, :invalid_recipient, :public_key}
  end

  # Ephemeral-static ECDH (RFC 5753, 3.1.1; RFC 8418, 3): a key pair for
  # this recipient alone, discarded after.
  def encrypt(%{type: :key_agreement} = prepared, cek) do
    options = prepared.recipient.options
    scheme = options.key_agreement || default_scheme(prepared.kind)
    wrap = options.key_wrap || default_wrap(byte_size(cek))
    wrap_id = DER.encode({:seq, [{:oid, wrap}]})

    with {:ok, originator_alg, public, shared} <-
           ephemeral(prepared.kind, prepared.cert.public_key) do
      kek = kek(scheme, shared, wrap_id, options.ukm, Recipient.wrap_size(wrap))

      {:ok,
       {:constructed, 0xA1,
        Enum.reject(
          [
            {:int, 3},
            {:explicit, 0, {:constructed, 0xA1, [originator_alg, {:bits, public}]}},
            options.ukm && {:explicit, 1, {:octets, options.ukm}},
            {:seq, [{:oid, scheme}, {:raw, wrap_id}]},
            {:seq, [{:seq, [prepared.rid, {:octets, wrap(wrap, kek, cek)}]}]}
          ],
          &is_nil/1
        )}}
    end
  end

  def encrypt(%{type: :kek, recipient: recipient}, cek) do
    %{key_wrap: wrap, date: date, other: other} = recipient.options

    kekid =
      Enum.reject(
        [
          {:octets, recipient.key_id},
          date &&
            {:generalized_time,
             date |> DateTime.shift_zone!("Etc/UTC") |> DateTime.truncate(:second)},
          other && other_key_attribute(other)
        ],
        &is_nil/1
      )

    {:ok,
     {:constructed, 0xA2,
      [
        {:int, 4},
        {:seq, kekid},
        {:seq, [{:oid, wrap}]},
        {:octets, wrap(wrap, recipient.secret, cek)}
      ]}}
  end

  # RFC 3211: PBKDF2 with the PRF written out, since the default is
  # hmacWithSHA1, and id-alg-PWRI-KEK over AES-CBC.
  def encrypt(%{type: :password, recipient: recipient}, cek) do
    %{iterations: iterations, salt: salt, prf: prf, kek_cipher: name} = recipient.options
    salt = salt || :crypto.strong_rand_bytes(16)
    cipher = Cipher.new(name)
    kek = KDF.pbkdf2(Map.fetch!(@prfs, prf), recipient.secret, salt, iterations, cipher.key_size)
    encrypted_key = PasswordWrap.wrap(cipher.crypto, kek, cipher.iv, 16, cek)

    {:ok,
     {:constructed, 0xA3,
      [
        {:int, 0},
        {:constructed, 0xA0,
         [
           {:oid, :pbkdf2},
           {:seq, [{:octets, salt}, {:int, iterations}, {:seq, [{:oid, prf}, :null]}]}
         ]},
        {:seq, [{:oid, :pwri_kek}, Cipher.identifier(cipher)]},
        {:octets, encrypted_key}
      ]}}
  end

  defp other_key_attribute({oid, nil}), do: {:seq, [{:oid, oid}]}
  defp other_key_attribute({oid, value}), do: {:seq, [{:oid, oid}, {:raw, value}]}

  # X9.63 with the hash of the size of the curve (RFC 5753, 8); HKDF for
  # X25519 (RFC 8551, 2.3) and X448.
  defp default_scheme({:ec, curve}) do
    case curve do
      c when c in [:secp384r1, :brainpool_p384r1] -> :std_dh_sha384kdf
      c when c in [:secp521r1, :brainpool_p512r1] -> :std_dh_sha512kdf
      _ -> :std_dh_sha256kdf
    end
  end

  defp default_scheme(:x25519), do: :std_dh_hkdf_sha256
  defp default_scheme(:x448), do: :std_dh_hkdf_sha512

  # The key wrap of the size of the key it wraps (RFC 8551, 2.3).
  defp default_wrap(16), do: :aes128_wrap
  defp default_wrap(24), do: :aes192_wrap
  defp default_wrap(_size), do: :aes256_wrap

  defp ephemeral({:ec, curve}, {:ec, curve, point}) do
    crypto_curve = Key.crypto_curve(curve)
    {public, private} = :crypto.generate_key(:ecdh, crypto_curve)
    shared = :crypto.compute_key(:ecdh, point, private, crypto_curve)
    {:ok, {:seq, [{:oid, :ec_public_key}]}, public, shared}
  rescue
    _ -> {:error, :invalid_recipient, :public_key}
  end

  # RFC 8418, 2: an all-zero secret means a peer key of small order.
  defp ephemeral(type, {type, peer}) do
    {public, private} = :crypto.generate_key(:ecdh, type)
    shared = :crypto.compute_key(:ecdh, peer, private, type)

    if zero?(shared),
      do: {:error, :invalid_recipient, :public_key},
      else: {:ok, {:seq, [{:oid, type}]}, public, shared}
  rescue
    _ -> {:error, :invalid_recipient, :public_key}
  end

  defp wrap(name, kek, cek) when name in @aes_wraps, do: KeyWrap.wrap(kek, cek)
  defp wrap(name, kek, cek) when name in @aes_wraps_pad, do: KeyWrap.wrap_with_padding(kek, cek)

  # ECC-CMS-SharedInfo (RFC 5753, 7.2): the key wrap, the ukm and the size
  # of the key-encryption key in bits.
  defp kek(scheme, shared, wrap_id, ukm, size) do
    shared_info =
      DER.encode(
        {:seq,
         Enum.reject(
           [
             {:raw, wrap_id},
             ukm && {:explicit, 0, {:octets, ukm}},
             {:explicit, 2, {:octets, <<size * 8::32>>}}
           ],
           &is_nil/1
         )}
      )

    case scheme do
      _ when is_map_key(@x963, scheme) ->
        KDF.x963(@x963[scheme], shared, shared_info, size)

      _ ->
        KDF.hkdf(@hkdf[scheme], ukm || <<>>, shared, shared_info, size)
    end
  end

  defp zero?(bytes), do: bytes == :binary.copy(<<0>>, byte_size(bytes))

  ## Decrypting

  @doc """
  The credentials of `Cmsex.decrypt/2`, read: the key and certificate,
  checked against each other, the KEK and the password.
  """
  @spec credentials(map()) :: {:ok, map()} | {:error, atom(), term()}
  def credentials(opts) do
    with {:ok, cert} <- optional_certificate(opts[:certificate]),
         {:ok, key} <- optional_key(opts[:key], cert) do
      {:ok, %{cert: cert, key: key, kek: opts[:kek], password: opts[:password]}}
    end
  end

  defp optional_certificate(nil), do: {:ok, nil}
  defp optional_certificate(der), do: certificate(der)

  defp optional_key(nil, _cert), do: {:ok, nil}
  defp optional_key(fun, _cert) when is_function(fun, 1), do: {:ok, {:external, fun}}

  defp optional_key(key, cert) do
    case Key.parse(key) do
      {:ok, key} ->
        if Key.matches?(key, cert.public_key),
          do: {:ok, {:local, key}},
          else: {:error, :key_certificate_mismatch, nil}

      :error ->
        {:error, :invalid_key, nil}
    end
  end

  @doc """
  The RecipientInfos the credentials can open, in the order of the
  message, each with what opens it.
  """
  @spec candidates([RecipientInfo.t()], map()) :: [{non_neg_integer(), RecipientInfo.t(), term()}]
  def candidates(recipient_infos, credentials) do
    for {info, index} <- Enum.with_index(recipient_infos),
        target = target(info, credentials),
        target != nil,
        do: {index, info, target}
  end

  defp target(%RecipientInfo{type: :key_transport, rid: rid}, %{cert: cert, key: key})
       when cert != nil and key != nil do
    if match?({:rsa, _, _}, cert.public_key) and names?(rid, cert), do: :key_transport
  end

  defp target(%RecipientInfo{type: :key_agreement} = info, %{cert: cert, key: key})
       when cert != nil and key != nil do
    with true <- agreement_key?(cert.public_key),
         {_rid, encrypted_key} <-
           Enum.find(info.recipient_encrypted_keys, fn {rid, _} -> names?(rid, cert) end) do
      {:key_agreement, encrypted_key}
    else
      _ -> nil
    end
  end

  defp target(%RecipientInfo{type: :kek, rid: {:kek, id}}, %{kek: {id, _key}}), do: :kek

  defp target(%RecipientInfo{type: :password}, %{password: password}) when password != nil,
    do: :password

  defp target(_info, _credentials), do: nil

  defp agreement_key?({:ec, _curve, _point}), do: true
  defp agreement_key?({type, _public}), do: type in [:x25519, :x448]
  defp agreement_key?(_public_key), do: false

  defp names?({:issuer_and_serial, issuer, serial}, cert),
    do: cert.serial == serial and Trust.same_name?(issuer, cert.issuer)

  defp names?({:subject_key_identifier, ski}, cert), do: cert.subject_key_identifier == ski
  defp names?(_rid, _cert), do: false

  @doc """
  Recovers the content-encryption key of `size` bytes from one candidate.
  `context` has the certificates of the message, for an originator named
  by its certificate, and `:max_iterations`.

  Returns `{:ok, key}`, `:error` when it does not decrypt, or
  `{:error, reason, detail}` for an algorithm this library does not
  implement, parameters that do not fit it, or a limit.
  """
  @spec recover({non_neg_integer(), RecipientInfo.t(), term()}, map(), pos_integer(), map()) ::
          {:ok, binary()} | :error | {:error, atom(), term()}
  def recover({_index, info, :key_transport}, credentials, size, _context),
    do: key_transport(info, credentials.key, size)

  def recover({_index, info, {:key_agreement, encrypted_key}}, credentials, size, context),
    do: key_agreement(info, encrypted_key, credentials, size, context)

  def recover({_index, info, :kek}, %{kek: {_id, kek}}, size, _context) do
    {oid, params} = info.raw.key_encryption_algorithm
    sized(unwrap(OID.name(oid), oid, params, kek, info.encrypted_key), size)
  end

  def recover({_index, info, :password}, credentials, size, context),
    do: password(info, credentials.password, size, context)

  ## Key transport

  defp key_transport(info, key, size) do
    {oid, params} = info.raw.key_encryption_algorithm

    case OID.name(oid) do
      :rsaes_oaep ->
        with {:ok, oaep} <- Algorithm.oaep_params(params),
             do: sized(oaep_decrypt(key, info.encrypted_key, oaep), size)

      :rsa_encryption ->
        if params == nil or DER.null?(params),
          do: {:ok, pkcs1_decrypt(key, info.encrypted_key, size)},
          else: {:error, :malformed, oid}

      _ ->
        {:error, :unsupported_algorithm, oid}
    end
  end

  defp oaep_decrypt({:local, {:rsa, key, _n, _e}}, encrypted_key, oaep) do
    label = if oaep.label == <<>>, do: [], else: [rsa_oaep_label: oaep.label]

    {:ok,
     :crypto.private_decrypt(
       :rsa,
       encrypted_key,
       key,
       [
         rsa_padding: :rsa_pkcs1_oaep_padding,
         rsa_oaep_md: Digest.crypto(oaep.hash),
         rsa_mgf1_md: Digest.crypto(oaep.mgf_hash)
       ] ++ label
     )}
  rescue
    _ -> :error
  end

  defp oaep_decrypt({:external, fun}, encrypted_key, oaep) do
    external(fun, %{
      operation: :decrypt,
      ciphertext: encrypted_key,
      padding: :oaep,
      hash: oaep.hash,
      mgf_hash: oaep.mgf_hash,
      label: oaep.label
    })
  end

  defp oaep_decrypt(_key, _encrypted_key, _oaep), do: :error

  # RFC 3218, 2.3: the key that came out if the padding checks and the
  # size is the expected one, else a random key; both are computed every
  # time, and the choice is made with a mask rather than a branch.
  defp pkcs1_decrypt(key, encrypted_key, size) do
    random = :crypto.strong_rand_bytes(size)

    case raw_decrypt(key, encrypted_key, size) do
      {:block, block} -> select(pkcs1_check(block, size), block, random, size)
      {:plain, plain} when byte_size(plain) == size -> plain
      _ -> random
    end
  end

  defp raw_decrypt({:local, {:rsa, key, n, _e}}, encrypted_key, _size) do
    k = byte_size(:binary.encode_unsigned(n))
    encrypted_key = left_pad(encrypted_key, k)

    {:block,
     left_pad(:crypto.private_decrypt(:rsa, encrypted_key, key, rsa_padding: :rsa_no_padding), k)}
  rescue
    _ -> :error
  end

  defp raw_decrypt({:external, fun}, encrypted_key, _size) do
    case external(fun, %{operation: :decrypt, ciphertext: encrypted_key, padding: :pkcs1}) do
      {:ok, plain} -> {:plain, plain}
      :error -> :error
    end
  end

  defp raw_decrypt(_key, _encrypted_key, _size), do: :error

  defp left_pad(bytes, k) when byte_size(bytes) < k,
    do: :binary.copy(<<0>>, k - byte_size(bytes)) <> bytes

  defp left_pad(bytes, _k), do: bytes

  # EM = 0x00 || 0x02 || PS || 0x00 || M (RFC 8017, 7.2.2), with M of
  # `size` bytes and PS of at least 8 non-zero bytes. Returns 1 when it
  # checks, 0 otherwise, after looking at every byte.
  defp pkcs1_check(block, size) do
    ps_size = byte_size(block) - 3 - size

    if ps_size >= 8 do
      <<first, second, ps::binary-size(ps_size), separator, _m::binary-size(size)>> = block
      zeros = for <<b <- ps>>, reduce: 0, do: (acc -> acc ||| ((b - 1) >>> 8 &&& 1))
      bad = first ||| bxor(second, 2) ||| separator ||| zeros
      (bad - 1) >>> 8 &&& 1
    else
      0
    end
  end

  defp select(valid, block, random, size) do
    mask = -valid
    m = :binary.decode_unsigned(binary_part(block, byte_size(block) - size, size))
    r = :binary.decode_unsigned(random)
    <<(m &&& mask) ||| (r &&& bnot(mask))::size(size * 8)>>
  end

  ## Key agreement

  defp key_agreement(info, encrypted_key, credentials, size, context) do
    {oid, params} = info.raw.key_encryption_algorithm
    scheme = OID.name(oid)

    with :ok <- known_scheme(scheme, oid),
         {:ok, {wrap_oid, wrap_params}} <- wrap_algorithm(params, oid),
         {:ok, wrap_size} <- wrap_key_size(OID.name(wrap_oid), wrap_oid, wrap_params),
         {:ok, peer} <- originator_key(info, credentials.cert, context) do
      case agree(credentials.key, credentials.cert.public_key, peer) do
        {:ok, shared} ->
          kek = kek(scheme, shared, wrap_id(wrap_oid, wrap_params), info.ukm, wrap_size)
          sized(unwrap(OID.name(wrap_oid), wrap_oid, wrap_params, kek, encrypted_key), size)

        :error ->
          :error
      end
    end
  end

  # The keyInfo of the SharedInfo is the KeyWrapAlgorithm in DER, written
  # again rather than taken as received, which may be BER.
  defp wrap_id(oid, nil), do: DER.encode({:seq, [{:oid, oid}]})
  defp wrap_id(oid, {_, _, raw}), do: DER.encode({:seq, [{:oid, oid}, {:raw, raw}]})

  defp known_scheme(scheme, _oid) when is_map_key(@x963, scheme) or is_map_key(@hkdf, scheme),
    do: :ok

  defp known_scheme(_scheme, oid), do: {:error, :unsupported_algorithm, oid}

  # The parameters of the scheme are the KeyWrapAlgorithm.
  defp wrap_algorithm({0x30, _, _} = params, oid) do
    case Algorithm.read(params) do
      {:ok, alg} -> {:ok, alg}
      :error -> {:error, :malformed, oid}
    end
  end

  defp wrap_algorithm(_params, oid), do: {:error, :malformed, oid}

  defp wrap_key_size(name, oid, params) when name in @aes_wraps or name in @aes_wraps_pad do
    if params == nil, do: {:ok, Recipient.wrap_size(name)}, else: {:error, :malformed, oid}
  end

  defp wrap_key_size(:cms3des_wrap, oid, params) do
    if params == nil or DER.null?(params), do: {:ok, 24}, else: {:error, :malformed, oid}
  end

  defp wrap_key_size(:cmsrc2_wrap, oid, params) do
    case params && DER.integer(params) do
      {:ok, 58} -> {:ok, 16}
      {:ok, _version} -> {:error, :unsupported_algorithm, oid}
      _ -> {:error, :malformed, oid}
    end
  end

  defp wrap_key_size(_name, oid, _params), do: {:error, :unsupported_algorithm, oid}

  # The key of the sender: its ephemeral key, which must be on the curve
  # of the recipient, or the key of its certificate (static-static ECDH),
  # among the certificates of the message.
  defp originator_key(%{originator: {:public_key, alg, public}} = info, cert, _context) do
    {_oid, params} = info.raw.originator_key

    case {alg, cert.public_key} do
      {:ec_public_key, {:ec, curve, _point}} ->
        if ec_params?(params, curve),
          do: {:ok, public},
          else: {:error, :malformed, OID.oid(:ec_public_key)}

      {type, {type, own}} when type in [:x25519, :x448] ->
        if params == nil and byte_size(public) == byte_size(own),
          do: {:ok, public},
          else: {:error, :malformed, OID.oid(type)}

      {alg, _key} ->
        {:error, :unsupported_algorithm, OID.oid(alg)}
    end
  end

  defp originator_key(%{originator: identifier}, cert, context) do
    found =
      Enum.find_value(context.certificates, fn der ->
        with {:ok, originator} <- Certificate.parse(der),
             true <- names?(identifier, originator),
             true <- same_curve?(originator.public_key, cert.public_key) do
          originator.public_key
        else
          _ -> nil
        end
      end)

    case found do
      {:ec, _curve, point} -> {:ok, point}
      {_type, public} -> {:ok, public}
      nil -> :error
    end
  end

  defp same_curve?({:ec, curve, _}, {:ec, curve, _}), do: true
  defp same_curve?({type, _}, {type, _}) when type in [:x25519, :x448], do: true
  defp same_curve?(_a, _b), do: false

  # RFC 5753, 3.1.1: absent, NULL or the named curve.
  defp ec_params?(nil, _curve), do: true
  defp ec_params?({0x05, <<>>, _}, _curve), do: true

  defp ec_params?({0x06, _, _} = oid, curve) do
    case DER.oid(oid) do
      {:ok, oid} -> OID.name(oid) == curve
      :error -> false
    end
  end

  defp ec_params?(_params, _curve), do: false

  defp agree({:local, {:ec, curve, private, _point}}, _public, peer) do
    {:ok, :crypto.compute_key(:ecdh, peer, private, Key.crypto_curve(curve))}
  rescue
    _ -> :error
  end

  defp agree({:local, {type, private, _public}}, _public_key, peer)
       when type in [:x25519, :x448] do
    shared = :crypto.compute_key(:ecdh, peer, private, type)
    if zero?(shared), do: :error, else: {:ok, shared}
  rescue
    _ -> :error
  end

  defp agree({:external, fun}, public_key, peer) do
    curve =
      case public_key do
        {:ec, curve, _point} -> curve
        {type, _public} -> type
      end

    with {:ok, shared} <- external(fun, %{operation: :agree, curve: curve, public_key: peer}) do
      if zero?(shared), do: :error, else: {:ok, shared}
    end
  end

  defp agree(_key, _public_key, _peer), do: :error

  ## Key wrap

  defp unwrap(name, _oid, nil, kek, wrapped) when name in @aes_wraps,
    do:
      if(byte_size(kek) == Recipient.wrap_size(name),
        do: KeyWrap.unwrap(kek, wrapped),
        else: :error
      )

  defp unwrap(name, _oid, nil, kek, wrapped) when name in @aes_wraps_pad do
    if byte_size(kek) == Recipient.wrap_size(name),
      do: KeyWrap.unwrap_with_padding(kek, wrapped),
      else: :error
  end

  defp unwrap(name, oid, _params, _kek, _wrapped)
       when name in @aes_wraps or name in @aes_wraps_pad,
       do: {:error, :malformed, oid}

  defp unwrap(:cms3des_wrap, oid, params, kek, wrapped) do
    cond do
      params != nil and not DER.null?(params) -> {:error, :malformed, oid}
      :des_ede3_cbc not in :crypto.supports(:ciphers) -> {:error, :not_available, :cms3des_wrap}
      true -> LegacyWrap.des3_unwrap(kek, wrapped)
    end
  end

  # RFC 3217, 4: the RC2ParameterVersion, 58 for 128 bits, the only size
  # where the effective key bits of `:crypto` and of the message agree.
  defp unwrap(:cmsrc2_wrap, oid, params, kek, wrapped) do
    cond do
      not match?({:ok, 58}, params && DER.integer(params)) ->
        {:error, :unsupported_algorithm, oid}

      :rc2_cbc not in :crypto.supports(:ciphers) ->
        {:error, :not_available, :cmsrc2_wrap}

      true ->
        LegacyWrap.rc2_unwrap(kek, wrapped)
    end
  end

  defp unwrap(_name, oid, _params, _kek, _wrapped), do: {:error, :unsupported_algorithm, oid}

  ## Password

  defp password(info, password, size, context) do
    {oid, params} = info.raw.key_encryption_algorithm

    with :ok <- pwri_kek(OID.name(oid), oid),
         {:ok, inner} <- inner_cipher(params, oid),
         {:ok, kek} <- password_kek(info, password, inner.key_size, context) do
      inner.crypto
      |> PasswordWrap.unwrap(kek, inner.iv, Cipher.block_size(inner), info.encrypted_key)
      |> sized(size)
    end
  end

  defp pwri_kek(:pwri_kek, _oid), do: :ok
  defp pwri_kek(_name, oid), do: {:error, :unsupported_algorithm, oid}

  # The parameters of id-alg-PWRI-KEK are the cipher of the key wrap, a
  # block cipher in CBC mode (RFC 3211, 2.3).
  defp inner_cipher({0x30, _, _} = params, oid) do
    with {:ok, alg} <- Algorithm.read(params),
         {:ok, cipher} <- Cipher.read(alg) do
      if Cipher.block_size(cipher),
        do: {:ok, cipher},
        else: {:error, :unsupported_algorithm, elem(alg, 0)}
    else
      :error -> {:error, :malformed, oid}
      error -> error
    end
  end

  defp inner_cipher(_params, oid), do: {:error, :malformed, oid}

  # Without keyDerivationAlgorithm, the password is the key-encryption
  # key itself (RFC 3211, 2.2.1).
  defp password_kek(%{raw: %{key_derivation_algorithm: nil}}, password, key_size, _context) do
    if byte_size(password) == key_size, do: {:ok, password}, else: :error
  end

  defp password_kek(%{raw: %{key_derivation_algorithm: {oid, params}}}, password, size, context) do
    with :ok <- pbkdf2_oid(OID.name(oid), oid),
         {:ok, salt, iterations, length, prf} <- pbkdf2_params(params, oid),
         :ok <- iterations(iterations, context.max_iterations),
         :ok <- key_length(length, size) do
      {:ok, KDF.pbkdf2(prf, password, salt, iterations, size)}
    end
  end

  # A keyLength, when present, is the size of the key-encryption key.
  defp key_length(nil, _size), do: :ok
  defp key_length(size, size), do: :ok
  defp key_length(_length, _size), do: :error

  defp pbkdf2_oid(:pbkdf2, _oid), do: :ok
  defp pbkdf2_oid(_name, oid), do: {:error, :unsupported_algorithm, oid}

  # PBKDF2-params (RFC 8018, A.2): salt, iterationCount, keyLength
  # OPTIONAL, prf DEFAULT hmacWithSHA1.
  defp pbkdf2_params({0x30, _, _} = params, oid) do
    with [{0x04, salt, _}, count | rest] <- DER.children(params),
         {:ok, iterations} when iterations > 0 <- DER.integer(count),
         {length, rest} <- optional_key_length(rest),
         {:ok, prf} <- prf(rest) do
      {:ok, salt, iterations, length, prf}
    else
      {:error, _, _} = error -> error
      _ -> {:error, :malformed, oid}
    end
  end

  defp pbkdf2_params(_params, oid), do: {:error, :malformed, oid}

  defp optional_key_length([{0x02, _, _} = length | rest]) do
    case DER.integer(length) do
      {:ok, length} when length > 0 -> {length, rest}
      _ -> :error
    end
  end

  defp optional_key_length(rest), do: {nil, rest}

  defp prf([]), do: {:ok, :sha1}

  defp prf([alg]) do
    with {:ok, {oid, params}} <- Algorithm.read(alg) do
      case Map.fetch(@prfs, OID.name(oid)) do
        {:ok, hash} when params == nil -> {:ok, hash}
        {:ok, hash} -> null_params(hash, params)
        :error -> {:error, :unsupported_algorithm, oid}
      end
    end
  end

  defp prf(_rest), do: :error

  defp null_params(hash, params), do: if(DER.null?(params), do: {:ok, hash}, else: :error)

  defp iterations(iterations, max) when iterations <= max, do: :ok
  defp iterations(_iterations, _max), do: {:error, :limit_exceeded, :max_iterations}

  ## Common

  defp sized({:ok, key}, size) when byte_size(key) == size, do: {:ok, key}
  defp sized({:error, _, _} = error, _size), do: error
  defp sized(_result, _size), do: :error

  defp external(fun, request) do
    case fun.(request) do
      {:ok, bytes} when is_binary(bytes) -> {:ok, bytes}
      _ -> :error
    end
  end
end
