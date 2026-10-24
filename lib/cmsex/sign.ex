defmodule Cmsex.Sign do
  @moduledoc false
  # Writing SignedData (RFC 5652, 5), in DER from the first byte to the
  # last: minimal lengths, primitive strings, sorted SET OF.
  #
  # Every signer is checked before anything is signed: the certificate and
  # key are read, the algorithms chosen, and the choice is run through the
  # same policy as verification (`Cmsex.Algorithm.plan/4`), so the library
  # never writes what it would refuse to verify.

  alias Cmsex.{Algorithm, Attribute, Certificate, DER, Digest, Error, Key, OID, Options, Signer}

  @options %{
    detached: nil,
    content_type: :data,
    no_attributes: false,
    certificates: :signers,
    crls: [],
    min_rsa_bits: 2048,
    digest: nil,
    rsa_padding: :pkcs1,
    identifier: :issuer_and_serial,
    signing_time: true,
    algorithm_protection: true
  }

  @doc "Signs `content`; see `Cmsex.sign/3`."
  @spec sign(term(), term(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(content, signers, opts) do
    opts = options!(content, opts)

    with {:ok, signed} <- signer_infos(content, signers, opts) do
      {:ok,
       encode(
         signed.prepared,
         signed.signer_infos,
         content,
         signed.certificates,
         signed.crls,
         opts
       )}
    end
  end

  @doc """
  The SignerInfos of `signers` over `content`, in DER, with what the
  message gains: the digest identifiers, the certificates and the CRLs.
  `opts` is a map of the options of `options/1`; a `:content_type` of
  `nil` makes countersignatures (RFC 5652, 11.4), without the
  content-type attribute.

  `check` is `{hashes, fun}`: the digests of the content for `hashes` and
  those of the signers go to `fun` before anything is signed, which
  returns `:ok` or an error.
  """
  @spec signer_infos(
          term(),
          term(),
          map(),
          {[Digest.hash()], (map() -> :ok | {:error, Error.t()})}
        ) ::
          {:ok, map()} | {:error, Error.t()}
  def signer_infos(content, signers, opts, check \\ {[], fn _digests -> :ok end}) do
    signers = signers!(signers)
    {hashes, check} = check

    with {:ok, prepared} <- prepare(signers, content, opts, 0, []),
         {:ok, certificates} <- certificates(opts.certificates, signers),
         {:ok, crls} <- crls(opts.crls),
         digests = Digest.many(content, Enum.map(prepared, & &1.digest) ++ hashes),
         :ok <- check.(digests),
         {:ok, signer_infos} <- sign_all(prepared, content, digests, opts, []) do
      {:ok,
       %{
         prepared: prepared,
         signer_infos: signer_infos,
         digest_ids: Enum.map(prepared, & &1.digest_id),
         versions: Enum.map(prepared, & &1.version),
         certificates: certificates,
         crls: crls
       }}
    end
  end

  @doc """
  The signing options of `keys`, checked, as a map with the defaults of
  `Cmsex.sign/3`.
  """
  @spec options(keyword(), [atom()]) :: map()
  def options(opts, keys), do: take!(opts, keys)

  @doc "A certificates-only SignedData; see `Cmsex.certs_only/2`."
  @spec certs_only([binary()], keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def certs_only(certificates, opts) do
    unless is_list(certificates) and Enum.all?(certificates, &is_binary/1),
      do: raise(ArgumentError, "expected a list of DER certificates")

    opts = take!(opts, [:crls])

    with {:ok, certificates} <- parse_certificates(certificates),
         {:ok, crls} <- crls(opts.crls) do
      fields =
        [{:int, 1}, {:set, []}, {:seq, [{:oid, :data}]}] ++
          tagged_set(0xA0, certificates) ++ tagged_set(0xA1, crls) ++ [{:set, []}]

      {:ok, content_info(fields)}
    end
  end

  ## Options

  defp options!(content, opts) do
    unless Options.content?(content),
      do:
        raise(
          ArgumentError,
          "the content must be a binary, {:stream, enumerable} or {:digest, hash, binary}"
        )

    opts = take!(opts, Map.keys(@options))
    binary? = is_binary(content)
    content_type = OID.name(OID.oid(opts.content_type))

    detached =
      case {opts.detached, binary?} do
        {nil, binary?} -> not binary?
        {false, false} -> raise ArgumentError, "a stream or a digest can only be detached"
        {detached, _} -> detached
      end

    if opts.no_attributes and not (binary? and content_type == :data),
      do:
        raise(
          ArgumentError,
          "no_attributes: true needs id-data content given as a binary (RFC 5652, 5.3)"
        )

    %{opts | detached: detached, content_type: content_type}
  end

  defp take!(opts, keys) do
    unless Keyword.keyword?(opts),
      do: raise(ArgumentError, "expected a keyword list of options, got: #{inspect(opts)}")

    for {key, value} <- opts do
      unless key in keys, do: raise(ArgumentError, "unknown option #{inspect(key)}")
      check!(key, value)
    end

    @options |> Map.take(keys) |> Map.merge(Map.new(opts))
  end

  defp check!(key, value) when key in [:detached, :no_attributes, :algorithm_protection],
    do: ensure!(is_boolean(value), "#{inspect(key)} must be a boolean", value)

  defp check!(:content_type, value) do
    ensure!(is_atom(value) or is_tuple(value), ":content_type must be an OID", value)
    _ = value |> OID.oid() |> OID.encode()
    :ok
  end

  defp check!(:certificates, value) do
    ensure!(
      value in [:signers, :none] or binaries?(value),
      ":certificates must be :signers, :none or a list of DER certificates",
      value
    )
  end

  defp check!(:crls, value),
    do: ensure!(binaries?(value), ":crls must be a list of DER revocation lists", value)

  defp check!(:min_rsa_bits, value),
    do:
      ensure!(is_integer(value) and value > 0, ":min_rsa_bits must be a positive integer", value)

  defp check!(:digest, value) do
    ensure!(
      value in [:sha224, :sha256, :sha384, :sha512],
      ":digest must be :sha224, :sha256, :sha384 or :sha512",
      value
    )
  end

  defp check!(:rsa_padding, value),
    do: ensure!(value in [:pkcs1, :pss], ":rsa_padding must be :pkcs1 or :pss", value)

  defp check!(:identifier, value) do
    ensure!(
      value in [:issuer_and_serial, :subject_key_identifier],
      ":identifier must be :issuer_and_serial or :subject_key_identifier",
      value
    )
  end

  defp check!(:signing_time, value) do
    ensure!(
      is_boolean(value) or match?(%DateTime{}, value),
      ":signing_time must be a boolean or a DateTime",
      value
    )
  end

  defp ensure!(true, _message, _value), do: :ok

  defp ensure!(false, message, value),
    do: raise(ArgumentError, "#{message}, got: #{inspect(value, limit: 5)}")

  defp binaries?(list), do: is_list(list) and Enum.all?(list, &is_binary/1)

  # One signer, as a struct, a map or a keyword list, or a list of them.
  defp signers!(%Signer{} = signer), do: [Signer.new!(signer)]
  defp signers!(signer) when is_map(signer), do: [Signer.new!(signer)]
  defp signers!([]), do: raise(ArgumentError, "expected at least one signer")
  defp signers!([{key, _} | _] = signer) when is_atom(key), do: [Signer.new!(signer)]
  defp signers!(signers) when is_list(signers), do: Enum.map(signers, &Signer.new!/1)

  defp signers!(other),
    do: raise(ArgumentError, "expected a signer or a list of signers, got #{Options.kind(other)}")

  ## Each signer, before anything is signed

  defp prepare([], _content, _opts, _index, acc), do: {:ok, Enum.reverse(acc)}

  defp prepare([signer | rest], content, opts, index, acc) do
    case prepare_one(signer, content, opts) do
      {:ok, prepared} -> prepare(rest, content, opts, index + 1, [prepared | acc])
      {:error, reason, detail} -> {:error, %{Error.new(reason, detail) | signer: index}}
    end
  end

  defp prepare_one(%Signer{} = signer, content, opts) do
    attributes? = not opts.no_attributes

    with {:ok, cert} <- certificate(signer.certificate),
         {:ok, _chain} <- chain(signer.chain),
         {:ok, key} <- key(signer.key, cert),
         {:ok, scheme} <- scheme(cert.public_key, signer.rsa_padding || opts.rsa_padding),
         {:ok, digest} <- digest(signer.digest || opts.digest, scheme, cert, content, opts),
         pss = pss(scheme, digest, cert.public_key),
         digest_id = Algorithm.digest_identifier(digest),
         signature_id = signature_identifier(scheme, digest, pss),
         {:ok, plan} <- plan(digest_id, signature_id, cert, attributes?, opts),
         {:ok, sid, version} <- sid(signer.identifier || opts.identifier, cert) do
      prepared = %{
        signer: signer,
        cert: cert,
        key: key,
        scheme: scheme,
        digest: digest,
        hash: plan.hash,
        pss: pss,
        digest_id: digest_id,
        signature_id: signature_id,
        sid: sid,
        version: version
      }

      {:ok, Map.put(prepared, :attributes, attributes!(prepared, opts))}
    end
  end

  defp certificate(der) do
    case Certificate.parse(der) do
      {:ok, cert} -> {:ok, cert}
      :error -> {:error, :invalid_certificate, nil}
    end
  end

  defp chain(ders) do
    case parse_certificates(ders) do
      {:ok, certs} -> {:ok, certs}
      {:error, _} -> {:error, :invalid_certificate, :chain}
    end
  end

  defp key(fun, _cert) when is_function(fun, 1), do: {:ok, {:external, fun}}

  defp key(key, cert) do
    case Key.parse(key) do
      {:ok, key} ->
        if Key.matches?(key, cert.public_key),
          do: {:ok, {:local, key}},
          else: {:error, :key_certificate_mismatch, nil}

      :error ->
        {:error, :invalid_key, nil}
    end
  end

  defp scheme({:unknown, oid}, _padding), do: {:error, :unsupported_algorithm, oid}

  defp scheme(public_key, padding) do
    case Key.scheme(public_key, padding) do
      nil -> {:error, :key_mismatch, nil}
      scheme -> {:ok, scheme}
    end
  end

  # Ed25519 takes SHA-512 and Ed448 SHAKE256 (RFC 8419); a PSS key with
  # parameters, its own hash; a ready digest, its hash.
  defp digest(given, scheme, cert, content, opts) do
    ready = ready_hash(content)

    with {:ok, digest} <- choose_digest(scheme, given, cert.public_key, ready, opts) do
      if ready in [nil, digest], do: {:ok, digest}, else: {:error, :content_required, digest}
    end
  end

  defp ready_hash({:digest, hash, _digest}), do: hash
  defp ready_hash(_content), do: nil

  defp choose_digest(:ed25519, given, _key, _ready, _opts) when given in [nil, :sha512],
    do: {:ok, :sha512}

  defp choose_digest(:ed25519, given, _key, _ready, _opts),
    do: {:error, :algorithm_mismatch, {given, :ed25519}}

  defp choose_digest(:ed448, nil, _key, _ready, %{no_attributes: true}), do: {:ok, :shake256}
  defp choose_digest(:ed448, nil, _key, _ready, _opts), do: {:ok, :shake256_len}

  defp choose_digest(:ed448, given, _key, _ready, _opts),
    do: {:error, :algorithm_mismatch, {given, :ed448}}

  defp choose_digest(_scheme, given, _key, _ready, _opts) when given != nil, do: {:ok, given}

  defp choose_digest(:rsa_pss, nil, {:rsa_pss, _, _, %{hash: hash}}, _ready, _opts),
    do: {:ok, hash}

  defp choose_digest(_scheme, nil, _key, ready, _opts)
       when ready in [:sha224, :sha256, :sha384, :sha512],
       do: {:ok, ready}

  defp choose_digest(_scheme, nil, _key, _ready, _opts), do: {:ok, :sha256}

  # A PSS key with parameters is signed with them (RFC 4056, 3); otherwise
  # MGF1 with the same hash and a salt of its size.
  defp pss(:rsa_pss, hash, {:rsa_pss, _, _, %{hash: hash} = params}), do: params

  defp pss(:rsa_pss, hash, _public_key),
    do: %{hash: hash, mgf_hash: hash, salt_length: Digest.size(hash), trailer_field: 1}

  defp pss(_scheme, _hash, _public_key), do: nil

  defp signature_identifier(:rsa_pss, _digest, pss), do: Algorithm.pss_identifier(pss)

  defp signature_identifier(scheme, digest, _pss),
    do: Algorithm.signature_identifier(scheme, digest)

  # The identifiers are read back and put through the policy of
  # verification.
  defp plan(digest_id, signature_id, cert, attributes?, opts) do
    {:ok, digest} = digest_id |> read_back() |> Algorithm.digest()
    {:ok, signature} = signature_id |> read_back() |> Algorithm.signature()

    Algorithm.plan(digest, signature, cert.public_key,
      allow_sha1: false,
      min_rsa_bits: opts.min_rsa_bits,
      ed25519_digest: :strict,
      signed_attributes?: attributes?
    )
  end

  defp read_back(term) do
    {:ok, element} = term |> DER.encode() |> DER.decode()
    {:ok, alg} = Algorithm.read(element)
    alg
  end

  defp sid(:issuer_and_serial, cert),
    do: {:ok, {:seq, [{:raw, cert.issuer}, {:int, cert.serial}]}, 1}

  defp sid(:subject_key_identifier, %Certificate{subject_key_identifier: nil}),
    do: {:error, :invalid_certificate, :subject_key_identifier}

  defp sid(:subject_key_identifier, cert),
    do: {:ok, {:primitive, 0x80, cert.subject_key_identifier}, 3}

  # The signed attributes the library writes, then those of the signer,
  # which may not repeat them. The message digest comes when signing.
  defp attributes!(prepared, opts) do
    signer = prepared.signer

    if opts.no_attributes do
      if signer.signed_attributes != [],
        do: raise(ArgumentError, "no_attributes: true leaves no room for :signed_attributes")

      []
    else
      written =
        [
          opts.content_type && Attribute.content_type(opts.content_type),
          signing_time(signer.signing_time, opts.signing_time),
          protection(signer.algorithm_protection, opts.algorithm_protection, prepared)
        ]
        |> Enum.filter(& &1)

      types = [:message_digest, :content_type | Enum.map(written, & &1.type)]

      for %Attribute{type: type} <- signer.signed_attributes, type in types do
        raise ArgumentError, written_by(type, opts.content_type)
      end

      written ++ signer.signed_attributes
    end
  end

  defp written_by(:content_type, nil),
    do: "a countersignature has no content-type attribute (RFC 5652, 11.4)"

  defp written_by(type, _content_type),
    do: "the signed attribute #{inspect(type)} is written by the library"

  defp signing_time(nil, global), do: signing_time(global, nil)
  defp signing_time(false, _global), do: nil
  defp signing_time(true, _global), do: Attribute.signing_time(DateTime.utc_now())
  defp signing_time(%DateTime{} = time, _global), do: Attribute.signing_time(time)

  defp protection(nil, global, prepared), do: protection(global, nil, prepared)
  defp protection(false, _global, _prepared), do: nil

  # RFC 6211: the digest algorithm and, as [1] IMPLICIT, the signature
  # algorithm of the signer.
  defp protection(true, _global, prepared) do
    signature = DER.retag(DER.encode(prepared.signature_id), 0xA1)
    value = DER.encode({:seq, [prepared.digest_id, {:raw, signature}]})
    %Attribute{type: :cms_algorithm_protection, values: [value]}
  end

  ## Signing

  defp sign_all([], _content, _digests, _opts, acc), do: {:ok, Enum.reverse(acc)}

  defp sign_all([prepared | rest], content, digests, opts, acc) do
    case sign_one(prepared, content, digests, opts) do
      {:ok, signer_info} ->
        sign_all(rest, content, digests, opts, [signer_info | acc])

      {:error, reason, detail} ->
        {:error, %{Error.new(reason, detail) | signer: length(acc)}}
    end
  end

  defp sign_one(prepared, content, digests, opts) do
    {signed, tbs} =
      if opts.no_attributes do
        {[], content}
      else
        message_digest = %Attribute{
          type: :message_digest,
          values: [DER.encode({:octets, Map.fetch!(digests, prepared.digest)})]
        }

        set = attribute_set([message_digest | prepared.attributes])
        {[{:raw, DER.retag(set, 0xA0)}], set}
      end

    with {:ok, signature} <- signature(prepared, tbs) do
      fields =
        [{:int, prepared.version}, prepared.sid, prepared.digest_id] ++
          signed ++
          [prepared.signature_id, {:octets, signature}] ++
          unsigned(prepared.signer.unsigned_attributes)

      {:ok, DER.encode({:seq, fields})}
    end
  end

  defp attribute_set(attributes),
    do: DER.encode({:set, Enum.map(attributes, &{:raw, DER.encode(Attribute.to_term(&1))})})

  defp unsigned([]), do: []
  defp unsigned(attributes), do: [{:raw, DER.retag(attribute_set(attributes), 0xA1)}]

  # RSA and ECDSA sign the digest of the TBS; EdDSA, the TBS itself.
  defp signature(%{key: {:local, key}} = prepared, tbs),
    do: {:ok, Key.sign(key, prepared.scheme, prepared.hash, data(prepared, tbs), prepared.pss)}

  defp signature(%{key: {:external, fun}} = prepared, tbs) do
    data = data(prepared, tbs)

    request = %{
      tbs: tbs,
      hash: prepared.hash,
      digest: prepared.hash && data,
      scheme: prepared.scheme,
      pss: prepared.pss
    }

    case fun.(request) do
      {:ok, signature} when is_binary(signature) -> check_signature(prepared, data, signature)
      {:error, reason} -> {:error, :signer_failed, reason}
      _other -> {:error, :signer_failed, :unexpected_return}
    end
  end

  defp data(%{hash: nil}, tbs), do: tbs
  defp data(%{hash: hash}, tbs), do: Digest.hash(hash, tbs)

  defp check_signature(%{signer: %Signer{verify_signature: false}}, _data, signature),
    do: {:ok, signature}

  defp check_signature(prepared, data, signature) do
    if Key.verify(
         prepared.cert.public_key,
         prepared.scheme,
         prepared.hash,
         data,
         signature,
         prepared.pss
       ),
       do: {:ok, signature},
       else: {:error, :signer_failed, :invalid_signature}
  end

  ## The message

  defp certificates(:none, _signers), do: {:ok, []}

  defp certificates(:signers, signers),
    do: {:ok, signers |> Enum.flat_map(&[&1.certificate | &1.chain]) |> Enum.uniq()}

  defp certificates(certificates, _signers) do
    with {:ok, _} <- parse_certificates(certificates), do: {:ok, Enum.uniq(certificates)}
  end

  defp parse_certificates(ders) do
    if Enum.all?(ders, &match?({:ok, _}, Certificate.parse(&1))),
      do: {:ok, ders},
      else: {:error, Error.new(:invalid_certificate)}
  end

  defp crls(crls) do
    if Enum.all?(crls, &match?({:ok, {0x30, _, _}}, DER.decode(&1))),
      do: {:ok, Enum.uniq(crls)},
      else: {:error, Error.new(:malformed, :crls)}
  end

  # RFC 5652, 5.1: version 3 with a SignerInfo of version 3 or content
  # other than id-data, 1 otherwise; only X.509 certificates and CRLs are
  # written, so never 4 or 5.
  defp encode(prepared, signer_infos, content, certificates, crls, opts) do
    version =
      if opts.content_type != :data or Enum.any?(prepared, &(&1.version == 3)), do: 3, else: 1

    content = if opts.detached, do: [], else: [{:explicit, 0, {:octets, content}}]

    content_info(
      [
        {:int, version},
        {:set, prepared |> Enum.map(& &1.digest_id) |> Enum.uniq()},
        {:seq, [{:oid, opts.content_type} | content]}
      ] ++
        tagged_set(0xA0, certificates) ++
        tagged_set(0xA1, crls) ++
        [{:set, Enum.map(signer_infos, &{:raw, &1})}]
    )
  end

  defp tagged_set(_tag, []), do: []

  defp tagged_set(tag, ders),
    do: [{:raw, DER.retag(DER.encode({:set, Enum.map(ders, &{:raw, &1})}), tag)}]

  defp content_info(fields),
    do: DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, {:seq, fields}}]})
end
