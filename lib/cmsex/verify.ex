defmodule Cmsex.Verify do
  @moduledoc false
  # Verification of the signers of a SignedData (RFC 5652, 5.6), with the
  # algorithm checks of RFC 6211, RFC 8933, RFC 4056, RFC 5754 and RFC 8419,
  # the signing-certificate attributes of RFC 2634 and RFC 5035, and the
  # countersignatures of RFC 5652, 11.4.
  #
  # The checks of one signer run in stages, and when several certificates
  # match its identifier each is tried in turn: the first one that passes
  # every stage is the signer. When none does, the error reported is that
  # of the candidate that went furthest.

  alias Cmsex.{
    Algorithm,
    Attribute,
    Certificate,
    DER,
    Digest,
    Error,
    Key,
    Message,
    SignedData,
    SignerInfo,
    Trust,
    Verified
  }

  @doc "Verifies every signer, or at least one, as `opts.signers` asks."
  @spec verify(binary(), map()) :: {:ok, Verified.t()} | {:error, Error.t()}
  def verify(der, opts) do
    with {:ok, signed_data, ctx} <- prepare(der, opts) do
      signers = Enum.with_index(signed_data.signer_infos)

      result =
        case opts.signers do
          :all -> all(signers, ctx, [])
          :any -> any(signers, ctx)
        end

      with {:ok, verified} <- result do
        {:ok,
         %Verified{
           content: signed_data.content,
           content_type: signed_data.content_type,
           signed_data: signed_data,
           signers: verified
         }}
      end
    end
  end

  @doc "The result of each signer."
  @spec verify_each(binary(), map()) ::
          {:ok, SignedData.t(),
           [{SignerInfo.t(), {:ok, Verified.signer()} | {:error, Error.t()}}]}
          | {:error, Error.t()}
  def verify_each(der, opts) do
    with {:ok, signed_data, ctx} <- prepare(der, opts) do
      results =
        for {signer_info, index} <- Enum.with_index(signed_data.signer_infos),
            do: {signer_info, check(signer_info, [index], ctx, main_target(ctx))}

      {:ok, signed_data, results}
    end
  end

  @doc """
  Verifies the countersignature at `path` against the signature value of
  the SignerInfo above it, which is not verified itself.
  """
  @spec verify_countersignature(binary(), [non_neg_integer(), ...], map()) ::
          {:ok, Verified.signer()} | {:error, Error.t()}
  def verify_countersignature(der, [index | rest] = path, opts) do
    with {:ok, signed_data} <- SignedData.parse(der, opts),
         {:ok, certificates} <- certificates(signed_data, opts.certificates),
         {:ok, roots} <- roots(opts.trust),
         {:ok, parent, counter} <- locate(signed_data.signer_infos, index, rest, [index], opts) do
      ctx = %{certificates: certificates, roots: roots, opts: opts}

      target = %{
        type: nil,
        content: parent.signature,
        digests: Digest.many(parent.signature, hashes([counter])),
        countersignature?: true
      }

      check(counter, path, ctx, target)
    end
  end

  defp locate(signer_infos, index, rest, at, opts) do
    case {Enum.fetch(signer_infos, index), rest} do
      {:error, _} ->
        raise ArgumentError, "the message has no signer at #{inspect(at)}"

      {{:ok, signer_info}, [next | rest]} ->
        case SignerInfo.read_countersignatures(signer_info, opts) do
          {:ok, counters} when rest == [] -> found_counter(signer_info, counters, next, at)
          {:ok, counters} -> locate(counters, next, rest, at ++ [next], opts)
          {:error, error} -> {:error, %{error | signer: at ++ List.wrap(error.signer)}}
        end

      {{:ok, _signer_info}, []} ->
        raise ArgumentError, "expected the position of a countersignature, got: #{inspect(at)}"
    end
  end

  defp found_counter(parent, counters, index, at) do
    case Enum.fetch(counters, index) do
      {:ok, counter} -> {:ok, parent, counter}
      :error -> raise ArgumentError, "the message has no signer at #{inspect(at ++ [index])}"
    end
  end

  defp all([], _ctx, acc), do: {:ok, Enum.reverse(acc)}

  defp all([{signer_info, index} | rest], ctx, acc) do
    case check(signer_info, [index], ctx, main_target(ctx)) do
      {:ok, signer} -> all(rest, ctx, [signer | acc])
      {:error, _} = error -> error
    end
  end

  defp any(signers, ctx) do
    results =
      for {signer_info, index} <- signers, do: check(signer_info, [index], ctx, main_target(ctx))

    case for({:ok, signer} <- results, do: signer) do
      [] -> hd(results)
      verified -> {:ok, verified}
    end
  end

  ## The message

  defp prepare(der, opts) do
    with {:ok, signed_data} <- SignedData.parse(der, opts),
         :ok <- signers?(signed_data),
         {:ok, content} <- Message.content(signed_data.content, opts.content),
         {:ok, certificates} <- certificates(signed_data, opts.certificates),
         {:ok, roots} <- roots(opts.trust) do
      {:ok, signed_data,
       %{
         content: content,
         content_type: signed_data.content_type,
         digests: Digest.many(content, hashes(signed_data.signer_infos)),
         certificates: certificates,
         roots: roots,
         opts: opts
       }}
    end
  end

  defp signers?(%SignedData{signer_infos: []}), do: {:error, Error.new(:no_signers)}
  defp signers?(_signed_data), do: :ok

  defp hashes(signer_infos) do
    for signer_info <- signer_infos,
        {:ok, hash} <- [digest_algorithm(signer_info)],
        uniq: true,
        do: hash
  end

  # The certificates given by the caller come first; those of the message
  # that cannot be read are left out.
  defp certificates(signed_data, given) do
    with {:ok, given} <- parse_all(given) do
      from_message =
        for der <- signed_data.certificates, {:ok, cert} <- [Certificate.parse(der)], do: cert

      {:ok, Enum.uniq_by(given ++ from_message, & &1.der)}
    end
  end

  defp roots(nil), do: {:ok, nil}
  defp roots(roots), do: parse_all(roots)

  defp parse_all(ders) do
    Enum.reduce_while(ders, {:ok, []}, fn der, {:ok, acc} ->
      case Certificate.parse(der) do
        {:ok, cert} -> {:cont, {:ok, [cert | acc]}}
        :error -> {:halt, {:error, Error.new(:invalid_certificate)}}
      end
    end)
    |> case do
      {:ok, certs} -> {:ok, Enum.reverse(certs)}
      error -> error
    end
  end

  defp main_target(ctx),
    do: %{
      type: ctx.content_type,
      content: ctx.content,
      digests: ctx.digests,
      countersignature?: false
    }

  ## One signer

  # `path` is the position of the signer: `[index]` for a signer of the
  # message, longer for a countersignature.
  defp check(signer_info, path, ctx, target) do
    result =
      with {:ok, digest} <- error(digest_algorithm(signer_info)),
           {:ok, signature} <- error(signature_algorithm(signer_info)),
           {:ok, candidates} <- candidates(signer_info.sid, ctx.certificates) do
        job = %{si: signer_info, digest: digest, signature: signature, path: path, target: target}
        try_candidates(candidates, job, ctx, nil)
      end

    case result do
      {:ok, signer} -> {:ok, signer}
      {:error, error} -> {:error, %{error | signer: error.signer || position(path)}}
    end
  end

  defp position([index]), do: index
  defp position(path), do: path

  defp digest_algorithm(signer_info) do
    {:ok, alg} = Algorithm.read(signer_info.raw.digest_algorithm)
    Algorithm.digest(alg)
  end

  defp signature_algorithm(signer_info) do
    {:ok, alg} = Algorithm.read(signer_info.raw.signature_algorithm)
    Algorithm.signature(alg)
  end

  defp error({:error, reason, detail}), do: {:error, Error.new(reason, detail)}
  defp error(ok), do: ok

  defp candidates({:issuer_and_serial, issuer, serial}, certificates) do
    certificates
    |> Enum.filter(&(&1.serial == serial and Trust.same_name?(issuer, &1.issuer)))
    |> found()
  end

  defp candidates({:subject_key_identifier, ski}, certificates) do
    certificates
    |> Enum.filter(&(&1.subject_key_identifier == ski))
    |> found()
  end

  defp found([]), do: {:error, Error.new(:signer_not_found)}
  defp found(candidates), do: {:ok, candidates}

  defp try_candidates([], _job, _ctx, {_stage, error}), do: {:error, error}

  defp try_candidates([cert | rest], job, ctx, best) do
    case candidate(cert, job, ctx) do
      {:ok, signer} -> {:ok, signer}
      {:error, stage, error} -> try_candidates(rest, job, ctx, better(best, {stage, error}))
    end
  end

  defp better({best, _} = old, {stage, _}) when best >= stage, do: old
  defp better(_old, new), do: new

  defp candidate(cert, %{si: si, target: target} = job, ctx) do
    plan_opts = [
      allow_sha1: ctx.opts.allow_sha1,
      min_rsa_bits: ctx.opts.min_rsa_bits,
      ed25519_digest: ctx.opts.ed25519_digest,
      signed_attributes?: si.signed_attributes != nil
    ]

    with {:ok, plan} <-
           stage(1, Algorithm.plan(job.digest, job.signature, cert.public_key, plan_opts)),
         {:ok, time} <- stage(2, attributes(si, plan, target)),
         :ok <- stage(2, algorithm_protection(si)),
         :ok <- stage(3, signing_certificate(si, cert)),
         :ok <- stage(4, signature(si, plan, cert, target)),
         {:ok, chain} <- stage(5, trust(cert, ctx)),
         {:ok, countersignatures} <- stage(6, countersignatures(si, job.path, ctx)) do
      {:ok,
       %{
         index: List.last(job.path),
         certificate: cert.der,
         signer_info: si,
         signing_time: time,
         path: chain,
         deviations: si.deviations ++ plan.deviations,
         countersignatures: countersignatures
       }}
    end
  end

  defp stage(_n, :ok), do: :ok
  defp stage(_n, {:ok, _} = ok), do: ok
  defp stage(n, {:error, reason, detail}), do: {:error, n, Error.new(reason, detail)}
  defp stage(n, {:error, %Error{} = error}), do: {:error, n, error}

  ## Attributes

  # Without signed attributes the content must be id-data (RFC 5652, 5.3),
  # except in a countersignature, which has no content type.
  defp attributes(%SignerInfo{signed_attributes: nil}, _plan, target) do
    if target.countersignature? or target.type == :data,
      do: {:ok, nil},
      else: {:error, :missing_attribute, :content_type}
  end

  defp attributes(si, plan, target) do
    with :ok <- content_type(si, target),
         :ok <- message_digest(si, plan.digest, target) do
      signing_time(si)
    end
  end

  defp content_type(si, %{countersignature?: true}) do
    if SignerInfo.attribute(si, :content_type),
      do: {:error, :invalid_attribute, :content_type},
      else: :ok
  end

  defp content_type(si, %{type: type}) do
    case SignerInfo.read_attribute(si, :content_type) do
      {:ok, ^type} -> :ok
      {:ok, _other} -> {:error, :content_type_mismatch, nil}
      {:error, :missing} -> {:error, :missing_attribute, :content_type}
      {:error, :invalid} -> {:error, :invalid_attribute, :content_type}
    end
  end

  defp message_digest(si, hash, target) do
    with {:ok, value} <- read(si, :message_digest),
         {:ok, digest} <- digest_of(target, hash) do
      if Digest.equal?(value, digest), do: :ok, else: {:error, :digest_mismatch, nil}
    end
  end

  defp read(si, type) do
    case SignerInfo.read_attribute(si, type) do
      {:ok, value} -> {:ok, value}
      {:error, :missing} -> {:error, :missing_attribute, type}
      {:error, :invalid} -> {:error, :invalid_attribute, type}
    end
  end

  defp digest_of(target, hash) do
    case Map.fetch(target.digests, hash) do
      {:ok, digest} -> {:ok, digest}
      :error -> {:error, :content_required, hash}
    end
  end

  defp signing_time(si) do
    case SignerInfo.read_attribute(si, :signing_time) do
      {:ok, {time, _encoding}} -> {:ok, time}
      {:error, :missing} -> {:ok, nil}
      {:error, :invalid} -> {:error, :invalid_attribute, :signing_time}
    end
  end

  # RFC 6211: one value, the same algorithms as the SignerInfo, modulo
  # encoding, and no MAC algorithm.
  defp algorithm_protection(si) do
    case attributes_of(si, :cms_algorithm_protection) do
      [] -> :ok
      [%Attribute{values: [value]}] -> protection(value, si)
      _ -> {:error, :invalid_attribute, :cms_algorithm_protection}
    end
  end

  defp attributes_of(si, type),
    do: for(%Attribute{type: ^type} = attribute <- si.signed_attributes || [], do: attribute)

  defp protection(value, si) do
    with {:ok, {0x30, _, _} = seq} <- DER.decode(value),
         [digest, {0xA1, content, raw}] <- DER.children(seq),
         {:ok, digest} <- Algorithm.read(digest),
         {:ok, signature} <- Algorithm.read({0x30, content, raw}) do
      {:ok, own_digest} = Algorithm.read(si.raw.digest_algorithm)
      {:ok, own_signature} = Algorithm.read(si.raw.signature_algorithm)

      if Algorithm.canonical(digest) == Algorithm.canonical(own_digest) and
           Algorithm.canonical(signature) == Algorithm.canonical(own_signature),
         do: :ok,
         else: {:error, :algorithm_mismatch, :cms_algorithm_protection}
    else
      _ -> {:error, :invalid_attribute, :cms_algorithm_protection}
    end
  end

  # ESS signing-certificate (RFC 2634, 5.4) and signing-certificate-v2
  # (RFC 5035): the first certificate named must be that of the signer.
  defp signing_certificate(si, cert) do
    with :ok <- ess(si, :signing_certificate, cert),
         do: ess(si, :signing_certificate_v2, cert)
  end

  defp ess(si, type, cert) do
    case attributes_of(si, type) do
      [] -> :ok
      [%Attribute{values: [value]}] -> ess_value(type, value, cert)
      _ -> {:error, :invalid_attribute, type}
    end
  end

  defp ess_value(type, value, cert) do
    with {:ok, {0x30, _, _} = seq} <- DER.decode(value),
         [{0x30, _, _} = ids | _policies] <- DER.children(seq),
         [first | _] <- DER.children(ids),
         {:ok, hash, cert_hash, issuer_serial} <- ess_cert_id(type, DER.children(first)) do
      same? = Digest.equal?(Digest.hash(hash, cert.der), cert_hash)

      if same? and issuer_serial?(issuer_serial, cert),
        do: :ok,
        else: {:error, :signing_certificate_mismatch, nil}
    else
      {:error, _reason, _detail} = error -> error
      _ -> {:error, :invalid_attribute, type}
    end
  end

  # ESSCertID: the SHA-1 of the certificate. ESSCertIDv2: SHA-256 unless
  # another hash is named.
  defp ess_cert_id(:signing_certificate, [{0x04, cert_hash, _} | rest]),
    do: issuer_serial(:sha1, cert_hash, rest)

  defp ess_cert_id(:signing_certificate_v2, [{0x30, _, _} = alg, {0x04, cert_hash, _} | rest]) do
    with {:ok, alg} <- Algorithm.read(alg),
         {:ok, hash} <- Algorithm.digest(alg),
         do: issuer_serial(hash, cert_hash, rest)
  end

  defp ess_cert_id(:signing_certificate_v2, [{0x04, cert_hash, _} | rest]),
    do: issuer_serial(:sha256, cert_hash, rest)

  defp ess_cert_id(_type, _fields), do: :error

  defp issuer_serial(hash, cert_hash, []), do: {:ok, hash, cert_hash, nil}

  defp issuer_serial(hash, cert_hash, [{0x30, _, _} = issuer_serial]) do
    with [{0x30, _, _} = names, serial] <- DER.children(issuer_serial),
         {:ok, serial} <- DER.integer(serial) do
      {:ok, hash, cert_hash, {DER.children(names), serial}}
    else
      _ -> :error
    end
  end

  defp issuer_serial(_hash, _cert_hash, _rest), do: :error

  # The issuer must be among the GeneralNames, as a directoryName [4].
  defp issuer_serial?(nil, _cert), do: true

  defp issuer_serial?({names, serial}, cert) do
    serial == cert.serial and
      Enum.any?(names, fn
        {0xA4, _, _} = name -> directory_name?(DER.children(name), cert.issuer)
        _ -> false
      end)
  end

  defp directory_name?([{0x30, _, name}], issuer), do: Trust.same_name?(name, issuer)
  defp directory_name?(_children, _issuer), do: false

  ## Signature

  defp signature(si, plan, cert, target) do
    with {:ok, data} <- signed_data(si, plan, target) do
      if Key.verify(cert.public_key, plan.scheme, plan.hash, data, si.signature, plan.pss),
        do: :ok,
        else: {:error, :invalid_signature, nil}
    end
  end

  # What the key signed: the digest for RSA and ECDSA, the message itself
  # for EdDSA (RFC 8419).
  defp signed_data(si, plan, target) do
    case {SignerInfo.signed_attributes_tbs(si), plan.scheme} do
      {nil, scheme} when scheme in [:ed25519, :ed448] -> whole_content(target.content)
      {nil, _scheme} -> digest_of(target, plan.digest)
      {tbs, scheme} when scheme in [:ed25519, :ed448] -> {:ok, tbs}
      {tbs, _scheme} -> {:ok, Digest.hash(plan.hash, tbs)}
    end
  end

  defp whole_content(content) when is_binary(content), do: {:ok, content}

  defp whole_content({:stream, enumerable}),
    do: {:ok, enumerable |> Enum.to_list() |> IO.iodata_to_binary()}

  defp whole_content({:digest, _hash, _value}), do: {:error, :content_required, nil}

  ## Trust and countersignatures

  defp trust(_cert, %{roots: nil}), do: {:ok, nil}

  defp trust(cert, ctx) do
    case Trust.validate(cert, ctx.certificates, ctx.roots, ctx.opts.path_validation) do
      {:ok, path} -> {:ok, path}
      {:error, reason} -> {:error, :untrusted, reason}
    end
  end

  defp countersignatures(_si, _path, %{opts: %{countersignatures: false}}), do: {:ok, []}

  defp countersignatures(si, path, ctx) do
    case SignerInfo.read_countersignatures(si, ctx.opts) do
      {:ok, counters} ->
        target = %{
          type: nil,
          content: si.signature,
          digests: Digest.many(si.signature, hashes(counters)),
          countersignature?: true
        }

        check_counters(counters, 0, path, ctx, target, [])

      # A limit on the countersignatures belongs to the signer itself.
      {:error, %Error{signer: nil} = error} ->
        {:error, %{error | signer: position(path)}}

      {:error, error} ->
        {:error, %{error | signer: path ++ error.signer}}
    end
  end

  defp check_counters([], _index, _path, _ctx, _target, acc), do: {:ok, Enum.reverse(acc)}

  defp check_counters([counter | rest], index, path, ctx, target, acc) do
    case check(counter, path ++ [index], ctx, target) do
      {:ok, signer} -> check_counters(rest, index + 1, path, ctx, target, [signer | acc])
      {:error, _} = error -> error
    end
  end
end
