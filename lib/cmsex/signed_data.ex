defmodule Cmsex.SignedData do
  @moduledoc """
  A SignedData message, as `Cmsex.decode/2` reads it (RFC 5652, 5).
  Reading checks the structure only; `Cmsex.verify/2` checks the
  signatures.

  Fields:

    * `:version` - the version written in the message.
    * `:content_type` - the type of the signed content (eContentType), as
      a name of `Cmsex.OID`, such as `:data` or `:tst_info`, or an OID.
    * `:content` - the signed content, or `nil` for a detached signature.
      It is the value of the eContent OCTET STRING, its segments joined
      when the message was written in BER. For a PKCS #7 message whose
      content is not an OCTET STRING (RFC 5652, 5.2.1), it is the content
      octets of that value, which is what the signature covers.
    * `:pkcs7_content` - for such a PKCS #7 message, the whole encoding of
      the content; `nil` otherwise.
    * `:digest_algorithms` - the digestAlgorithms field, as names or OIDs.
      Verification does not depend on it.
    * `:certificates` - the X.509 certificates of the message, in DER, in
      the order of the message. They are not trusted for being there.
    * `:other_certificates` - the other choices of CertificateChoices
      (attribute certificates, other formats), each as received.
    * `:crls` - the certificate revocation lists, in DER.
    * `:other_crls` - other revocation information (RFC 5652, 10.2.1),
      each as received.
    * `:signer_infos` - the signers, a list of `Cmsex.SignerInfo`. Empty in
      a certificate bundle.
    * `:deviations` - what the library tolerated when reading, against
      RFC 5652: `:signed_data_version` when the version is not the one
      the fields call for (section 5.1). The signers have their own.
  """

  alias Cmsex.{Algorithm, DER, Error, OID, SignerInfo}

  @type t :: %__MODULE__{
          version: integer(),
          content_type: atom() | tuple(),
          content: binary() | nil,
          pkcs7_content: binary() | nil,
          digest_algorithms: [atom() | tuple()],
          certificates: [binary()],
          other_certificates: [binary()],
          crls: [binary()],
          other_crls: [binary()],
          signer_infos: [SignerInfo.t()],
          deviations: [atom()],
          raw: map() | nil
        }

  @derive {Inspect, except: [:raw]}
  defstruct [
    :version,
    :content_type,
    :content,
    :pkcs7_content,
    digest_algorithms: [],
    certificates: [],
    other_certificates: [],
    crls: [],
    other_crls: [],
    signer_infos: [],
    deviations: [],
    raw: nil
  ]

  @doc false
  # Reads a ContentInfo that holds a SignedData. `opts` is the map of
  # Cmsex.Options with the limits.
  @spec parse(binary(), map()) :: {:ok, t()} | {:error, Error.t()}
  def parse(der, opts) do
    with {:ok, root} <- decode(der, opts),
         {:ok, type, content} <- content_info(root) do
      case OID.name(type) do
        :signed_data -> signed_data(content, opts)
        _ -> {:error, Error.new(:unsupported_content_type, type)}
      end
    end
  end

  defp decode(der, opts) do
    case DER.decode(der, max_depth: opts.max_depth, max_elements: opts.max_elements) do
      {:ok, root} -> {:ok, root}
      {:error, {:limit_exceeded, limit}} -> {:error, Error.new(:limit_exceeded, limit)}
      {:error, :malformed} -> {:error, Error.new(:malformed)}
    end
  end

  @doc false
  # ContentInfo (RFC 5652, 3): the type and the element inside [0].
  @spec content_info(DER.element()) :: {:ok, tuple(), DER.element()} | {:error, Error.t()}
  def content_info({0x30, _, _} = root) do
    with [oid, {0xA0, _, _} = explicit] <- DER.children(root),
         {:ok, oid} <- DER.oid(oid),
         [content] <- DER.children(explicit) do
      {:ok, oid, content}
    else
      _ -> malformed(:content_info)
    end
  end

  def content_info(_root), do: malformed(:content_info)

  defp signed_data({0x30, _, _} = element, opts) do
    with [version, {0x31, _, _} = digests, {0x30, _, _} = encap | rest] <- DER.children(element),
         {:ok, version} <- DER.integer(version),
         {:ok, certificates, crls, {0x31, _, _} = signers} <- optional_fields(rest),
         {:ok, digest_algorithms} <- digest_algorithms(digests),
         {:ok, encap} <- encap_content_info(encap) do
      with {:ok, certs} <- certificates(certificates, opts),
           {:ok, revocation} <- crls(crls, opts),
           {:ok, signer_infos} <- signer_infos(signers, opts) do
        signed_data =
          struct!(
            %__MODULE__{
              version: version,
              digest_algorithms: digest_algorithms,
              signer_infos: signer_infos,
              raw: %{
                signed_data: element,
                encap_content_info: encap.raw,
                certificates: certificates,
                crls: crls
              }
            },
            Map.merge(Map.delete(encap, :raw), Map.merge(certs, revocation))
          )

        {:ok, %{signed_data | deviations: deviations(signed_data)}}
      end
    else
      _ -> malformed(:signed_data)
    end
  end

  defp signed_data(_element, _opts), do: malformed(:signed_data)

  defp optional_fields(fields) do
    {certificates, rest} = optional(fields, 0xA0)
    {crls, rest} = optional(rest, 0xA1)

    case rest do
      [signers] -> {:ok, certificates, crls, signers}
      _ -> :error
    end
  end

  defp optional([{id, _, _} = element | rest], id), do: {element, rest}
  defp optional(rest, _id), do: {nil, rest}

  defp digest_algorithms(set) do
    set
    |> DER.children()
    |> Enum.reduce_while({:ok, []}, fn element, {:ok, acc} ->
      case Algorithm.read(element) do
        {:ok, {oid, _}} -> {:cont, {:ok, [OID.name(oid) | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, names} -> {:ok, Enum.reverse(names)}
      :error -> :error
    end
  end

  # EncapsulatedContentInfo (RFC 5652, 5.2), or the PKCS #7 form, where the
  # content is any type and only its content octets are signed (5.2.1).
  defp encap_content_info({0x30, _, raw} = element) do
    case DER.children(element) do
      [oid] ->
        with {:ok, oid} <- DER.oid(oid),
             do: {:ok, %{content_type: OID.name(oid), content: nil, pkcs7_content: nil, raw: raw}}

      [oid, {0xA0, _, _} = explicit] ->
        with {:ok, oid} <- DER.oid(oid),
             [value] <- DER.children(explicit),
             {:ok, content, pkcs7} <- encap_content(OID.name(oid), value) do
          {:ok, %{content_type: OID.name(oid), content: content, pkcs7_content: pkcs7, raw: raw}}
        else
          _ -> :error
        end

      _ ->
        :error
    end
  end

  defp encap_content(_type, {id, _, _} = value) when id in [0x04, 0x24] do
    with {:ok, content} <- DER.octets(value), do: {:ok, content, nil}
  end

  defp encap_content(:data, _value), do: :error
  defp encap_content(_type, {_id, content, raw}), do: {:ok, content, raw}

  defp certificates(nil, _opts), do: {:ok, %{certificates: [], other_certificates: []}}

  defp certificates(set, opts) do
    children = DER.children(set)

    cond do
      length(children) > opts.max_certificates ->
        {:error, Error.new(:limit_exceeded, :max_certificates)}

      Enum.all?(children, &match?({id, _, _} when id in [0x30, 0xA0, 0xA1, 0xA2, 0xA3], &1)) ->
        {x509, other} = Enum.split_with(children, &match?({0x30, _, _}, &1))
        {:ok, %{certificates: raws(x509), other_certificates: raws(other)}}

      true ->
        malformed(:certificates)
    end
  end

  defp crls(nil, _opts), do: {:ok, %{crls: [], other_crls: []}}

  defp crls(set, opts) do
    children = DER.children(set)

    cond do
      length(children) > opts.max_certificates ->
        {:error, Error.new(:limit_exceeded, :max_certificates)}

      Enum.all?(children, &match?({id, _, _} when id in [0x30, 0xA1], &1)) ->
        {lists, other} = Enum.split_with(children, &match?({0x30, _, _}, &1))
        {:ok, %{crls: raws(lists), other_crls: raws(other)}}

      true ->
        malformed(:crls)
    end
  end

  defp raws(elements), do: Enum.map(elements, &elem(&1, 2))

  defp signer_infos(set, opts) do
    children = DER.children(set)

    if length(children) > opts.max_signers,
      do: {:error, Error.new(:limit_exceeded, :max_signers)},
      else: signer_infos(children, 0, opts, [])
  end

  defp signer_infos([], _index, _opts, acc), do: {:ok, Enum.reverse(acc)}

  defp signer_infos([element | rest], index, opts, acc) do
    case SignerInfo.parse(element, opts) do
      {:ok, signer_info} -> signer_infos(rest, index + 1, opts, [signer_info | acc])
      {:error, error} -> {:error, %{error | signer: index}}
    end
  end

  defp deviations(signed_data) do
    if signed_data.version == expected_version(signed_data),
      do: [],
      else: [:signed_data_version]
  end

  @doc false
  # The version the fields call for (RFC 5652, 5.1).
  @spec expected_version(t()) :: 1 | 3 | 4 | 5
  def expected_version(%__MODULE__{} = signed_data) do
    tags = Enum.map(signed_data.other_certificates, &:binary.first/1)

    cond do
      0xA3 in tags or signed_data.other_crls != [] -> 5
      0xA2 in tags -> 4
      0xA1 in tags or signed_data.content_type != :data -> 3
      Enum.any?(signed_data.signer_infos, &(&1.version == 3)) -> 3
      true -> 1
    end
  end

  defp malformed(where), do: {:error, Error.new(:malformed, where)}
end
