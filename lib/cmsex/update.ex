defmodule Cmsex.Update do
  @moduledoc false
  # Changes to a SignedData that exists: more signers, a countersignature,
  # an unsigned attribute.
  #
  # What does not change keeps its bytes and its place: the other
  # SignerInfos, the signed part of the SignerInfo that gains an unsigned
  # attribute, the attributes and certificates already there. What is added
  # goes last. So every signature of the message still verifies, and the
  # position of each signer and countersignature stays what it was. The
  # SETs are not sorted again, so the result is in DER where the message
  # was and the additions keep its order; the encapsulated content is
  # written in DER when it was not.

  alias Cmsex.{Algorithm, DER, Error, Options, Sign, SignedData, SignerInfo}

  @sign_options [
    :certificates,
    :crls,
    :no_attributes,
    :min_rsa_bits,
    :digest,
    :rsa_padding,
    :identifier,
    :signing_time,
    :algorithm_protection
  ]

  @doc "See `Cmsex.add_signer/3`."
  @spec add_signer(binary(), term(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def add_signer(der, signers, opts) do
    {read, sign} = split!(opts, [:content])

    with {:ok, signed_data} <- SignedData.parse(der, read),
         {:ok, content} <- content(signed_data, read.content) do
      sign = Map.put(sign, :content_type, signed_data.content_type)
      no_attributes!(sign, content)

      with {:ok, added} <- Sign.signer_infos(content, signers, sign, check(signed_data)) do
        signer_infos = Enum.map(signed_data.signer_infos, & &1.raw.signer_info)
        {:ok, encode(signed_data, %{added | signer_infos: signer_infos ++ added.signer_infos})}
      end
    end
  end

  @doc "See `Cmsex.countersign/4`."
  @spec countersign(binary(), term(), term(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def countersign(der, path, signers, opts) do
    path = path!(path)
    {read, sign} = split!(opts, [])
    sign = Map.put(sign, :content_type, nil)

    with {:ok, signed_data} <- SignedData.parse(der, read) do
      update(signed_data, path, read, &countersign_one(&1, signers, sign, read))
    end
  end

  # The digests and versions of countersignatures are not those of the
  # SignedData (RFC 5652, 5.1).
  defp countersign_one(signer_info, signers, sign, read) do
    with {:ok, added} <- Sign.signer_infos(signer_info.signature, signers, sign) do
      {:ok, countersigned(signer_info, added.signer_infos, read),
       %{added | digest_ids: [], versions: []}}
    end
  end

  @doc "See `Cmsex.add_unsigned_attribute/4`."
  @spec add_unsigned_attribute(binary(), term(), [Cmsex.Attribute.t()], keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def add_unsigned_attribute(der, path, attributes, opts) do
    path = path!(path)
    read = Options.take!(opts, Options.limits())

    with {:ok, signed_data} <- SignedData.parse(der, read) do
      update(signed_data, path, read, fn signer_info ->
        terms = Enum.map(attributes, &Cmsex.Attribute.to_term/1)
        {:ok, with_unsigned(signer_info, unsigned(signer_info, read) ++ terms), nothing()}
      end)
    end
  end

  ## Options

  # The limits of reading, with `extra`, and the options of signing.
  defp split!(opts, extra) do
    unless Keyword.keyword?(opts),
      do: raise(ArgumentError, "expected a keyword list of options, got: #{inspect(opts)}")

    {read, sign} = Keyword.split(opts, extra ++ Options.limits())
    {Options.take!(read, extra ++ Options.limits()), Sign.options(sign, @sign_options)}
  end

  defp no_attributes!(%{no_attributes: true, content_type: type}, content)
       when type != :data or not is_binary(content),
       do:
         raise(
           ArgumentError,
           "no_attributes: true needs id-data content given as a binary (RFC 5652, 5.3)"
         )

  defp no_attributes!(_sign, _content), do: :ok

  # A position: an integer for a signer of the message, or a list, where
  # [0, 1] is the second countersignature of the first signer.
  defp path!(index) when is_integer(index) and index >= 0, do: [index]

  defp path!([_ | _] = path) do
    if Enum.all?(path, &(is_integer(&1) and &1 >= 0)), do: path, else: bad_path!(path)
  end

  defp path!(path), do: bad_path!(path)

  @spec bad_path!(term()) :: no_return()
  defp bad_path!(path) do
    raise ArgumentError,
          "expected the position of a signer, an integer or a list of them, got: #{inspect(path)}"
  end

  defp nothing, do: %{digest_ids: [], versions: [], certificates: [], crls: []}

  ## Content

  defp content(%SignedData{content: nil}, nil), do: {:error, Error.new(:content_required)}
  defp content(%SignedData{content: nil}, given), do: {:ok, given}
  defp content(%SignedData{content: content}, nil), do: {:ok, content}
  defp content(_signed_data, _given), do: {:error, Error.new(:unexpected_content)}

  # The content given for a detached message must be the one the signers
  # there signed: their message digests are checked before anything is
  # signed. A signer without signed attributes, or whose digest cannot be
  # told from the content given, is not checked.
  defp check(signed_data) do
    signers =
      for {signer_info, index} <- Enum.with_index(signed_data.signer_infos),
          signer_info.signed_attributes != nil,
          {:ok, alg} <- [Algorithm.read(signer_info.raw.digest_algorithm)],
          {:ok, hash} <- [Algorithm.digest(alg)],
          {:ok, digest} <- [SignerInfo.read_attribute(signer_info, :message_digest)],
          do: {index, hash, digest}

    {Enum.map(signers, &elem(&1, 1)),
     fn digests ->
       case Enum.find(signers, fn {_, hash, digest} -> mismatch?(digests, hash, digest) end) do
         nil -> :ok
         {index, _, _} -> {:error, %{Error.new(:digest_mismatch) | signer: index}}
       end
     end}
  end

  defp mismatch?(digests, hash, digest) do
    case Map.fetch(digests, hash) do
      {:ok, value} -> value != digest
      :error -> false
    end
  end

  ## The SignerInfo at a position

  # Replaces the SignerInfo at `path` by what `fun` returns for it, and
  # writes the message with what `fun` adds to it.
  defp update(signed_data, [index | rest], read, fun) do
    case Enum.fetch(signed_data.signer_infos, index) do
      {:ok, signer_info} ->
        with {:ok, der, added} <- nested(signer_info, rest, [index], read, fun) do
          signer_infos =
            signed_data.signer_infos
            |> Enum.map(& &1.raw.signer_info)
            |> List.replace_at(index, der)

          {:ok, encode(signed_data, Map.put(added, :signer_infos, signer_infos))}
        end

      :error ->
        no_signer!([index])
    end
  end

  defp nested(signer_info, [], _at, _read, fun), do: fun.(signer_info)

  defp nested(signer_info, [index | rest], at, read, fun) do
    at = at ++ [index]
    attributes = unsigned(signer_info, read)

    case countersignature_at(attributes, index, read) do
      nil ->
        no_signer!(at)

      {position, number, value} ->
        with {:ok, counter} <- read_countersignature(value, at, read),
             {:ok, der, added} <- nested(counter, rest, at, read, fun) do
          attributes = List.update_at(attributes, position, &replace_value(&1, number, der, read))
          {:ok, with_unsigned(signer_info, attributes), added}
        end
    end
  end

  @spec no_signer!([non_neg_integer()]) :: no_return()
  defp no_signer!(path),
    do: raise(ArgumentError, "the message has no signer at #{inspect(path)}")

  # The unsigned attributes of a SignerInfo, each as received.
  defp unsigned(signer_info, read) do
    {:ok, element} =
      DER.decode(signer_info.raw.signer_info,
        max_depth: read.max_depth,
        max_elements: read.max_elements
      )

    case List.last(DER.children(element)) do
      {0xA1, _, _} = set -> Enum.map(DER.children(set), &{:raw, elem(&1, 2)})
      _ -> []
    end
  end

  # The countersignatures are numbered across all the countersignature
  # attributes of a signer, in order. The one of number `index`, as the
  # position of its attribute, its place among the values there, and its
  # bytes; or nil.
  defp countersignature_at(attributes, index, read) do
    attributes
    |> Enum.with_index()
    |> Enum.flat_map(fn {{:raw, raw}, position} ->
      raw
      |> countersignature_values(read)
      |> Enum.with_index(fn value, number -> {position, number, value} end)
    end)
    |> Enum.at(index)
  end

  defp countersignature_values(raw, read) do
    with {:ok, element} <-
           DER.decode(raw, max_depth: read.max_depth, max_elements: read.max_elements),
         {:ok, %Cmsex.Attribute{type: :countersignature, values: values}} <-
           Cmsex.Attribute.read(element) do
      values
    else
      _ -> []
    end
  end

  defp read_countersignature(value, at, read) do
    case DER.decode(value, max_depth: read.max_depth, max_elements: read.max_elements) do
      {:ok, element} ->
        case SignerInfo.parse(element, read) do
          {:ok, signer_info} -> {:ok, signer_info}
          {:error, error} -> {:error, %{error | signer: at}}
        end

      {:error, _} ->
        {:error, %{Error.new(:malformed, :countersignature) | signer: at}}
    end
  end

  # The attribute with the value at `number` replaced, the others as
  # received.
  defp replace_value({:raw, raw}, number, new, read) do
    {oid, values} = attribute_parts(raw, read)
    {:seq, [oid, {:constructed, 0x31, List.replace_at(values, number, {:raw, new})}]}
  end

  defp attribute_parts(raw, read) do
    {:ok, element} = DER.decode(raw, max_depth: read.max_depth, max_elements: read.max_elements)
    [{_, _, oid}, set] = DER.children(element)
    {{:raw, oid}, for({_, _, value} <- DER.children(set), do: {:raw, value})}
  end

  # The signed part as received, then the unsigned attributes.
  defp with_unsigned(signer_info, attributes) do
    signed = Enum.map(signer_info.raw.signed_part, &{:raw, &1})
    DER.encode({:seq, signed ++ [{:constructed, 0xA1, attributes}]})
  end

  # The new countersignatures go at the end of the last countersignature
  # attribute, or in a new one at the end, so that the others keep their
  # numbers.
  defp countersigned(signer_info, counters, read) do
    attributes = unsigned(signer_info, read)
    values = Enum.map(counters, &{:raw, &1})

    last =
      attributes
      |> Enum.with_index()
      |> Enum.filter(fn {{:raw, raw}, _} -> countersignature_values(raw, read) != [] end)
      |> List.last()

    attributes =
      case last do
        nil ->
          attributes ++ [{:seq, [{:oid, :countersignature}, {:constructed, 0x31, values}]}]

        {_, position} ->
          List.update_at(attributes, position, &append_values(&1, values, read))
      end

    with_unsigned(signer_info, attributes)
  end

  defp append_values({:raw, raw}, values, read) do
    {oid, old} = attribute_parts(raw, read)
    {:seq, [oid, {:constructed, 0x31, old ++ values}]}
  end

  ## The message

  defp encode(signed_data, changes) do
    [version, digests, encap | _rest] = DER.children(signed_data.raw.signed_data)

    fields =
      [
        version(signed_data, version, changes.versions),
        digest_algorithms(signed_data, digests, changes.digest_ids),
        encap(signed_data, encap)
      ] ++
        added(signed_data.raw.certificates, 0xA0, changes.certificates) ++
        added(signed_data.raw.crls, 0xA1, changes.crls) ++
        [{:constructed, 0x31, Enum.map(changes.signer_infos, &{:raw, &1})}]

    DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, {:seq, fields}}]})
  end

  # RFC 5652, 5.1: a signer of version 3 makes the message version 3. A
  # version already higher stays.
  defp version(signed_data, {_, _, raw}, versions) do
    needed = Enum.max([SignedData.expected_version(signed_data) | versions])

    if needed > signed_data.version,
      do: {:int, needed},
      else: {:raw, raw}
  end

  defp digest_algorithms(signed_data, {_, _, raw} = set, ids) do
    new =
      ids
      |> Enum.uniq()
      |> Enum.reject(fn {:seq, [{:oid, name} | _]} -> name in signed_data.digest_algorithms end)

    if new == [],
      do: {:raw, raw},
      else: {:constructed, 0x31, Enum.map(DER.children(set), &{:raw, elem(&1, 2)}) ++ new}
  end

  defp encap(signed_data, {_, _, raw}) do
    cond do
      DER.der?(raw) ->
        {:raw, raw}

      signed_data.content == nil ->
        {:seq, [{:oid, signed_data.content_type}]}

      signed_data.pkcs7_content ->
        pkcs7_encap(signed_data)

      true ->
        {:seq, [{:oid, signed_data.content_type}, {:explicit, 0, {:octets, signed_data.content}}]}
    end
  end

  defp pkcs7_encap(signed_data),
    do:
      {:seq,
       [{:oid, signed_data.content_type}, {:explicit, 0, {:raw, signed_data.pkcs7_content}}]}

  # The certificates or CRLs of the message, with those that are new after
  # them.
  defp added(nil, _tag, []), do: []
  defp added({_, _, raw}, _tag, []), do: [{:raw, raw}]

  defp added(element, tag, ders) do
    old = if element, do: Enum.map(DER.children(element), &elem(&1, 2)), else: []

    case Enum.uniq(ders) -- old do
      [] when element == nil -> []
      [] -> [{:raw, elem(element, 2)}]
      new -> [{:constructed, tag, Enum.map(old ++ new, &{:raw, &1})}]
    end
  end
end
