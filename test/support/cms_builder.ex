defmodule Cmsex.TestCMS do
  @moduledoc false
  # Messages built field by field, for the cases no signer writes on
  # purpose: odd versions, other certificate choices, PKCS #7 content,
  # broken attributes. Each function takes the fields as options and
  # returns DER, or a DER term with `term: true`.

  alias Cmsex.DER

  @doc """
  A ContentInfo with a SignedData. Options: `:version` (1),
  `:digest_algorithms` (`[:sha256]`), `:content_type` (`:data`),
  `:content` (a binary, `nil` for detached, or `{:raw, der}` for the value
  inside [0]), `:certificates` and `:crls` (lists of DER, or `nil` to leave
  the field out), `:signer_infos` (DER of each).
  """
  def signed_data(opts \\ []) do
    content =
      case Keyword.get(opts, :content, "content") do
        nil -> []
        {:raw, der} -> [{:explicit, 0, {:raw, der}}]
        bin -> [{:explicit, 0, {:octets, bin}}]
      end

    fields =
      [
        {:int, Keyword.get(opts, :version, 1)},
        {:set, Enum.map(Keyword.get(opts, :digest_algorithms, [:sha256]), &{:seq, [{:oid, &1}]})},
        {:seq, [{:oid, Keyword.get(opts, :content_type, :data)} | content]},
        tagged(0xA0, Keyword.get(opts, :certificates)),
        tagged(0xA1, Keyword.get(opts, :crls)),
        {:constructed, 0x31, Enum.map(Keyword.get(opts, :signer_infos, []), &{:raw, &1})}
      ]
      |> Enum.reject(&is_nil/1)

    DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, {:seq, fields}}]})
  end

  defp tagged(_id, nil), do: nil
  defp tagged(id, items), do: {:constructed, id, Enum.map(items, &{:raw, &1})}

  @doc """
  A SignerInfo. Options: `:version` (1), `:sid` (`{:issuer_and_serial,
  issuer_der, serial}` or `{:subject_key_identifier, ski}`), `:digest`
  (`:sha256`), `:signed` (a list of attribute DER, `{:raw, der}` for the
  whole [0], or `nil`), `:signature_algorithm` (a DER term),
  `:signature`, `:unsigned` (a list of attribute DER, or `nil`).
  """
  def signer_info(opts \\ []) do
    sid =
      case Keyword.get(opts, :sid, {:issuer_and_serial, DER.encode({:seq, []}), 1}) do
        {:issuer_and_serial, issuer, serial} -> {:seq, [{:raw, issuer}, {:int, serial}]}
        {:subject_key_identifier, ski} -> {:primitive, 0x80, ski}
      end

    signed =
      case Keyword.get(opts, :signed) do
        nil ->
          nil

        {:raw, der} ->
          {:raw, der}

        attributes ->
          {:raw, DER.retag(DER.encode({:set, Enum.map(attributes, &{:raw, &1})}), 0xA0)}
      end

    unsigned =
      case Keyword.get(opts, :unsigned) do
        nil -> nil
        attributes -> {:constructed, 0xA1, Enum.map(attributes, &{:raw, &1})}
      end

    [
      {:int, Keyword.get(opts, :version, 1)},
      sid,
      {:seq, [{:oid, Keyword.get(opts, :digest, :sha256)}]},
      signed,
      Keyword.get(opts, :signature_algorithm, {:seq, [{:oid, :rsa_encryption}, :null]}),
      {:octets, Keyword.get(opts, :signature, <<1, 2, 3>>)},
      unsigned
    ]
    |> Enum.reject(&is_nil/1)
    |> then(&DER.encode({:seq, &1}))
  end

  @doc "An Attribute in DER, with values as DER terms."
  def attribute(type, values), do: DER.encode({:seq, [{:oid, type}, {:set, values}]})

  @doc """
  Re-encodes a SignedData message as a streaming encoder writes it:
  indefinite lengths on the outer structures and the signers, and the
  eContent and signatures split in segments. The certificates, the CRLs
  and the signed attributes keep their bytes, so the message still
  verifies.
  """
  def to_ber(der) do
    {:ok, root} = DER.decode(der)
    [oid, explicit] = DER.children(root)
    [signed_data] = DER.children(explicit)
    indefinite(0x30, [raw(oid), indefinite(0xA0, [ber_signed_data(signed_data)])])
  end

  defp ber_signed_data(element) do
    [version, digests, encap | rest] = DER.children(element)

    rest =
      Enum.map(rest, fn
        {0x31, _, _} = signers -> indefinite(0x31, Enum.map(DER.children(signers), &ber_signer/1))
        {id, _, _} = set -> indefinite(id, Enum.map(DER.children(set), &raw/1))
      end)

    indefinite(0x30, [raw(version), raw(digests), ber_encap(encap) | rest])
  end

  defp ber_encap(element) do
    case DER.children(element) do
      [oid] ->
        indefinite(0x30, [raw(oid)])

      [oid, explicit] ->
        [value] = DER.children(explicit)
        indefinite(0x30, [raw(oid), indefinite(0xA0, [segments(value)])])
    end
  end

  defp ber_signer(element) do
    element
    |> DER.children()
    |> Enum.map(fn
      {0x04, _, _} = signature -> segments(signature)
      other -> raw(other)
    end)
    |> then(&indefinite(0x30, &1))
  end

  defp segments({0x04, bin, _raw}) do
    parts = for <<part::binary-size(16) <- bin>>, do: DER.encode({:octets, part})
    tail = rem(byte_size(bin), 16)

    last =
      if tail > 0,
        do: [DER.encode({:octets, binary_part(bin, byte_size(bin) - tail, tail)})],
        else: []

    indefinite(0x24, parts ++ last)
  end

  defp segments({_, _, raw}), do: raw

  defp raw({_, _, raw}), do: raw
  defp indefinite(id, parts), do: IO.iodata_to_binary([id, 0x80, parts, 0, 0])
end
