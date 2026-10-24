defmodule Cmsex.Compose do
  @moduledoc false
  # What the writers of EnvelopedData, AuthEnvelopedData, EncryptedData,
  # DigestedData and AuthenticatedData share: their options, the
  # recipients, the OriginatorInfo, the attributes and the ContentInfo.

  alias Cmsex.{
    Attribute,
    Certificate,
    DER,
    Error,
    OID,
    Options,
    Recipient,
    RecipientKey
  }

  # The ciphers written. Triple-DES and RC2 are read only.
  @ciphers [
    :aes128_cbc,
    :aes192_cbc,
    :aes256_cbc,
    :aes128_gcm,
    :aes192_gcm,
    :aes256_gcm,
    :aes128_ccm,
    :aes192_ccm,
    :aes256_ccm,
    :chacha20_poly1305
  ]

  @macs [:hmac_sha224, :hmac_sha256, :hmac_sha384, :hmac_sha512]
  @digests [:sha224, :sha256, :sha384, :sha512]

  ## Options

  @doc """
  Checks `opts` against the keys of `defaults` and returns them as a map,
  with the defaults filled in and the content type as a name of
  `Cmsex.OID`. An unknown option, or a value of the wrong kind, raises
  `ArgumentError`.
  """
  @spec options!(keyword(), map()) :: map()
  def options!(opts, defaults) do
    unless Keyword.keyword?(opts),
      do: raise(ArgumentError, "expected a keyword list of options, got: #{inspect(opts)}")

    for {key, value} <- opts do
      unless is_map_key(defaults, key), do: raise(ArgumentError, "unknown option #{inspect(key)}")
      check!(key, value)
    end

    opts = Map.merge(defaults, Map.new(opts))
    %{opts | content_type: OID.name(OID.oid(opts.content_type))}
  end

  defp check!(:cipher, value),
    do: ensure!(value in @ciphers, ":cipher must be one of #{inspect(@ciphers)}", value)

  defp check!(:mac, value),
    do: ensure!(value in @macs, ":mac must be one of #{inspect(@macs)}", value)

  defp check!(:digest, value),
    do: ensure!(value in @digests, ":digest must be one of #{inspect(@digests)}", value)

  defp check!(:tag_size, value),
    do: ensure!(is_integer(value), ":tag_size must be an integer", value)

  defp check!(:content_type, value) do
    ensure!(is_atom(value) or is_tuple(value), ":content_type must be an OID", value)
    _ = value |> OID.oid() |> OID.encode()
    :ok
  end

  defp check!(:detached, value),
    do: ensure!(is_boolean(value), ":detached must be a boolean", value)

  defp check!(key, value) when key in [:unprotected_attributes, :unauthenticated_attributes],
    do: attributes!(key, value)

  defp check!(:authenticated_attributes, value) do
    attributes!(:authenticated_attributes, value)

    for %Attribute{type: type} <- value, type in [:content_type, :message_digest] do
      raise ArgumentError,
            "the authenticated attribute #{inspect(type)} is written by the library, or not at all"
    end
  end

  defp check!(key, value) when key in [:certificates, :crls] do
    ensure!(
      is_list(value) and Enum.all?(value, &is_binary/1),
      "#{inspect(key)} must be a list of DER binaries",
      value
    )
  end

  defp check!(:min_rsa_bits, value),
    do:
      ensure!(is_integer(value) and value > 0, ":min_rsa_bits must be a positive integer", value)

  defp attributes!(key, value) do
    ensure!(
      is_list(value) and Enum.all?(value, &match?(%Attribute{}, &1)),
      "#{inspect(key)} must be a list of Cmsex.Attribute",
      value
    )
  end

  defp ensure!(true, _message, _value), do: :ok

  defp ensure!(false, message, value),
    do: raise(ArgumentError, "#{message}, got: #{inspect(value, limit: 5)}")

  @doc "Raises `ArgumentError` unless `content` is a binary."
  @spec binary!(binary()) :: :ok
  def binary!(content) do
    unless is_binary(content),
      do: raise(ArgumentError, "the content must be a binary, got #{Options.kind(content)}")

    :ok
  end

  @doc """
  Raises `ArgumentError` unless `content` is a binary, `{:stream,
  enumerable}` or `{:digest, hash, binary}`.
  """
  @spec content!(term()) :: :ok
  def content!(content) do
    unless Options.content?(content),
      do:
        raise(
          ArgumentError,
          "the content must be a binary, {:stream, enumerable} or {:digest, hash, binary}, " <>
            "got #{Options.kind(content)}"
        )

    :ok
  end

  @doc """
  Whether the content is left out of the message: `detached` when given,
  else for a stream and a ready digest, which can only be detached.
  """
  @spec detached!(term(), boolean() | nil) :: boolean()
  def detached!(content, detached) do
    case {detached, is_binary(content)} do
      {nil, binary?} -> not binary?
      {false, false} -> raise ArgumentError, "a stream or a digest can only be detached"
      {detached, _binary?} -> detached
    end
  end

  ## Recipients

  @doc "One recipient, a certificate in DER, or a list of them, as a list."
  @spec recipients!(term()) :: [Recipient.t(), ...]
  def recipients!(%Recipient{} = recipient), do: [recipient]
  def recipients!(certificate) when is_binary(certificate), do: [recipient!(certificate)]
  def recipients!([_ | _] = recipients), do: Enum.map(recipients, &recipient!/1)

  def recipients!(other),
    do:
      raise(
        ArgumentError,
        "expected a Cmsex.Recipient, a DER certificate or a list of them, got " <>
          Options.kind(other)
      )

  defp recipient!(%Recipient{} = recipient), do: recipient
  defp recipient!(certificate) when is_binary(certificate), do: Recipient.certificate(certificate)
  defp recipient!(other), do: recipients!(other)

  @doc """
  Checks every recipient before anything is encrypted. An error carries
  the position of its recipient.
  """
  @spec prepare([Recipient.t()], map()) :: {:ok, [map()]} | {:error, Error.t()}
  def prepare(recipients, opts), do: prepare(recipients, opts, 0, [])

  defp prepare([], _opts, _index, acc), do: {:ok, Enum.reverse(acc)}

  defp prepare([recipient | rest], opts, index, acc) do
    case RecipientKey.prepare(recipient, opts) do
      {:ok, prepared} -> prepare(rest, opts, index + 1, [prepared | acc])
      {:error, reason, detail} -> {:error, %{Error.new(reason, detail) | recipient: index}}
    end
  end

  @doc "The RecipientInfos that carry `key`, for the prepared recipients."
  @spec recipient_infos([map()], binary()) :: {:ok, [DER.term_()]} | {:error, Error.t()}
  def recipient_infos(prepared, key), do: recipient_infos(prepared, key, 0, [])

  defp recipient_infos([], _key, _index, acc), do: {:ok, Enum.reverse(acc)}

  defp recipient_infos([prepared | rest], key, index, acc) do
    case RecipientKey.encrypt(prepared, key) do
      {:ok, term} ->
        recipient_infos(rest, key, index + 1, [{:raw, DER.encode(term)} | acc])

      {:error, reason, detail} ->
        {:error, %{Error.new(reason, detail) | recipient: index}}
    end
  end

  @doc """
  The OriginatorInfo (RFC 5652, 6.1): certs [0] and crls [1], only X.509,
  or `nil` without either.
  """
  @spec originator_info([binary()], [binary()]) ::
          {:ok, DER.term_() | nil} | {:error, Error.t()}
  def originator_info([], []), do: {:ok, nil}

  def originator_info(certificates, crls) do
    cond do
      not Enum.all?(certificates, &match?({:ok, _}, Certificate.parse(&1))) ->
        {:error, Error.new(:invalid_certificate)}

      not Enum.all?(crls, &match?({:ok, {0x30, _, _}}, DER.decode(&1))) ->
        {:error, Error.new(:malformed, :crls)}

      true ->
        fields =
          tagged_set(0xA0, Enum.uniq(certificates)) ++ tagged_set(0xA1, Enum.uniq(crls))

        {:ok, {:constructed, 0xA0, fields}}
    end
  end

  ## Encoding

  @doc "A SET OF Attribute under `tag`, or nothing when there are none."
  @spec attributes(byte(), [Attribute.t()]) :: [DER.term_()]
  def attributes(_tag, []), do: []
  def attributes(tag, attributes), do: [{:raw, DER.retag(attribute_set(attributes), tag)}]

  @doc "The DER of a SET OF Attribute."
  @spec attribute_set([Attribute.t()]) :: binary()
  def attribute_set(attributes),
    do: DER.encode({:set, Enum.map(attributes, &{:raw, DER.encode(Attribute.to_term(&1))})})

  @doc "The message-digest attribute (RFC 5652, 11.2)."
  @spec message_digest(binary()) :: Attribute.t()
  def message_digest(digest),
    do: %Attribute{type: :message_digest, values: [DER.encode({:octets, digest})]}

  @doc "EncapsulatedContentInfo (RFC 5652, 5.2), without eContent when detached."
  @spec encap_content_info(atom() | tuple(), binary() | nil) :: DER.term_()
  def encap_content_info(type, nil), do: {:seq, [{:oid, type}]}

  def encap_content_info(type, content),
    do: {:seq, [{:oid, type}, {:explicit, 0, {:octets, content}}]}

  @doc "A ContentInfo of `type` around the SEQUENCE of `fields`, in DER."
  @spec content_info(atom(), [DER.term_()]) :: binary()
  def content_info(type, fields),
    do: DER.encode({:seq, [{:oid, type}, {:explicit, 0, {:seq, fields}}]})

  defp tagged_set(_tag, []), do: []

  defp tagged_set(tag, ders),
    do: [{:raw, DER.retag(DER.encode({:set, Enum.map(ders, &{:raw, &1})}), tag)}]
end
