defmodule Cmsex.Message do
  @moduledoc false
  # Reading a ContentInfo of any of the types this library knows, and what
  # the types share: the limits on the input, the certificates and
  # revocation lists of SignedData and OriginatorInfo, attribute sets, and
  # EncapsulatedContentInfo.

  alias Cmsex.{
    Attribute,
    AuthenticatedData,
    DER,
    DigestedData,
    EncryptedData,
    EnvelopedData,
    Error,
    OID,
    SignedData
  }

  @type content_type ::
          :signed_data
          | :enveloped_data
          | :auth_enveloped_data
          | :encrypted_data
          | :digested_data
          | :auth_data

  @type t ::
          SignedData.t()
          | EnvelopedData.t()
          | EncryptedData.t()
          | DigestedData.t()
          | AuthenticatedData.t()

  @types [
    :signed_data,
    :enveloped_data,
    :auth_enveloped_data,
    :encrypted_data,
    :digested_data,
    :auth_data
  ]

  @doc """
  Reads a ContentInfo whose type is one of `types`. `opts` is the map of
  Cmsex.Options with the limits.
  """
  @spec parse(binary(), map(), [content_type()]) :: {:ok, t()} | {:error, Error.t()}
  def parse(der, opts, types \\ @types) do
    with {:ok, root} <- decode(der, opts),
         {:ok, type, content} <- content_info(root) do
      name = OID.name(type)

      if name in types,
        do: read(name, content, opts),
        else: {:error, Error.new(:unsupported_content_type, type)}
    end
  end

  defp read(:signed_data, content, opts), do: SignedData.read(content, opts)

  defp read(:enveloped_data, content, opts),
    do: EnvelopedData.read(:enveloped_data, content, opts)

  defp read(:auth_enveloped_data, content, opts),
    do: EnvelopedData.read(:auth_enveloped_data, content, opts)

  defp read(:encrypted_data, content, opts), do: EncryptedData.read(content, opts)
  defp read(:digested_data, content, opts), do: DigestedData.read(content, opts)
  defp read(:auth_data, content, opts), do: AuthenticatedData.read(content, opts)

  @doc "Decodes the input with the limits of `opts`."
  @spec decode(binary(), map()) :: {:ok, DER.element()} | {:error, Error.t()}
  def decode(der, opts) do
    case DER.decode(der, max_depth: opts.max_depth, max_elements: opts.max_elements) do
      {:ok, root} -> {:ok, root}
      {:error, {:limit_exceeded, limit}} -> {:error, Error.new(:limit_exceeded, limit)}
      {:error, :malformed} -> {:error, Error.new(:malformed)}
    end
  end

  @doc "ContentInfo (RFC 5652, 3): the type and the element inside [0]."
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

  @doc "The next field, when it has the identifier `id`."
  @spec optional([DER.element()], DER.id()) :: {DER.element() | nil, [DER.element()]}
  def optional([{id, _, _} = element | rest], id), do: {element, rest}
  def optional(rest, _id), do: {nil, rest}

  @doc "A CMSVersion."
  @spec version(DER.element()) :: {:ok, 0..255} | :error
  def version(element) do
    case DER.integer(element) do
      {:ok, version} when version in 0..255 -> {:ok, version}
      _ -> :error
    end
  end

  ## Certificates

  @doc """
  The CertificateSet and RevocationInfoChoices of a SignedData or an
  OriginatorInfo (RFC 5652, 10.2), each `nil` when absent: X.509
  certificates and lists apart from the other choices, all as received.
  """
  @spec certificates(DER.element() | nil, DER.element() | nil, map()) ::
          {:ok, map()} | {:error, Error.t()}
  def certificates(certificates, crls, opts) do
    with {:ok, certs} <- certificate_set(certificates, opts),
         {:ok, revocation} <- revocation_info(crls, opts) do
      {:ok, Map.merge(certs, revocation)}
    end
  end

  defp certificate_set(nil, _opts), do: {:ok, %{certificates: [], other_certificates: []}}

  defp certificate_set(set, opts) do
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

  defp revocation_info(nil, _opts), do: {:ok, %{crls: [], other_crls: []}}

  defp revocation_info(set, opts) do
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

  @doc """
  OriginatorInfo (RFC 5652, 6.1), `nil` when absent: its certificates and
  revocation lists, as `certificates/3` reads them.
  """
  @spec originator_info(DER.element() | nil, map()) :: {:ok, map()} | {:error, Error.t()}
  def originator_info(nil, opts), do: certificates(nil, nil, opts)

  def originator_info(element, opts) do
    {certificates, rest} = optional(DER.children(element), 0xA0)
    {crls, rest} = optional(rest, 0xA1)

    if rest == [],
      do: certificates(certificates, crls, opts),
      else: malformed(:originator_info)
  end

  @doc """
  The version a message with an OriginatorInfo calls for, from the tags of
  its other certificates and revocation lists: `:other` for the other
  formats, `:v2_attribute` for version 2 attribute certificates, or `nil`.
  """
  @spec originator_kind(%{
          :other_certificates => [binary()],
          :other_crls => [binary()],
          optional(atom()) => term()
        }) :: :other | :v2_attribute | nil
  def originator_kind(%{other_certificates: certificates, other_crls: crls}) do
    tags = Enum.map(certificates, &:binary.first/1)

    cond do
      0xA3 in tags or crls != [] -> :other
      0xA2 in tags -> :v2_attribute
      true -> nil
    end
  end

  ## Attributes

  @doc """
  A SET OF Attribute under an implicit tag, `nil` when absent, with at most
  `max_attributes`.
  """
  @spec attributes(DER.element() | nil, map()) ::
          {:ok, [Attribute.t()] | nil} | {:error, Error.t()}
  def attributes(nil, _opts), do: {:ok, nil}

  def attributes(element, opts) do
    children = DER.children(element)

    if length(children) > opts.max_attributes,
      do: {:error, Error.new(:limit_exceeded, :max_attributes)},
      else: read_attributes(children, [])
  end

  @doc """
  The value of the attribute of `type` in `attributes`, which must have
  one, with one value: an OID for `:content_type`, an OCTET STRING for
  `:message_digest`.
  """
  @spec read_attribute([Attribute.t()] | nil, :content_type | :message_digest) ::
          {:ok, term()} | {:error, :missing | :invalid}
  def read_attribute(attributes, type) do
    case for(%Attribute{type: ^type} = attribute <- attributes || [], do: attribute) do
      [] -> {:error, :missing}
      [%Attribute{values: [value]}] -> attribute_value(type, value)
      _ -> {:error, :invalid}
    end
  end

  defp attribute_value(type, value) do
    result =
      case {type, DER.decode(value)} do
        {:content_type, {:ok, element}} -> DER.oid(element)
        {:message_digest, {:ok, element}} -> DER.octets(element)
        _ -> :error
      end

    case result do
      {:ok, oid} when type == :content_type -> {:ok, OID.name(oid)}
      {:ok, value} -> {:ok, value}
      :error -> {:error, :invalid}
    end
  end

  defp read_attributes([], acc), do: {:ok, Enum.reverse(acc)}

  defp read_attributes([element | rest], acc) do
    case Attribute.read(element) do
      {:ok, attribute} -> read_attributes(rest, [attribute | acc])
      :error -> {:error, Error.new(:malformed, :attribute)}
    end
  end

  ## Content

  @doc """
  EncapsulatedContentInfo (RFC 5652, 5.2), or the PKCS #7 form, where the
  content is any type and only its content octets are signed (5.2.1).
  """
  @spec encap_content_info(DER.element()) :: {:ok, map()} | :error
  def encap_content_info({0x30, _, raw} = element) do
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

  def encap_content_info(_element), do: :error

  defp encap_content(_type, {id, _, _} = value) when id in [0x04, 0x24] do
    with {:ok, content} <- DER.octets(value), do: {:ok, content, nil}
  end

  defp encap_content(:data, _value), do: :error
  defp encap_content(_type, {_id, content, raw}), do: {:ok, content, raw}

  @doc """
  EncryptedContentInfo (RFC 5652, 6.1): the content type, the
  content-encryption AlgorithmIdentifier, and the encrypted content, `nil`
  when it is not in the message.
  """
  @spec encrypted_content_info(DER.element()) ::
          {:ok,
           %{
             content_type: atom() | tuple(),
             algorithm: Cmsex.Algorithm.t(),
             content: binary() | nil
           }}
          | :error
  def encrypted_content_info({0x30, _, _} = element) do
    {fields, content} =
      case DER.children(element) do
        [type, alg, {id, _, _} = content] when id in [0x80, 0xA0] -> {[type, alg], content}
        fields -> {fields, nil}
      end

    with [type, alg] <- fields,
         {:ok, type} <- DER.oid(type),
         {:ok, alg} <- Cmsex.Algorithm.read(alg),
         {:ok, content} <- encrypted_content(content) do
      {:ok, %{content_type: OID.name(type), algorithm: alg, content: content}}
    else
      _ -> :error
    end
  end

  def encrypted_content_info(_element), do: :error

  defp encrypted_content(nil), do: {:ok, nil}
  defp encrypted_content(element), do: DER.string(element, 0x80)

  @doc """
  The content to work on: the one in the message, or the one the caller
  gave for a detached message, but not both and not neither.
  """
  @spec content(binary() | nil, term()) :: {:ok, term()} | {:error, Error.t()}
  def content(nil, nil), do: {:error, Error.new(:content_required)}
  def content(nil, given), do: {:ok, given}
  def content(in_message, nil), do: {:ok, in_message}
  def content(_in_message, _given), do: {:error, Error.new(:unexpected_content)}

  @doc "A malformed error, with where."
  @spec malformed(atom()) :: {:error, Error.t()}
  def malformed(where), do: {:error, Error.new(:malformed, where)}
end
