defmodule Cmsex.EnvelopedData do
  @moduledoc """
  An EnvelopedData (RFC 5652, 6) or AuthEnvelopedData (RFC 5083) message,
  as `Cmsex.decode/2` reads it. Reading checks the structure only;
  `Cmsex.decrypt/2` decrypts.

  Fields:

    * `:type` - `:enveloped_data`, or `:auth_enveloped_data` for content
      encrypted with an authenticated cipher, such as AES-GCM.
    * `:version` - the version written in the message.
    * `:recipient_infos` - the recipients, a list of `Cmsex.RecipientInfo`.
    * `:content_type` - the type of the encrypted content, as a name of
      `Cmsex.OID`, such as `:data`, or an OID.
    * `:content_encryption_algorithm` - the name of the cipher in
      `Cmsex.OID`, such as `:aes256_cbc` or `:aes256_gcm`, or its OID.
    * `:encrypted_content` - the ciphertext, its segments joined when the
      message was written in BER, or `nil` when it is not in the message.
    * `:certificates`, `:other_certificates`, `:crls`, `:other_crls` - the
      OriginatorInfo, as in `Cmsex.SignedData`; empty when it is absent.
    * `:authenticated_attributes` - for `:auth_enveloped_data`, the
      attributes the tag covers, a list of `Cmsex.Attribute`, or `nil`.
    * `:mac` - for `:auth_enveloped_data`, the tag; `nil` otherwise.
    * `:unprotected_attributes` - the unprotectedAttrs of an EnvelopedData,
      or the unauthAttrs of an AuthEnvelopedData: attributes that nothing
      protects, empty when there are none.
    * `:deviations` - what the library tolerated when reading, against
      RFC 5652 and RFC 5083: `:enveloped_data_version` when the version is
      not the one the fields call for. The recipients have their own.
  """

  alias Cmsex.{Attribute, DER, Error, Message, RecipientInfo}

  @type t :: %__MODULE__{
          type: :enveloped_data | :auth_enveloped_data,
          version: integer(),
          recipient_infos: [RecipientInfo.t()],
          content_type: atom() | tuple(),
          content_encryption_algorithm: atom() | tuple(),
          encrypted_content: binary() | nil,
          certificates: [binary()],
          other_certificates: [binary()],
          crls: [binary()],
          other_crls: [binary()],
          authenticated_attributes: [Attribute.t()] | nil,
          mac: binary() | nil,
          unprotected_attributes: [Attribute.t()],
          deviations: [atom()],
          raw: map() | nil
        }

  @derive {Inspect, except: [:raw]}
  defstruct [
    :type,
    :version,
    :content_type,
    :content_encryption_algorithm,
    :encrypted_content,
    :authenticated_attributes,
    :mac,
    recipient_infos: [],
    certificates: [],
    other_certificates: [],
    crls: [],
    other_crls: [],
    unprotected_attributes: [],
    deviations: [],
    raw: nil
  ]

  @doc false
  # Reads the EnvelopedData or AuthEnvelopedData inside a ContentInfo.
  @spec read(:enveloped_data | :auth_enveloped_data, DER.element(), map()) ::
          {:ok, t()} | {:error, Error.t()}
  def read(type, {0x30, _, _} = element, opts) do
    with {:ok, fields} <- fields(type, DER.children(element)),
         {:ok, version} <- Message.version(fields.version),
         {:ok, info} <- Message.encrypted_content_info(fields.info) do
      with {:ok, originator} <- Message.originator_info(fields.originator, opts),
           {:ok, recipient_infos} <- recipient_infos(fields.recipients, opts),
           {:ok, authenticated} <- Message.attributes(fields.authenticated, opts),
           {:ok, unprotected} <- Message.attributes(fields.unprotected, opts) do
        {oid, _} = info.algorithm

        enveloped_data =
          struct!(
            %__MODULE__{
              type: type,
              version: version,
              recipient_infos: recipient_infos,
              content_type: info.content_type,
              content_encryption_algorithm: Cmsex.OID.name(oid),
              encrypted_content: info.content,
              authenticated_attributes: authenticated,
              mac: fields.mac,
              unprotected_attributes: unprotected || [],
              raw: %{
                content_encryption_algorithm: info.algorithm,
                authenticated_attributes: fields.authenticated && elem(fields.authenticated, 2),
                originator_info: fields.originator
              }
            },
            originator
          )

        {:ok, %{enveloped_data | deviations: deviations(enveloped_data)}}
      end
    else
      _ -> Message.malformed(type)
    end
  end

  def read(type, _element, _opts), do: Message.malformed(type)

  # EnvelopedData (RFC 5652, 6.1): version, originatorInfo [0],
  # recipientInfos, encryptedContentInfo, unprotectedAttrs [1].
  defp fields(:enveloped_data, [version | rest]) do
    {originator, rest} = Message.optional(rest, 0xA0)

    with [{0x31, _, _} = recipients, info | rest] <- rest,
         {unprotected, []} <- Message.optional(rest, 0xA1) do
      {:ok,
       %{
         version: version,
         originator: originator,
         recipients: recipients,
         info: info,
         authenticated: nil,
         mac: nil,
         unprotected: unprotected
       }}
    else
      _ -> :error
    end
  end

  # AuthEnvelopedData (RFC 5083, 2.1): version, originatorInfo [0],
  # recipientInfos, authEncryptedContentInfo, authAttrs [1], mac,
  # unauthAttrs [2].
  defp fields(:auth_enveloped_data, [version | rest]) do
    {originator, rest} = Message.optional(rest, 0xA0)

    with [{0x31, _, _} = recipients, info | rest] <- rest,
         {authenticated, [mac | rest]} <- Message.optional(rest, 0xA1),
         {:ok, mac} <- DER.octets(mac),
         {unauthenticated, []} <- Message.optional(rest, 0xA2) do
      {:ok,
       %{
         version: version,
         originator: originator,
         recipients: recipients,
         info: info,
         authenticated: authenticated,
         mac: mac,
         unprotected: unauthenticated
       }}
    else
      _ -> :error
    end
  end

  defp fields(_type, _fields), do: :error

  @doc false
  # The RecipientInfos of a message: at least one, at most `max_recipients`.
  @spec recipient_infos(DER.element(), map()) ::
          {:ok, [RecipientInfo.t(), ...]} | {:error, Error.t()}
  def recipient_infos(set, opts) do
    case DER.children(set) do
      [] ->
        Message.malformed(:recipient_infos)

      children when length(children) > opts.max_recipients ->
        {:error, Error.new(:limit_exceeded, :max_recipients)}

      children ->
        read_recipient_infos(children, opts, [])
    end
  end

  defp read_recipient_infos([], _opts, acc), do: {:ok, Enum.reverse(acc)}

  defp read_recipient_infos([element | rest], opts, acc) do
    with {:ok, info} <- RecipientInfo.parse(element, opts) do
      read_recipient_infos(rest, opts, [info | acc])
    end
  end

  defp deviations(enveloped_data) do
    if enveloped_data.version == expected_version(enveloped_data),
      do: [],
      else: [:enveloped_data_version]
  end

  @doc false
  # The version the fields call for (RFC 5652, 6.1; RFC 5083, 2.1).
  @spec expected_version(t()) :: 0 | 2 | 3 | 4
  def expected_version(%__MODULE__{type: :auth_enveloped_data}), do: 0

  def expected_version(%__MODULE__{} = enveloped_data) do
    version(
      Message.originator_kind(enveloped_data),
      enveloped_data.raw.originator_info != nil,
      Enum.map(enveloped_data.recipient_infos, &{&1.type, &1.version}),
      enveloped_data.unprotected_attributes != []
    )
  end

  @doc false
  # The rule of RFC 5652, 6.1, from the kind of the originator certificates
  # and revocation lists, whether there is an OriginatorInfo, the type and
  # version of each recipient, and whether there are unprotected
  # attributes.
  @spec version(:other | :v2_attribute | nil, boolean(), [{atom(), integer() | nil}], boolean()) ::
          0 | 2 | 3 | 4
  def version(kind, originator?, recipients, unprotected?) do
    types = Enum.map(recipients, &elem(&1, 0))

    cond do
      kind == :other ->
        4

      kind == :v2_attribute or :password in types or :other in types ->
        3

      not originator? and not unprotected? and Enum.all?(recipients, &(elem(&1, 1) == 0)) ->
        0

      true ->
        2
    end
  end
end
