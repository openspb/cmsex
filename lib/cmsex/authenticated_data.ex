defmodule Cmsex.AuthenticatedData do
  @moduledoc """
  An AuthenticatedData message, as `Cmsex.decode/2` reads it (RFC 5652, 9):
  a content and a MAC over it, with the MAC key sent to each recipient as
  in EnvelopedData. The content is not encrypted. `Cmsex.verify_mac/2`
  checks it.

  Fields:

    * `:version` - the version written in the message.
    * `:recipient_infos` - the recipients, a list of `Cmsex.RecipientInfo`.
    * `:mac_algorithm` - the name of the MAC algorithm, such as
      `:hmac_sha256`, or its OID.
    * `:digest_algorithm` - the name of the digest algorithm of the
      message-digest attribute, or `nil` when there are no authenticated
      attributes.
    * `:content_type` - the type of the content, as a name of `Cmsex.OID`
      or an OID.
    * `:content` - the content, or `nil` when it is not in the message.
    * `:pkcs7_content` - as in `Cmsex.SignedData`.
    * `:certificates`, `:other_certificates`, `:crls`, `:other_crls` - the
      OriginatorInfo, empty when it is absent.
    * `:authenticated_attributes` - the attributes the MAC covers, a list
      of `Cmsex.Attribute`, or `nil`.
    * `:mac` - the MAC.
    * `:unauthenticated_attributes` - attributes the MAC does not cover,
      empty when there are none.
    * `:deviations` - `:auth_data_version` when the version is not the one
      the fields call for. The recipients have their own.
  """

  alias Cmsex.{Algorithm, Attribute, DER, EnvelopedData, Error, Message, OID, RecipientInfo}

  @type t :: %__MODULE__{
          version: integer(),
          recipient_infos: [RecipientInfo.t()],
          mac_algorithm: atom() | tuple(),
          digest_algorithm: atom() | tuple() | nil,
          content_type: atom() | tuple(),
          content: binary() | nil,
          pkcs7_content: binary() | nil,
          certificates: [binary()],
          other_certificates: [binary()],
          crls: [binary()],
          other_crls: [binary()],
          authenticated_attributes: [Attribute.t()] | nil,
          mac: binary(),
          unauthenticated_attributes: [Attribute.t()],
          deviations: [atom()],
          raw: map() | nil
        }

  @derive {Inspect, except: [:raw]}
  defstruct [
    :version,
    :mac_algorithm,
    :digest_algorithm,
    :content_type,
    :content,
    :pkcs7_content,
    :authenticated_attributes,
    :mac,
    recipient_infos: [],
    certificates: [],
    other_certificates: [],
    crls: [],
    other_crls: [],
    unauthenticated_attributes: [],
    deviations: [],
    raw: nil
  ]

  @doc false
  # Reads the AuthenticatedData inside a ContentInfo: version,
  # originatorInfo [0], recipientInfos, macAlgorithm, digestAlgorithm [1],
  # encapContentInfo, authAttrs [2], mac, unauthAttrs [3].
  @spec read(DER.element(), map()) :: {:ok, t()} | {:error, Error.t()}
  def read({0x30, _, _} = element, opts) do
    with {:ok, fields} <- fields(DER.children(element)),
         {:ok, version} <- Message.version(fields.version),
         {:ok, {mac_oid, _} = mac_alg} <- Algorithm.read(fields.mac_algorithm),
         {:ok, digest_alg} <- digest_algorithm(fields.digest_algorithm),
         {:ok, encap} <- Message.encap_content_info(fields.encap),
         {:ok, mac} <- DER.octets(fields.mac) do
      with {:ok, originator} <- Message.originator_info(fields.originator, opts),
           {:ok, recipient_infos} <- EnvelopedData.recipient_infos(fields.recipients, opts),
           {:ok, authenticated} <- Message.attributes(fields.authenticated, opts),
           {:ok, unauthenticated} <- Message.attributes(fields.unauthenticated, opts) do
        auth_data =
          struct!(
            %__MODULE__{
              version: version,
              recipient_infos: recipient_infos,
              mac_algorithm: OID.name(mac_oid),
              digest_algorithm: digest_alg && OID.name(elem(digest_alg, 0)),
              content_type: encap.content_type,
              content: encap.content,
              pkcs7_content: encap.pkcs7_content,
              authenticated_attributes: authenticated,
              mac: mac,
              unauthenticated_attributes: unauthenticated || [],
              raw: %{
                mac_algorithm: mac_alg,
                digest_algorithm: digest_alg,
                encap_content_info: encap.raw,
                authenticated_attributes: fields.authenticated && elem(fields.authenticated, 2),
                originator_info: fields.originator
              }
            },
            originator
          )

        {:ok, %{auth_data | deviations: deviations(auth_data)}}
      end
    else
      _ -> Message.malformed(:auth_data)
    end
  end

  def read(_element, _opts), do: Message.malformed(:auth_data)

  defp fields([version | rest]) do
    {originator, rest} = Message.optional(rest, 0xA0)

    with [{0x31, _, _} = recipients, mac_algorithm | rest] <- rest,
         {digest_algorithm, [encap | rest]} <- Message.optional(rest, 0xA1),
         {authenticated, [mac | rest]} <- Message.optional(rest, 0xA2),
         {unauthenticated, []} <- Message.optional(rest, 0xA3) do
      {:ok,
       %{
         version: version,
         originator: originator,
         recipients: recipients,
         mac_algorithm: mac_algorithm,
         digest_algorithm: digest_algorithm,
         encap: encap,
         authenticated: authenticated,
         mac: mac,
         unauthenticated: unauthenticated
       }}
    else
      _ -> :error
    end
  end

  defp fields(_fields), do: :error

  # digestAlgorithm [1] IMPLICIT DigestAlgorithmIdentifier: the tag in
  # place of the SEQUENCE.
  defp digest_algorithm(nil), do: {:ok, nil}

  defp digest_algorithm({0xA1, content, raw}),
    do: Algorithm.read({0x30, content, DER.retag(raw, 0x30)})

  defp deviations(auth_data) do
    if auth_data.version == expected_version(auth_data), do: [], else: [:auth_data_version]
  end

  @doc false
  # The version the fields call for (RFC 5652, 9.1).
  @spec expected_version(t()) :: 0 | 1 | 3
  def expected_version(%__MODULE__{} = auth_data) do
    case Message.originator_kind(auth_data) do
      :other -> 3
      :v2_attribute -> 1
      nil -> 0
    end
  end
end
