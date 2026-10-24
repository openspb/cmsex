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

  alias Cmsex.{Algorithm, DER, Error, Message, OID, SignerInfo}

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
    case Message.parse(der, opts, [:signed_data]) do
      {:ok, %__MODULE__{} = signed_data} -> {:ok, signed_data}
      {:error, _} = error -> error
    end
  end

  @doc false
  # Reads the SignedData inside a ContentInfo.
  @spec read(DER.element(), map()) :: {:ok, t()} | {:error, Error.t()}
  def read({0x30, _, _} = element, opts) do
    with [version, {0x31, _, _} = digests, {0x30, _, _} = encap | rest] <- DER.children(element),
         {:ok, version} <- DER.integer(version),
         {:ok, certificates, crls, {0x31, _, _} = signers} <- optional_fields(rest),
         {:ok, digest_algorithms} <- digest_algorithms(digests),
         {:ok, encap} <- Message.encap_content_info(encap) do
      with {:ok, certs} <- Message.certificates(certificates, crls, opts),
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
            Map.merge(Map.delete(encap, :raw), certs)
          )

        {:ok, %{signed_data | deviations: deviations(signed_data)}}
      end
    else
      _ -> Message.malformed(:signed_data)
    end
  end

  def read(_element, _opts), do: Message.malformed(:signed_data)

  defp optional_fields(fields) do
    {certificates, rest} = Message.optional(fields, 0xA0)
    {crls, rest} = Message.optional(rest, 0xA1)

    case rest do
      [signers] -> {:ok, certificates, crls, signers}
      _ -> :error
    end
  end

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
      Message.originator_kind(signed_data) == :other -> 5
      0xA2 in tags -> 4
      0xA1 in tags or signed_data.content_type != :data -> 3
      Enum.any?(signed_data.signer_infos, &(&1.version == 3)) -> 3
      true -> 1
    end
  end
end
