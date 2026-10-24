defmodule Cmsex.DigestedData do
  @moduledoc """
  A DigestedData message, as `Cmsex.decode/2` reads it (RFC 5652, 7): a
  content and its digest, which shows it was not changed by accident, and
  nothing more: anyone can write a new digest. `Cmsex.verify_digest/2`
  checks it.

  Fields:

    * `:version` - the version written in the message.
    * `:digest_algorithm` - the name of the digest algorithm, such as
      `:sha256`, or its OID.
    * `:content_type` - the type of the content, as a name of `Cmsex.OID`
      or an OID.
    * `:content` - the content, or `nil` when it is not in the message.
      For a PKCS #7 message whose content is not an OCTET STRING, it is the
      content octets of that value, as in `Cmsex.SignedData`.
    * `:pkcs7_content` - for such a message, the whole encoding of the
      content; `nil` otherwise.
    * `:digest` - the digest.
    * `:deviations` - `:digested_data_version` when the version is not 0
      for `:data`, or 2 for another type.
  """

  alias Cmsex.{Algorithm, DER, Error, Message, OID}

  @type t :: %__MODULE__{
          version: integer(),
          digest_algorithm: atom() | tuple(),
          content_type: atom() | tuple(),
          content: binary() | nil,
          pkcs7_content: binary() | nil,
          digest: binary(),
          deviations: [atom()],
          raw: map() | nil
        }

  @derive {Inspect, except: [:raw]}
  defstruct [
    :version,
    :digest_algorithm,
    :content_type,
    :content,
    :pkcs7_content,
    :digest,
    deviations: [],
    raw: nil
  ]

  @doc false
  # Reads the DigestedData inside a ContentInfo: version, digestAlgorithm,
  # encapContentInfo, digest.
  @spec read(DER.element(), map()) :: {:ok, t()} | {:error, Error.t()}
  def read({0x30, _, _} = element, _opts) do
    with [version, alg, encap, digest] <- DER.children(element),
         {:ok, version} <- Message.version(version),
         {:ok, {oid, _} = alg} <- Algorithm.read(alg),
         {:ok, encap} <- Message.encap_content_info(encap),
         {:ok, digest} <- DER.octets(digest) do
      expected = if encap.content_type == :data, do: 0, else: 2

      {:ok,
       %__MODULE__{
         version: version,
         digest_algorithm: OID.name(oid),
         content_type: encap.content_type,
         content: encap.content,
         pkcs7_content: encap.pkcs7_content,
         digest: digest,
         deviations: if(version == expected, do: [], else: [:digested_data_version]),
         raw: %{digest_algorithm: alg, encap_content_info: encap.raw}
       }}
    else
      _ -> Message.malformed(:digested_data)
    end
  end

  def read(_element, _opts), do: Message.malformed(:digested_data)
end
