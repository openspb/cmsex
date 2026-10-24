defmodule Cmsex.EncryptedData do
  @moduledoc """
  An EncryptedData message, as `Cmsex.decode/2` reads it (RFC 5652, 8):
  content encrypted with a key the parties manage by other means, with no
  recipients. `Cmsex.decrypt/2` with `:content_key` decrypts it.

  Fields:

    * `:version` - the version written in the message.
    * `:content_type` - the type of the encrypted content, as a name of
      `Cmsex.OID` or an OID.
    * `:content_encryption_algorithm` - the name of the cipher in
      `Cmsex.OID`, such as `:aes256_cbc`, or its OID.
    * `:encrypted_content` - the ciphertext, or `nil` when it is not in the
      message.
    * `:unprotected_attributes` - attributes that nothing protects, empty
      when there are none.
    * `:deviations` - `:encrypted_data_version` when the version is not 0
      without unprotected attributes, or 2 with them.
  """

  alias Cmsex.{Attribute, DER, Error, Message, OID}

  @type t :: %__MODULE__{
          version: integer(),
          content_type: atom() | tuple(),
          content_encryption_algorithm: atom() | tuple(),
          encrypted_content: binary() | nil,
          unprotected_attributes: [Attribute.t()],
          deviations: [atom()],
          raw: map() | nil
        }

  @derive {Inspect, except: [:raw]}
  defstruct [
    :version,
    :content_type,
    :content_encryption_algorithm,
    :encrypted_content,
    unprotected_attributes: [],
    deviations: [],
    raw: nil
  ]

  @doc false
  # Reads the EncryptedData inside a ContentInfo: version,
  # encryptedContentInfo, unprotectedAttrs [1] IMPLICIT OPTIONAL.
  @spec read(DER.element(), map()) :: {:ok, t()} | {:error, Error.t()}
  def read({0x30, _, _} = element, opts) do
    with [version, info | rest] <- DER.children(element),
         {unprotected, []} <- Message.optional(rest, 0xA1),
         {:ok, version} <- Message.version(version),
         {:ok, info} <- Message.encrypted_content_info(info) do
      {oid, _} = info.algorithm
      expected = if unprotected, do: 2, else: 0

      with {:ok, attributes} <- Message.attributes(unprotected, opts) do
        {:ok,
         %__MODULE__{
           version: version,
           content_type: info.content_type,
           content_encryption_algorithm: OID.name(oid),
           encrypted_content: info.content,
           unprotected_attributes: attributes || [],
           deviations: if(version == expected, do: [], else: [:encrypted_data_version]),
           raw: %{content_encryption_algorithm: info.algorithm}
         }}
      end
    else
      _ -> Message.malformed(:encrypted_data)
    end
  end

  def read(_element, _opts), do: Message.malformed(:encrypted_data)
end
