defmodule Cmsex.Decrypted do
  @moduledoc """
  A message that `Cmsex.decrypt/2` decrypted.

  Fields:

    * `:content` - the content, decrypted.
    * `:content_type` - its type, as a name of `Cmsex.OID`, such as
      `:data`, or an OID. For AuthEnvelopedData, the content-type
      attribute, when present, was checked against it.
    * `:recipient` - the `Cmsex.RecipientInfo` that gave the
      content-encryption key, or `nil` when it came in `:content_key`.
    * `:message` - the message as `Cmsex.decode/2` reads it, a
      `Cmsex.EnvelopedData` or a `Cmsex.EncryptedData`, for the rest: the
      originator certificates, the unprotected attributes, and the
      authenticated attributes of an AuthEnvelopedData, which the tag
      covers.

  `Inspect` leaves the content out.
  """

  alias Cmsex.{EncryptedData, EnvelopedData, RecipientInfo}

  @type t :: %__MODULE__{
          content: binary(),
          content_type: atom() | tuple(),
          recipient: RecipientInfo.t() | nil,
          message: EnvelopedData.t() | EncryptedData.t()
        }

  @derive {Inspect, except: [:content]}
  @enforce_keys [:content, :content_type, :message]
  defstruct [:content, :content_type, :recipient, :message]
end
