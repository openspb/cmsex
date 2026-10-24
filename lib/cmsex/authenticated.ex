defmodule Cmsex.Authenticated do
  @moduledoc """
  An AuthenticatedData message whose MAC `Cmsex.verify_mac/2` checked.

  Fields:

    * `:content` - the content the MAC covers, when the message carries
      it; `nil` for a detached message, whose content the caller gave.
    * `:content_type` - its type, as a name of `Cmsex.OID`, such as
      `:data`, or an OID. With authenticated attributes, the content-type
      attribute was checked against it.
    * `:recipient` - the `Cmsex.RecipientInfo` that gave the MAC key, or
      `nil` when it came in `:mac_key`.
    * `:message` - the `Cmsex.AuthenticatedData`, for the rest: the
      authenticated attributes, which the MAC covers, the unauthenticated
      ones, which it does not, and the originator certificates.

  A MAC tells that the content comes from someone who had the MAC key,
  and was not changed since. Who that is depends on the recipients: see
  `Cmsex.mac/3`.
  """

  alias Cmsex.{AuthenticatedData, RecipientInfo}

  @type t :: %__MODULE__{
          content: binary() | nil,
          content_type: atom() | tuple(),
          recipient: RecipientInfo.t() | nil,
          message: AuthenticatedData.t()
        }

  @enforce_keys [:content_type, :message]
  defstruct [:content, :content_type, :recipient, :message]
end
