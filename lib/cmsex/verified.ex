defmodule Cmsex.Verified do
  @moduledoc """
  The result of `Cmsex.verify/2`.

  Fields:

    * `:content` - the content the signatures cover, when the message
      carries it; `nil` for a detached signature, whose content the caller
      gave.
    * `:content_type` - the type of the content, as signed.
    * `:signed_data` - the message, as `Cmsex.decode/2` reads it.
    * `:signers` - the signers that verified, in the order of the message.

  Each signer is a map:

    * `:index` - the position of the signer in the message, from 0.
    * `:certificate` - the certificate, in DER, whose key verified the
      signature. Without the `:trust` option nothing says who owns it: it
      may have come in the message itself.
    * `:signer_info` - the `Cmsex.SignerInfo`.
    * `:signing_time` - the signing-time attribute, or `nil`. It is what
      the signer claims, not a checked fact.
    * `:path` - with `:trust`, the validated certificate path, root first
      and this certificate last; `nil` otherwise.
    * `:deviations` - what was tolerated: those of the SignerInfo, and
      `:ed25519_digest` for an Ed25519 signer with a digest algorithm other
      than SHA-512.
    * `:countersignatures` - with `countersignatures: true`, the
      countersignatures of this signer, verified, each a map like this
      one; `[]` otherwise.

  Unsigned attributes, such as time-stamps and countersignatures, are not
  covered by the signature. Countersignatures are only verified with
  `countersignatures: true`.
  """

  @type signer :: %{
          index: non_neg_integer(),
          certificate: binary(),
          signer_info: Cmsex.SignerInfo.t(),
          signing_time: DateTime.t() | nil,
          path: [binary()] | nil,
          deviations: [atom()],
          countersignatures: [signer()]
        }

  @type t :: %__MODULE__{
          content: binary() | nil,
          content_type: atom() | tuple(),
          signed_data: Cmsex.SignedData.t(),
          signers: [signer()]
        }

  @enforce_keys [:content_type, :signed_data]
  defstruct [:content, :content_type, :signed_data, signers: []]
end
