defmodule Cmsex.Error do
  @moduledoc """
  Why a CMS message could not be read, verified, written or decrypted.

  The functions of `Cmsex` return it as `{:error, %Cmsex.Error{}}`, and their
  bang variants raise it. Match on `:reason`; `:signer` is the position of
  the signer in the message (from 0) when the error belongs to one signer,
  or a list of positions for a countersignature (`[0, 1]` is the second
  countersignature of the first signer); `:recipient` is the position of
  the recipient in the list given to `Cmsex.encrypt/3` when the error
  belongs to one; `:detail` adds what went wrong where that helps, such as
  the OID of an unknown algorithm in dotted form.

  Reading:

    * `:malformed` - not valid BER, or not the structure that was expected.
    * `:invalid_pem` - no PEM block with a label this library reads, or
      invalid Base64.
    * `:unsupported_content_type` - a ContentInfo of a type the function
      does not handle; `detail` is its OID.
    * `:limit_exceeded` - the message goes beyond a limit; `detail` is the
      option, such as `:max_depth` or `:max_signers`.

  Content:

    * `:no_signers` - the message has no signers (a certificate bundle).
    * `:content_required` - a detached message, or one that needs the whole
      content, was given without it.
    * `:unexpected_content` - content given for a message that carries its
      own.

  Signers and algorithms:

    * `:signer_not_found` - no certificate matches the signer identifier.
    * `:unsupported_algorithm` - an algorithm this library does not
      implement; `detail` is its OID.
    * `:weak_algorithm` - SHA-1 without `allow_sha1: true`, or MD5.
    * `:weak_key` - an RSA key shorter than `:min_rsa_bits`.
    * `:algorithm_mismatch` - the algorithms of a signer do not agree with
      each other or with the CMSAlgorithmProtection attribute.
    * `:key_mismatch` - the key of the certificate is not of the kind the
      algorithm needs.

  Attributes and signatures:

    * `:missing_attribute` - a required attribute is missing; `detail` is
      which.
    * `:invalid_attribute` - a malformed or repeated attribute, or one with
      the wrong number of values; `detail` is which.
    * `:content_type_mismatch` - the content-type attribute is not the type
      of the content.
    * `:digest_mismatch` - the message-digest attribute, or the digest of
      a DigestedData, is not the digest of the content.
    * `:invalid_signature` - the signature does not verify.
    * `:signing_certificate_mismatch` - the signing-certificate attribute
      names another certificate.
    * `:untrusted` - the certificate path did not validate; `detail` is the
      reason given by `:public_key`.

  Writing:

    * `:invalid_key` - the private key cannot be read.
    * `:invalid_certificate` - a certificate cannot be read.
    * `:key_certificate_mismatch` - the private key is not the key of the
      certificate.
    * `:signer_failed` - the signing function returned an error, or a
      signature that does not verify.
    * `:invalid_recipient` - a recipient cannot be used for encryption;
      `detail` says why.

  Decrypting and MACs:

    * `:recipient_not_found` - no recipient of the message matches the
      credentials that were given.
    * `:decryption_failed` - the message does not decrypt with that key, or
      it was changed. The library gives no other detail, on purpose.
    * `:not_available` - the algorithm is known, but the `:crypto`
      application of this system (its OpenSSL) refuses it, such as RC2
      without the OpenSSL "legacy" provider; `detail` is the algorithm.
    * `:invalid_mac` - the MAC of an AuthenticatedData does not check
      with the key of the recipient, or the key does not unwrap. As with
      `:decryption_failed`, nothing tells these apart.

  An error never carries key material, passwords or the content.
  """

  @type reason ::
          :malformed
          | :invalid_pem
          | :unsupported_content_type
          | :limit_exceeded
          | :no_signers
          | :content_required
          | :unexpected_content
          | :signer_not_found
          | :unsupported_algorithm
          | :weak_algorithm
          | :weak_key
          | :algorithm_mismatch
          | :key_mismatch
          | :missing_attribute
          | :invalid_attribute
          | :content_type_mismatch
          | :digest_mismatch
          | :invalid_signature
          | :signing_certificate_mismatch
          | :untrusted
          | :invalid_key
          | :invalid_certificate
          | :key_certificate_mismatch
          | :signer_failed
          | :invalid_recipient
          | :recipient_not_found
          | :decryption_failed
          | :not_available
          | :invalid_mac

  @type t :: %__MODULE__{
          reason: reason(),
          signer: non_neg_integer() | [non_neg_integer()] | nil,
          recipient: non_neg_integer() | nil,
          detail: term()
        }

  defexception [:reason, :signer, :recipient, :detail]

  @doc false
  @spec new(reason(), term()) :: t()
  def new(reason, detail \\ nil), do: %__MODULE__{reason: reason, detail: detail}

  @impl true
  def message(%__MODULE__{reason: reason, detail: detail} = error) do
    prefix(error) <> describe(reason, detail)
  end

  defp prefix(%__MODULE__{recipient: index}) when is_integer(index), do: "recipient #{index}: "
  defp prefix(%__MODULE__{signer: signer}), do: prefix(signer)
  defp prefix(nil), do: ""
  defp prefix(index) when is_integer(index), do: "signer #{index}: "
  defp prefix([first | rest]), do: "countersignature #{Enum.join(rest, ".")} of signer #{first}: "

  defp describe(:malformed, nil), do: "not a valid CMS message"
  defp describe(:malformed, detail), do: "not a valid CMS message (#{show(detail)})"
  defp describe(:invalid_pem, _), do: "no PEM block with a CMS or PKCS7 label"

  defp describe(:unsupported_content_type, oid),
    do: "unsupported content type #{show(oid)}"

  defp describe(:limit_exceeded, option),
    do: "the message goes beyond the #{show(option)} limit"

  defp describe(:no_signers, _), do: "the message has no signers"

  defp describe(:content_required, _),
    do: "the content is required: the message is detached, or needs the whole content"

  defp describe(:unexpected_content, _),
    do: "content was given, but the message carries its own"

  defp describe(:signer_not_found, _), do: "no certificate matches the signer identifier"
  defp describe(:unsupported_algorithm, oid), do: "unsupported algorithm #{show(oid)}"
  defp describe(:weak_algorithm, alg), do: "weak algorithm #{show(alg)}"
  defp describe(:weak_key, bits), do: "weak key (#{show(bits)} bits)"

  defp describe(:algorithm_mismatch, detail),
    do: "the algorithms do not agree (#{show(detail)})"

  defp describe(:key_mismatch, _),
    do: "the key of the certificate does not fit the signature algorithm"

  defp describe(:missing_attribute, attr), do: "missing attribute #{show(attr)}"
  defp describe(:invalid_attribute, attr), do: "invalid attribute #{show(attr)}"

  defp describe(:content_type_mismatch, _),
    do: "the content-type attribute does not match the content"

  defp describe(:digest_mismatch, _),
    do: "the digest does not match the content"

  defp describe(:invalid_signature, _), do: "invalid signature"

  defp describe(:signing_certificate_mismatch, _),
    do: "the signing-certificate attribute names another certificate"

  defp describe(:untrusted, detail), do: "untrusted certificate (#{show(detail)})"
  defp describe(:invalid_key, _), do: "the private key cannot be read"
  defp describe(:invalid_certificate, _), do: "the certificate cannot be read"

  defp describe(:key_certificate_mismatch, _),
    do: "the key is not the key of the certificate"

  defp describe(:signer_failed, _),
    do: "the signing function failed or returned an invalid signature"

  defp describe(:invalid_recipient, detail), do: "invalid recipient (#{show(detail)})"

  defp describe(:recipient_not_found, _),
    do: "no recipient of the message matches the credentials that were given"

  defp describe(:decryption_failed, _), do: "decryption failed"
  defp describe(:invalid_mac, _), do: "invalid MAC"

  defp describe(:not_available, alg),
    do: "#{show(alg)} is not available in the :crypto application of this system"

  defp describe(other, detail), do: "CMS error: #{inspect(other)} #{show(detail)}"

  defp show(nil), do: "unknown"
  defp show(value) when is_binary(value), do: value
  defp show(value) when is_atom(value), do: inspect(value)
  defp show(value) when is_integer(value), do: Integer.to_string(value)

  defp show(value) when is_tuple(value) do
    parts = Tuple.to_list(value)
    if Enum.all?(parts, &is_integer/1), do: Enum.join(parts, "."), else: inspect(value)
  end

  defp show(value), do: inspect(value)
end
