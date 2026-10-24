defmodule Cmsex.SignerInfo do
  @moduledoc """
  One signer of a SignedData message, as `Cmsex.decode/2` reads it
  (RFC 5652, 5.3). Reading checks the structure only; `Cmsex.verify/2`
  checks the signature.

  Fields:

    * `:version` - 1 with an issuer and serial number, 3 with a subject key
      identifier.
    * `:sid` - which certificate signed: `{:issuer_and_serial, issuer,
      serial}`, with the issuer as the DER of its Name as received, or
      `{:subject_key_identifier, ski}`.
    * `:digest_algorithm` - the name of the digest algorithm in
      `Cmsex.OID`, such as `:sha256`, or its OID.
    * `:signature_algorithm` - the name of the signature algorithm, such as
      `:rsa_encryption`, `:sha256_with_rsa_encryption`, `:rsassa_pss`,
      `:ecdsa_with_sha256` or `:ed25519`, or its OID.
    * `:signature_parameters` - for `:rsassa_pss`, a map with `:hash`,
      `:mgf_hash`, `:salt_length` and `:trailer_field`, the defaults filled
      in; `nil` otherwise.
    * `:signed_attributes` - a list of `Cmsex.Attribute`, in the order of
      the message, or `nil` when the signer has none.
    * `:unsigned_attributes` - a list of `Cmsex.Attribute`, empty when there
      are none. These are not covered by the signature: anyone can add,
      remove or change them.
    * `:signature` - the signature value. It is also what a signature
      time-stamp (RFC 3161, appendix A) and a countersignature cover.
    * `:deviations` - what the library tolerated when reading, against
      RFC 5652:
      * `:signer_info_version` - the version does not match the signer
        identifier;
      * `:signed_attributes_not_der` - the signed attributes are not in
        DER; the signature is checked over the bytes as received;
      * `:signing_time_encoding` - a signing time from 1950 to 2049 written
        as GeneralizedTime.
  """

  alias Cmsex.{Algorithm, Attribute, DER, Error, OID, Options}

  @type sid ::
          {:issuer_and_serial, binary(), integer()} | {:subject_key_identifier, binary()}

  @type t :: %__MODULE__{
          version: integer(),
          sid: sid(),
          digest_algorithm: atom() | tuple(),
          signature_algorithm: atom() | tuple(),
          signature_parameters: Algorithm.pss() | nil,
          signed_attributes: [Attribute.t()] | nil,
          unsigned_attributes: [Attribute.t()],
          signature: binary(),
          deviations: [atom()],
          raw: map() | nil
        }

  @derive {Inspect, except: [:raw]}
  defstruct [
    :version,
    :sid,
    :digest_algorithm,
    :signature_algorithm,
    :signature_parameters,
    :signed_attributes,
    :signature,
    unsigned_attributes: [],
    deviations: [],
    raw: nil
  ]

  @doc """
  The signature value of the signer. It is what a signature time-stamp
  covers (RFC 3161, appendix A): the time-stamp request hashes these
  bytes, and the token goes back in an unsigned attribute with
  `Cmsex.add_unsigned_attribute/4`. A countersignature covers it too
  (RFC 5652, 11.4).
  """
  @spec signature(t()) :: binary()
  def signature(%__MODULE__{signature: signature}), do: signature

  ## Attributes

  @doc """
  The content-type attribute: the type of the signed content, as a name of
  `Cmsex.OID` or an OID. `:error` when it is missing, repeated, or not a
  single OID.
  """
  @spec content_type(t()) :: {:ok, atom() | tuple()} | :error
  def content_type(signer_info), do: public(read_attribute(signer_info, :content_type))

  @doc """
  The message-digest attribute: the digest of the content. `:error` when it
  is missing, repeated, or not a single OCTET STRING.
  """
  @spec message_digest(t()) :: {:ok, binary()} | :error
  def message_digest(signer_info), do: public(read_attribute(signer_info, :message_digest))

  @doc """
  The signing-time attribute. It is what the signer claims, not a fact
  anyone checked. `:error` when it is missing, repeated or malformed.
  """
  @spec signing_time(t()) :: {:ok, DateTime.t()} | :error
  def signing_time(signer_info) do
    case read_attribute(signer_info, :signing_time) do
      {:ok, {time, _encoding}} -> {:ok, time}
      _ -> :error
    end
  end

  defp public({:ok, value}), do: {:ok, value}
  defp public({:error, _}), do: :error

  @doc """
  The first signed attribute of a type, a name of `Cmsex.OID` or an OID, or
  `nil`.
  """
  @spec attribute(t(), atom() | tuple()) :: Attribute.t() | nil
  def attribute(%__MODULE__{signed_attributes: attributes}, type),
    do: find(attributes || [], type)

  @doc """
  The first unsigned attribute of a type, such as `:time_stamp_token`, or
  `nil`. Unsigned attributes are not covered by the signature.
  """
  @spec unsigned_attribute(t(), atom() | tuple()) :: Attribute.t() | nil
  def unsigned_attribute(%__MODULE__{unsigned_attributes: attributes}, type),
    do: find(attributes, type)

  defp find(attributes, type) do
    type = OID.name(OID.oid(type))
    Enum.find(attributes, &(&1.type == type))
  end

  @doc """
  The countersignatures of this signer (RFC 5652, 11.4): each a SignerInfo
  over the signature of this one. They are read, not verified; see the
  `:countersignatures` option of `Cmsex.verify/2`. Takes the limits of
  `Cmsex.decode/2`.
  """
  @spec countersignatures(t(), keyword()) :: {:ok, [t()]} | {:error, Error.t()}
  def countersignatures(%__MODULE__{} = signer_info, opts \\ []) do
    opts = Options.take!(opts, Options.limits())
    read_countersignatures(signer_info, opts)
  end

  @doc false
  @spec read_countersignatures(t(), map()) :: {:ok, [t()]} | {:error, Error.t()}
  def read_countersignatures(%__MODULE__{unsigned_attributes: attributes}, opts) do
    values =
      for %Attribute{type: :countersignature, values: v} <- attributes, value <- v, do: value

    if length(values) > opts.max_signers,
      do: {:error, Error.new(:limit_exceeded, :max_signers)},
      else: read_countersignatures(values, 0, opts, [])
  end

  defp read_countersignatures([], _index, _opts, acc), do: {:ok, Enum.reverse(acc)}

  defp read_countersignatures([value | rest], index, opts, acc) do
    case read_countersignature(value, opts) do
      {:ok, signer_info} -> read_countersignatures(rest, index + 1, opts, [signer_info | acc])
      {:error, error} -> {:error, %{error | signer: [index]}}
    end
  end

  defp read_countersignature(value, opts) do
    case DER.decode(value, max_depth: opts.max_depth, max_elements: opts.max_elements) do
      {:ok, element} -> parse(element, opts)
      {:error, {:limit_exceeded, limit}} -> {:error, Error.new(:limit_exceeded, limit)}
      {:error, :malformed} -> {:error, Error.new(:malformed, :countersignature)}
    end
  end

  @doc false
  # The single value of a signed attribute that must appear once with one
  # value (RFC 5652, 11.1 to 11.3), decoded.
  @spec read_attribute(t(), :content_type | :message_digest | :signing_time) ::
          {:ok, term()} | {:error, :missing | :invalid}
  def read_attribute(%__MODULE__{signed_attributes: attributes}, type) do
    case for(%Attribute{type: ^type} = attribute <- attributes || [], do: attribute) do
      [] -> {:error, :missing}
      [%Attribute{values: [value]}] -> decode_value(type, value)
      _ -> {:error, :invalid}
    end
  end

  defp decode_value(type, value) do
    with {:ok, element} <- DER.decode(value),
         {:ok, decoded} <- value_of(type, element) do
      {:ok, decoded}
    else
      _ -> {:error, :invalid}
    end
  end

  defp value_of(:content_type, element) do
    with {:ok, oid} <- DER.oid(element), do: {:ok, OID.name(oid)}
  end

  defp value_of(:message_digest, element), do: DER.octets(element)

  defp value_of(:signing_time, element) do
    with {:ok, time, encoding} <- DER.time(element), do: {:ok, {time, encoding}}
  end

  ## Reading

  @doc false
  @spec parse(DER.element(), map()) :: {:ok, t()} | {:error, Error.t()}
  def parse({0x30, _, raw} = element, opts) do
    with {:ok, fields} <- fields(DER.children(element)),
         {:ok, version} <- DER.integer(fields.version),
         {:ok, sid} <- sid(fields.sid),
         {:ok, {digest_oid, _}} <- Algorithm.read(fields.digest),
         {:ok, {signature_oid, params}} <- Algorithm.read(fields.signature_algorithm),
         {:ok, signature} <- DER.octets(fields.signature) do
      with {:ok, signed} <- attributes(fields.signed, opts),
           {:ok, unsigned} <- attributes(fields.unsigned, opts) do
        signer_info = %__MODULE__{
          version: version,
          sid: sid,
          digest_algorithm: OID.name(digest_oid),
          signature_algorithm: OID.name(signature_oid),
          signature_parameters: pss(OID.name(signature_oid), params),
          signed_attributes: signed,
          unsigned_attributes: unsigned || [],
          signature: signature,
          raw: %{
            signer_info: raw,
            signed_attributes: fields.signed && elem(fields.signed, 2),
            digest_algorithm: fields.digest,
            signature_algorithm: fields.signature_algorithm,
            signed_part: fields.signed_part
          }
        }

        {:ok, %{signer_info | deviations: deviations(signer_info)}}
      end
    else
      _ -> {:error, Error.new(:malformed, :signer_info)}
    end
  end

  def parse(_element, _opts), do: {:error, Error.new(:malformed, :signer_info)}

  defp fields([version, sid, digest | rest]) do
    {signed, rest} = optional(rest, 0xA0)

    with [signature_algorithm, signature | rest] <- rest,
         {unsigned, []} <- optional(rest, 0xA1) do
      signed_part =
        for {_, _, raw} <- [version, sid, digest, signed, signature_algorithm, signature], do: raw

      {:ok,
       %{
         version: version,
         sid: sid,
         digest: digest,
         signed: signed,
         signature_algorithm: signature_algorithm,
         signature: signature,
         unsigned: unsigned,
         signed_part: signed_part
       }}
    else
      _ -> :error
    end
  end

  defp fields(_fields), do: :error

  defp optional([{id, _, _} = element | rest], id), do: {element, rest}
  defp optional(rest, _id), do: {nil, rest}

  defp sid({0x30, _, _} = element) do
    with [{0x30, _, issuer}, serial] <- DER.children(element),
         {:ok, serial} <- DER.integer(serial) do
      {:ok, {:issuer_and_serial, issuer, serial}}
    else
      _ -> :error
    end
  end

  defp sid({id, _, _} = element) when id in [0x80, 0xA0] do
    with {:ok, ski} <- DER.string(element, 0x80), do: {:ok, {:subject_key_identifier, ski}}
  end

  defp sid(_element), do: :error

  defp pss(:rsassa_pss, params) when params != nil do
    case Algorithm.pss_params(params) do
      {:ok, pss} -> pss
      _ -> nil
    end
  end

  defp pss(_name, _params), do: nil

  defp attributes(nil, _opts), do: {:ok, nil}

  defp attributes(element, opts) do
    children = DER.children(element)

    if length(children) > opts.max_attributes do
      {:error, Error.new(:limit_exceeded, :max_attributes)}
    else
      read_attributes(children, [])
    end
  end

  defp read_attributes([], acc), do: {:ok, Enum.reverse(acc)}

  defp read_attributes([element | rest], acc) do
    case Attribute.read(element) do
      {:ok, attribute} -> read_attributes(rest, [attribute | acc])
      :error -> {:error, Error.new(:malformed, :attribute)}
    end
  end

  defp deviations(%__MODULE__{} = signer_info) do
    [
      signer_info.version != expected_version(signer_info.sid) && :signer_info_version,
      signed_not_der?(signer_info.raw.signed_attributes) && :signed_attributes_not_der,
      generalized_signing_time?(signer_info) && :signing_time_encoding
    ]
    |> Enum.filter(& &1)
  end

  defp expected_version({:issuer_and_serial, _, _}), do: 1
  defp expected_version({:subject_key_identifier, _}), do: 3

  defp signed_not_der?(nil), do: false
  defp signed_not_der?(raw), do: not DER.der?(DER.retag(raw, 0x31))

  defp generalized_signing_time?(signer_info) do
    case read_attribute(signer_info, :signing_time) do
      {:ok, {time, :generalized_time}} -> time.year in 1950..2049
      _ -> false
    end
  end

  @doc false
  # What the signature covers when there are signed attributes: their bytes
  # as received, with the SET tag in place of [0] (RFC 5652, 5.4).
  @spec signed_attributes_tbs(t()) :: binary() | nil
  def signed_attributes_tbs(%__MODULE__{raw: %{signed_attributes: nil}}), do: nil
  def signed_attributes_tbs(%__MODULE__{raw: %{signed_attributes: raw}}), do: DER.retag(raw, 0x31)
end
