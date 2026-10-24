defmodule Cmsex.Attribute do
  @moduledoc """
  A signed or unsigned attribute of a signer (RFC 5652, 5.3): a type and its
  values.

  `type` is a name of `Cmsex.OID`, such as `:signing_time`, or the OID as a
  tuple when the library does not know it. Each value is one encoded
  AttributeValue: as received, in an attribute read from a message, or in
  DER, in one built here.

  The constructors build the attributes a signer may add; `new/2` builds
  any other one from its encoded values. The content-type and
  message-digest attributes are always written by `Cmsex.sign/3` itself.

      iex> attr = Cmsex.Attribute.signing_time(~U[2026-10-23 12:00:00Z])
      iex> attr.type
      :signing_time
      iex> attr.values
      [<<0x17, 13, "261023120000Z">>]
  """

  alias Cmsex.{Algorithm, Certificate, DER, Digest, OID}

  @type t :: %__MODULE__{type: atom() | tuple(), values: [binary()]}

  @enforce_keys [:type, :values]
  defstruct [:type, :values]

  @doc """
  An attribute of `type`, a name of `Cmsex.OID` or an OID tuple, with
  `values`, each the encoding of one AttributeValue.

      iex> Cmsex.Attribute.new({1, 2, 3, 4}, [<<0x0C, 2, "hi">>])
      %Cmsex.Attribute{type: {1, 2, 3, 4}, values: [<<0x0C, 2, "hi">>]}
  """
  @spec new(atom() | tuple(), [binary(), ...]) :: t()
  def new(type, [_ | _] = values) do
    oid = OID.oid(type)
    _ = OID.encode(oid)

    for value <- values, not (is_binary(value) and match?({:ok, _}, DER.decode(value))) do
      raise ArgumentError,
            "an attribute value must be one encoded element, got: #{inspect(value)}"
    end

    %__MODULE__{type: OID.name(oid), values: values}
  end

  def new(_type, values),
    do: raise(ArgumentError, "an attribute needs a list of values, got: #{inspect(values)}")

  @doc """
  The signing-time attribute (RFC 5652, 11.3), to the second: UTCTime from
  1950 to 2049, GeneralizedTime outside that range.
  """
  @spec signing_time(DateTime.t()) :: %__MODULE__{type: :signing_time, values: [binary(), ...]}
  def signing_time(%DateTime{} = time) do
    time = time |> DateTime.shift_zone!("Etc/UTC") |> DateTime.truncate(:second)
    %__MODULE__{type: :signing_time, values: [DER.encode({:time, time})]}
  end

  @doc """
  The content-hints attribute (RFC 2634, 2.9): the type of the innermost
  content, when the signed content is itself a CMS message, and an
  optional description.
  """
  @spec content_hint(atom() | tuple(), String.t() | nil) ::
          %__MODULE__{type: :content_hint, values: [binary(), ...]}
  def content_hint(content_type, description \\ nil) do
    description = if description, do: [{:utf8, description}], else: []
    value = DER.encode({:seq, description ++ [{:oid, content_type}]})
    %__MODULE__{type: :content_hint, values: [value]}
  end

  @doc """
  The content-type attribute (RFC 5652, 11.1). `Cmsex.sign/3` writes it
  itself; this is for code that builds a SignerInfo some other way.
  """
  @spec content_type(atom() | tuple()) ::
          %__MODULE__{type: :content_type, values: [binary(), ...]}
  def content_type(content_type),
    do: %__MODULE__{type: :content_type, values: [DER.encode({:oid, content_type})]}

  @doc """
  The signing-certificate-v2 attribute (RFC 5035), which binds the signature
  to the certificate of the signer, `certificate` in DER: an ESSCertIDv2
  with its hash and, unless `issuer_serial: false`, its issuer and serial
  number.

  Options: `:hash`, `:sha256` (the default, which the encoding leaves out),
  `:sha224`, `:sha384` or `:sha512`; `:issuer_serial` (true).

  `Cmsex.verify/2` checks it, and the older signing-certificate attribute
  (RFC 2634, 5.4), against the certificate that verified the signature.
  """
  @spec signing_certificate_v2(binary(), keyword()) ::
          %__MODULE__{type: :signing_certificate_v2, values: [binary(), ...]}
  def signing_certificate_v2(certificate, opts \\ []) when is_binary(certificate) do
    {hash, issuer_serial?} = ess_options!(opts)

    cert =
      case Certificate.parse(certificate) do
        {:ok, cert} -> cert
        :error -> raise ArgumentError, "not a certificate in DER"
      end

    algorithm = if hash == :sha256, do: [], else: [Algorithm.digest_identifier(hash)]

    issuer_serial =
      if issuer_serial?,
        do: [{:seq, [{:seq, [{:explicit, 4, {:raw, cert.issuer}}]}, {:int, cert.serial}]}],
        else: []

    id = {:seq, algorithm ++ [{:octets, Digest.hash(hash, cert.der)}] ++ issuer_serial}
    %__MODULE__{type: :signing_certificate_v2, values: [DER.encode({:seq, [{:seq, [id]}]})]}
  end

  defp ess_options!(opts) do
    known? = Keyword.keyword?(opts) and Enum.all?(opts, &(elem(&1, 0) in [:hash, :issuer_serial]))

    unless known?,
      do:
        raise(
          ArgumentError,
          "expected the options :hash and :issuer_serial, got: #{inspect(opts)}"
        )

    Cmsex.Options.unique!(opts)

    hash = Keyword.get(opts, :hash, :sha256)
    issuer_serial? = Keyword.get(opts, :issuer_serial, true)

    unless hash in [:sha224, :sha256, :sha384, :sha512],
      do:
        raise(
          ArgumentError,
          ":hash must be :sha224, :sha256, :sha384 or :sha512, got: #{inspect(hash)}"
        )

    unless is_boolean(issuer_serial?),
      do:
        raise(ArgumentError, ":issuer_serial must be a boolean, got: #{inspect(issuer_serial?)}")

    {hash, issuer_serial?}
  end

  @doc false
  # Reads an Attribute: a type and a SET OF values, kept as received.
  @spec read(DER.element()) :: {:ok, t()} | :error
  def read({0x30, _, _} = element) do
    with [oid, {0x31, _, _} = set] <- DER.children(element),
         {:ok, oid} <- DER.oid(oid) do
      {:ok, %__MODULE__{type: OID.name(oid), values: Enum.map(DER.children(set), &elem(&1, 2))}}
    else
      _ -> :error
    end
  end

  def read(_element), do: :error

  @doc false
  @spec to_term(t()) :: DER.term_()
  def to_term(%__MODULE__{type: type, values: values}),
    do: {:seq, [{:oid, type}, {:set, Enum.map(values, &{:raw, &1})}]}
end
