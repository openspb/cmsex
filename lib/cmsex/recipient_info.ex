defmodule Cmsex.RecipientInfo do
  @moduledoc """
  One recipient of an EnvelopedData, AuthEnvelopedData or AuthenticatedData
  message, as `Cmsex.decode/2` reads it (RFC 5652, 6.2): the means by which
  that recipient gets the content-encryption key.

  Fields:

    * `:type` - which kind of RecipientInfo:
      * `:key_transport` - the key encrypted to the public key of a
        certificate, with RSA (KeyTransRecipientInfo);
      * `:key_agreement` - a key wrapped with one agreed with ECDH or X25519
        and X448 (KeyAgreeRecipientInfo), for one or more recipients;
      * `:kek` - the key wrapped with a symmetric key the parties share
        (KEKRecipientInfo);
      * `:password` - the key wrapped with one derived from a password
        (PasswordRecipientInfo);
      * `:other` - an OtherRecipientInfo, which this library does not
        decrypt.
    * `:version` - the version written in the message; `nil` for `:other`.
    * `:rid` - which key the recipient holds: for `:key_transport`,
      `{:issuer_and_serial, issuer, serial}`, with the issuer as the DER of
      its Name as received, or `{:subject_key_identifier, ski}`; for `:kek`,
      `{:kek, key_identifier}`; `nil` for the others.
    * `:key_encryption_algorithm` - the name of the key-encryption
      algorithm in `Cmsex.OID`, or its OID: `:rsaes_oaep` or
      `:rsa_encryption`; a key agreement scheme, such as
      `:std_dh_sha256kdf`; a key wrap, such as `:aes256_wrap`; or
      `:pwri_kek`.
    * `:encrypted_key` - the encrypted key; `nil` for `:key_agreement`,
      which has one per recipient, and for `:other`.
    * `:originator` - for `:key_agreement`, the key of the sender:
      `{:public_key, algorithm, key}`, with the algorithm as a name such as
      `:ec_public_key` or `:x25519` and the key as the bytes of the public
      key (an EC point, or the raw X25519 or X448 key), or a certificate,
      as `{:issuer_and_serial, issuer, serial}` or
      `{:subject_key_identifier, ski}`.
    * `:ukm` - for `:key_agreement`, the user keying material, or `nil`.
    * `:key_wrap_algorithm` - for `:key_agreement`, the key wrap the
      scheme uses, such as `:aes128_wrap`, or `nil` when the parameters do
      not name one.
    * `:recipient_encrypted_keys` - for `:key_agreement`, a list of
      `{rid, encrypted_key}`, with `rid` as `:rid` above. The date and the
      other attribute of a RecipientKeyIdentifier are not read.
    * `:date` - for `:kek`, the date of the KEKIdentifier, or `nil`.
    * `:key_derivation_algorithm` - for `:password`, the name of the key
      derivation algorithm, such as `:pbkdf2`, or `nil` when absent.
    * `:other_type` - for `:other`, the oriType.
    * `:deviations` - what the library tolerated when reading, against
      RFC 5652: `:recipient_info_version` when the version is not the one
      the type and the identifier call for.
  """

  alias Cmsex.{Algorithm, DER, Error, Message, OID}

  @type rid ::
          {:issuer_and_serial, binary(), integer()}
          | {:subject_key_identifier, binary()}
          | {:kek, binary()}

  @type originator ::
          {:public_key, atom() | tuple(), binary()}
          | {:issuer_and_serial, binary(), integer()}
          | {:subject_key_identifier, binary()}

  @type t :: %__MODULE__{
          type: :key_transport | :key_agreement | :kek | :password | :other,
          version: non_neg_integer() | nil,
          rid: rid() | nil,
          key_encryption_algorithm: atom() | tuple() | nil,
          encrypted_key: binary() | nil,
          originator: originator() | nil,
          ukm: binary() | nil,
          key_wrap_algorithm: atom() | tuple() | nil,
          recipient_encrypted_keys: [{rid(), binary()}],
          date: DateTime.t() | nil,
          key_derivation_algorithm: atom() | tuple() | nil,
          other_type: atom() | tuple() | nil,
          deviations: [atom()],
          raw: map() | nil
        }

  @derive {Inspect, except: [:raw]}
  defstruct [
    :type,
    :version,
    :rid,
    :key_encryption_algorithm,
    :encrypted_key,
    :originator,
    :ukm,
    :key_wrap_algorithm,
    :date,
    :key_derivation_algorithm,
    :other_type,
    recipient_encrypted_keys: [],
    deviations: [],
    raw: nil
  ]

  @doc false
  # Reads a RecipientInfo (RFC 5652, 6.2): ktri is a SEQUENCE, the others
  # carry an implicit tag in place of theirs.
  @spec parse(DER.element(), map()) :: {:ok, t()} | {:error, Error.t()}
  def parse({id, _, raw} = element, opts) do
    case read(id, DER.children(element), opts) do
      {:ok, info} ->
        info = %{info | raw: Map.put(info.raw, :recipient_info, raw)}
        {:ok, %{info | deviations: deviations(info)}}

      {:error, %Error{}} = error ->
        error

      :error ->
        {:error, Error.new(:malformed, :recipient_info)}
    end
  end

  defp read(0x30, fields, _opts), do: key_transport(fields)
  defp read(0xA1, fields, opts), do: key_agreement(fields, opts)
  defp read(0xA2, fields, _opts), do: kek(fields)
  defp read(0xA3, fields, _opts), do: password(fields)
  defp read(0xA4, fields, _opts), do: other(fields)
  defp read(_id, _fields, _opts), do: :error

  # KeyTransRecipientInfo (RFC 5652, 6.2.1).
  defp key_transport([version, rid, alg, encrypted_key]) do
    with {:ok, version} <- Message.version(version),
         {:ok, rid} <- rid(rid),
         {:ok, {oid, _} = alg} <- Algorithm.read(alg),
         {:ok, encrypted_key} <- DER.octets(encrypted_key) do
      {:ok,
       %__MODULE__{
         type: :key_transport,
         version: version,
         rid: rid,
         key_encryption_algorithm: OID.name(oid),
         encrypted_key: encrypted_key,
         raw: %{key_encryption_algorithm: alg}
       }}
    end
  end

  defp key_transport(_fields), do: :error

  # KeyAgreeRecipientInfo (RFC 5652, 6.2.2).
  defp key_agreement([version, {0xA0, _, _} = originator | rest], opts) do
    {ukm, rest} = Message.optional(rest, 0xA1)

    with [alg, {0x30, _, _} = keys] <- rest,
         {:ok, version} <- Message.version(version),
         {:ok, originator, originator_key} <- originator(originator),
         {:ok, ukm} <- ukm(ukm),
         {:ok, {oid, params} = alg} <- Algorithm.read(alg),
         {:ok, encrypted_keys} <- recipient_encrypted_keys(keys, opts) do
      {:ok,
       %__MODULE__{
         type: :key_agreement,
         version: version,
         key_encryption_algorithm: OID.name(oid),
         originator: originator,
         ukm: ukm,
         key_wrap_algorithm: key_wrap(params),
         recipient_encrypted_keys: encrypted_keys,
         raw: %{key_encryption_algorithm: alg, originator_key: originator_key}
       }}
    else
      {:error, %Error{}} = error -> error
      _ -> :error
    end
  end

  defp key_agreement(_fields, _opts), do: :error

  # OriginatorIdentifierOrKey, inside [0] EXPLICIT.
  defp originator(explicit) do
    case DER.children(explicit) do
      [{0xA1, _, _} = key] ->
        with [alg, bits] <- DER.children(key),
             {:ok, {oid, _} = alg} <- Algorithm.read(alg),
             {:ok, public_key} <- DER.bit_string(bits) do
          {:ok, {:public_key, OID.name(oid), public_key}, alg}
        else
          _ -> :error
        end

      [identifier] ->
        with {:ok, identifier} <- rid(identifier), do: {:ok, identifier, nil}

      _ ->
        :error
    end
  end

  defp ukm(nil), do: {:ok, nil}

  defp ukm(explicit) do
    case DER.children(explicit) do
      [octets] -> DER.octets(octets)
      _ -> :error
    end
  end

  # The parameters of a key agreement scheme are the key wrap algorithm
  # (RFC 5753, 3.1.1; RFC 8418, 2).
  defp key_wrap({0x30, _, _} = params) do
    case Algorithm.read(params) do
      {:ok, {oid, _}} -> OID.name(oid)
      :error -> nil
    end
  end

  defp key_wrap(_params), do: nil

  defp recipient_encrypted_keys(keys, opts) do
    children = DER.children(keys)

    cond do
      children == [] ->
        :error

      length(children) > opts.max_recipients ->
        {:error, Error.new(:limit_exceeded, :max_recipients)}

      true ->
        read_encrypted_keys(children, [])
    end
  end

  defp read_encrypted_keys([], acc), do: {:ok, Enum.reverse(acc)}

  defp read_encrypted_keys([element | rest], acc) do
    with {:ok, pair} <- recipient_encrypted_key(element) do
      read_encrypted_keys(rest, [pair | acc])
    end
  end

  defp recipient_encrypted_key({0x30, _, _} = element) do
    with [rid, encrypted_key] <- DER.children(element),
         {:ok, rid} <- key_agree_rid(rid),
         {:ok, encrypted_key} <- DER.octets(encrypted_key) do
      {:ok, {rid, encrypted_key}}
    else
      _ -> :error
    end
  end

  defp recipient_encrypted_key(_element), do: :error

  # KeyAgreeRecipientIdentifier: issuerAndSerialNumber, or rKeyId [0]
  # IMPLICIT RecipientKeyIdentifier.
  defp key_agree_rid({0xA0, _, _} = element) do
    with [ski | rest] when length(rest) <= 2 <- DER.children(element),
         {:ok, ski} <- DER.octets(ski) do
      {:ok, {:subject_key_identifier, ski}}
    else
      _ -> :error
    end
  end

  defp key_agree_rid(element), do: rid(element)

  # KEKRecipientInfo (RFC 5652, 6.2.3).
  defp kek([version, {0x30, _, _} = kekid, alg, encrypted_key]) do
    with {:ok, version} <- Message.version(version),
         {:ok, key_identifier, date} <- kek_identifier(DER.children(kekid)),
         {:ok, {oid, _} = alg} <- Algorithm.read(alg),
         {:ok, encrypted_key} <- DER.octets(encrypted_key) do
      {:ok,
       %__MODULE__{
         type: :kek,
         version: version,
         rid: {:kek, key_identifier},
         key_encryption_algorithm: OID.name(oid),
         encrypted_key: encrypted_key,
         date: date,
         raw: %{key_encryption_algorithm: alg}
       }}
    end
  end

  defp kek(_fields), do: :error

  # KEKIdentifier: keyIdentifier, date GeneralizedTime OPTIONAL, other
  # OtherKeyAttribute OPTIONAL.
  defp kek_identifier([identifier | rest]) do
    {date, rest} = Message.optional(rest, 0x18)

    with {:ok, identifier} <- DER.octets(identifier),
         {:ok, date} <- date(date),
         true <- rest == [] or match?([{0x30, _, _}], rest) do
      {:ok, identifier, date}
    else
      _ -> :error
    end
  end

  defp kek_identifier(_fields), do: :error

  defp date(nil), do: {:ok, nil}

  defp date(element) do
    case DER.time(element) do
      {:ok, time, _encoding} -> {:ok, time}
      :error -> :error
    end
  end

  # PasswordRecipientInfo (RFC 3211, 2.2; RFC 5652, 6.2.4).
  defp password([version | rest]) do
    {derivation, rest} = Message.optional(rest, 0xA0)

    with [alg, encrypted_key] <- rest,
         {:ok, version} <- Message.version(version),
         {:ok, derivation} <- key_derivation(derivation),
         {:ok, {oid, _} = alg} <- Algorithm.read(alg),
         {:ok, encrypted_key} <- DER.octets(encrypted_key) do
      {:ok,
       %__MODULE__{
         type: :password,
         version: version,
         key_encryption_algorithm: OID.name(oid),
         encrypted_key: encrypted_key,
         key_derivation_algorithm: derivation && OID.name(elem(derivation, 0)),
         raw: %{key_encryption_algorithm: alg, key_derivation_algorithm: derivation}
       }}
    else
      _ -> :error
    end
  end

  defp password(_fields), do: :error

  # keyDerivationAlgorithm [0] IMPLICIT AlgorithmIdentifier: the tag in
  # place of the SEQUENCE.
  defp key_derivation(nil), do: {:ok, nil}

  defp key_derivation({0xA0, content, raw}),
    do: Algorithm.read({0x30, content, DER.retag(raw, 0x30)})

  # OtherRecipientInfo (RFC 5652, 6.2.5).
  defp other([type, _value]) do
    case DER.oid(type) do
      {:ok, oid} -> {:ok, %__MODULE__{type: :other, other_type: OID.name(oid), raw: %{}}}
      :error -> :error
    end
  end

  defp other(_fields), do: :error

  # RecipientIdentifier: issuerAndSerialNumber, or subjectKeyIdentifier
  # [0] IMPLICIT.
  defp rid({0x30, _, _} = element) do
    with [{0x30, _, issuer}, serial] <- DER.children(element),
         {:ok, serial} <- DER.integer(serial) do
      {:ok, {:issuer_and_serial, issuer, serial}}
    else
      _ -> :error
    end
  end

  defp rid({id, _, _} = element) when id in [0x80, 0xA0] do
    with {:ok, ski} <- DER.string(element, 0x80), do: {:ok, {:subject_key_identifier, ski}}
  end

  defp rid(_element), do: :error

  defp deviations(%__MODULE__{type: :other}), do: []

  defp deviations(info) do
    if info.version == expected_version(info), do: [], else: [:recipient_info_version]
  end

  @doc false
  # The version the type and the identifier call for (RFC 5652, 6.2).
  @spec expected_version(t()) :: non_neg_integer() | nil
  def expected_version(%__MODULE__{type: :key_transport, rid: {:issuer_and_serial, _, _}}), do: 0
  def expected_version(%__MODULE__{type: :key_transport}), do: 2
  def expected_version(%__MODULE__{type: :key_agreement}), do: 3
  def expected_version(%__MODULE__{type: :kek}), do: 4
  def expected_version(%__MODULE__{type: :password}), do: 0
  def expected_version(%__MODULE__{type: :other}), do: nil
end
