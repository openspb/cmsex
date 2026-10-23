defmodule Cmsex.Certificate do
  @moduledoc false
  # What CMS needs from an X.509 certificate (RFC 5280): the issuer and
  # subject as received, the serial number, the public key and a few
  # extensions. Read with `Cmsex.DER`, so the bytes of the issuer are those
  # of the certificate, whatever their string types.

  alias Cmsex.{Algorithm, DER, OID}

  @type public_key ::
          {:rsa, pos_integer(), pos_integer()}
          | {:rsa_pss, pos_integer(), pos_integer(), Algorithm.pss() | nil}
          | {:ec, atom() | tuple(), binary()}
          | {:ed25519 | :ed448 | :x25519 | :x448, binary()}
          | {:unknown, tuple()}

  @type t :: %__MODULE__{
          der: binary(),
          serial: integer(),
          issuer: binary(),
          subject: binary(),
          public_key: public_key(),
          spki: binary(),
          subject_key_identifier: binary() | nil,
          authority_key_identifier: binary() | nil,
          key_usage: [atom()] | nil,
          ext_key_usage: [atom() | tuple()] | nil,
          ca?: boolean()
        }

  defstruct [
    :der,
    :serial,
    :issuer,
    :subject,
    :public_key,
    :spki,
    :subject_key_identifier,
    :authority_key_identifier,
    :key_usage,
    :ext_key_usage,
    ca?: false
  ]

  @key_usage [
    :digital_signature,
    :non_repudiation,
    :key_encipherment,
    :data_encipherment,
    :key_agreement,
    :key_cert_sign,
    :crl_sign,
    :encipher_only,
    :decipher_only
  ]

  @doc "Reads a certificate in DER."
  @spec parse(binary()) :: {:ok, t()} | :error
  def parse(der) when is_binary(der) do
    with {:ok, {0x30, _, _} = cert} <- DER.decode(der),
         [{0x30, _, _} = tbs, {0x30, _, _}, {0x03, _, _}] <- DER.children(cert),
         {:ok, fields} <- tbs_fields(DER.children(tbs)),
         {:ok, serial} <- DER.integer(fields.serial),
         {:ok, public_key} <- spki_key(fields.spki),
         {:ok, extensions} <- extensions(fields.extensions) do
      {:ok,
       struct!(
         %__MODULE__{
           der: der,
           serial: serial,
           issuer: elem(fields.issuer, 2),
           subject: elem(fields.subject, 2),
           public_key: public_key,
           spki: elem(fields.spki, 2)
         },
         extensions
       )}
    else
      _ -> :error
    end
  end

  def parse(_der), do: :error

  defp tbs_fields(fields) do
    fields =
      case fields do
        [{0xA0, _, _} | rest] -> rest
        rest -> rest
      end

    case fields do
      [
        serial,
        {0x30, _, _},
        {0x30, _, _} = issuer,
        {0x30, _, _},
        {0x30, _, _} = subject,
        {0x30, _, _} = spki | rest
      ] ->
        extensions = Enum.find(rest, &match?({0xA3, _, _}, &1))

        {:ok,
         %{serial: serial, issuer: issuer, subject: subject, spki: spki, extensions: extensions}}

      _ ->
        :error
    end
  end

  @doc "The public key in a SubjectPublicKeyInfo element."
  @spec spki_key(DER.element()) :: {:ok, public_key()} | :error
  def spki_key({0x30, _, _} = spki) do
    with [alg, bits] <- DER.children(spki),
         {:ok, {oid, params}} <- Algorithm.read(alg),
         {:ok, key} <- DER.bit_string(bits) do
      key(OID.name(oid), oid, params, key)
    else
      _ -> :error
    end
  end

  def spki_key(_element), do: :error

  defp key(name, _oid, params, key) when name in [:rsa_encryption, :rsassa_pss] do
    with {:ok, {0x30, _, _} = seq} <- DER.decode(key),
         [n, e] <- DER.children(seq),
         {:ok, n} when n > 0 <- DER.integer(n),
         {:ok, e} when e > 0 <- DER.integer(e) do
      rsa_key(name, n, e, params)
    else
      _ -> :error
    end
  end

  defp key(:ec_public_key, _oid, {0x06, _, _} = curve, point) do
    with {:ok, curve} <- DER.oid(curve), do: {:ok, {:ec, OID.name(curve), point}}
  end

  defp key(name, _oid, nil, key) when name in [:ed25519, :ed448, :x25519, :x448] do
    if byte_size(key) == key_size(name), do: {:ok, {name, key}}, else: :error
  end

  defp key(_name, oid, _params, _key), do: {:ok, {:unknown, oid}}

  defp rsa_key(:rsa_encryption, n, e, _params), do: {:ok, {:rsa, n, e}}
  defp rsa_key(:rsassa_pss, n, e, nil), do: {:ok, {:rsa_pss, n, e, nil}}

  defp rsa_key(:rsassa_pss, n, e, params) do
    case Algorithm.pss_params(params) do
      {:ok, pss} -> {:ok, {:rsa_pss, n, e, pss}}
      _ -> :error
    end
  end

  @doc "The size of a public key of an Edwards or Montgomery curve."
  @spec key_size(:ed25519 | :ed448 | :x25519 | :x448) :: 32 | 56 | 57
  def key_size(:ed25519), do: 32
  def key_size(:x25519), do: 32
  def key_size(:ed448), do: 57
  def key_size(:x448), do: 56

  defp extensions(nil), do: {:ok, []}

  defp extensions({0xA3, _, _} = tagged) do
    case DER.children(tagged) do
      [{0x30, _, _} = list] -> Enum.reduce_while(DER.children(list), {:ok, []}, &add_extension/2)
      _ -> :error
    end
  end

  defp add_extension(ext, {:ok, acc}) do
    case extension(ext) do
      {:ok, nil} -> {:cont, {:ok, acc}}
      {:ok, field} -> {:cont, {:ok, [field | acc]}}
      :error -> {:halt, :error}
    end
  end

  @known [
    :subject_key_identifier,
    :authority_key_identifier,
    :key_usage,
    :ext_key_usage,
    :basic_constraints
  ]

  # Only the values of the extensions read here must be valid DER.
  defp extension({0x30, _, _} = ext) do
    with {:ok, oid, value} <- extension_fields(DER.children(ext)) do
      known_extension(OID.name(oid), value)
    end
  end

  defp extension(_ext), do: :error

  defp known_extension(name, value) when name in @known do
    case DER.decode(value) do
      {:ok, inner} -> extension_value(name, inner)
      {:error, _} -> :error
    end
  end

  defp known_extension(_name, _value), do: {:ok, nil}

  defp extension_fields([oid, {0x01, _, _}, {0x04, value, _}]), do: extension_fields(oid, value)
  defp extension_fields([oid, {0x04, value, _}]), do: extension_fields(oid, value)
  defp extension_fields(_fields), do: :error

  defp extension_fields(oid, value) do
    with {:ok, oid} <- DER.oid(oid), do: {:ok, oid, value}
  end

  defp extension_value(:subject_key_identifier, {0x04, ski, _}),
    do: {:ok, {:subject_key_identifier, ski}}

  defp extension_value(:authority_key_identifier, {0x30, _, _} = aki) do
    case DER.children(aki) do
      [{0x80, id, _} | _] -> {:ok, {:authority_key_identifier, id}}
      _ -> {:ok, nil}
    end
  end

  defp extension_value(:key_usage, bits) do
    with {:ok, positions} <- DER.named_bits(bits) do
      names = for i <- positions, i < length(@key_usage), do: Enum.at(@key_usage, i)
      {:ok, {:key_usage, names}}
    end
  end

  defp extension_value(:ext_key_usage, {0x30, _, _} = list) do
    oids = for el <- DER.children(list), {:ok, oid} <- [DER.oid(el)], do: OID.name(oid)
    {:ok, {:ext_key_usage, oids}}
  end

  defp extension_value(:basic_constraints, {0x30, _, _} = bc) do
    case DER.children(bc) do
      [{0x01, _, _} = ca | _] -> {:ok, {:ca?, DER.boolean(ca) == {:ok, true}}}
      _ -> {:ok, nil}
    end
  end

  defp extension_value(_name, _value), do: :error

  ## Names

  @doc """
  A Name in a form for comparison, after RFC 5280, 7.1: attribute values of
  the directory string types become UTF-8, with case folded and spaces
  collapsed; other values stay as their DER; the attributes of each RDN are
  sorted. Two names are the same when these forms are equal. Returns `nil`
  when the bytes are not a Name.
  """
  @spec canonical_name(binary()) :: [[{tuple(), term()}]] | nil
  def canonical_name(raw) do
    with {:ok, {0x30, _, _} = name} <- DER.decode(raw),
         {:ok, rdns} <- rdns(DER.children(name), []) do
      rdns
    else
      _ -> nil
    end
  end

  defp rdns([], acc), do: {:ok, Enum.reverse(acc)}

  defp rdns([{0x31, _, _} = rdn | rest], acc) do
    atvs =
      for {0x30, _, _} = atv <- DER.children(rdn) do
        case DER.children(atv) do
          [type, value] -> {DER.oid(type), value}
          _ -> :error
        end
      end

    if atvs != [] and Enum.all?(atvs, &match?({{:ok, _}, _}, &1)) do
      canonical =
        atvs |> Enum.map(fn {{:ok, type}, value} -> {type, value(value)} end) |> Enum.sort()

      rdns(rest, [canonical | acc])
    else
      :error
    end
  end

  defp rdns(_rdns, _acc), do: :error

  defp value({0x0C, s, _}), do: fold(s)
  defp value({0x13, s, _}), do: fold(s)
  defp value({0x16, s, _}), do: fold(s)
  defp value({0x14, s, _}), do: fold(:unicode.characters_to_binary(s, :latin1))
  defp value({0x1E, s, _}), do: fold(:unicode.characters_to_binary(s, {:utf16, :big}))
  defp value({0x1C, s, _}), do: fold(:unicode.characters_to_binary(s, {:utf32, :big}))
  defp value({_, _, raw}), do: {:der, raw}

  defp fold(s) when is_binary(s) do
    if String.valid?(s) do
      {:string, s |> String.downcase() |> String.split() |> Enum.join(" ")}
    else
      {:invalid, s}
    end
  end

  defp fold(other), do: {:invalid, other}
end
