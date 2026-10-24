defmodule Cmsex.Envelope do
  @moduledoc false
  # Writing EnvelopedData (RFC 5652, 6), AuthEnvelopedData (RFC 5083) and
  # EncryptedData (RFC 5652, 8), in DER.
  #
  # Every recipient is checked before anything is encrypted: its
  # certificate read, its key checked against the kind of recipient and its
  # key usage. A new content-encryption key is drawn for each message.

  alias Cmsex.{
    Attribute,
    Certificate,
    Cipher,
    DER,
    EnvelopedData,
    Error,
    OID,
    Recipient,
    RecipientKey
  }

  # The ciphers written. Triple-DES and RC2 are read only.
  @ciphers [
    :aes128_cbc,
    :aes192_cbc,
    :aes256_cbc,
    :aes128_gcm,
    :aes192_gcm,
    :aes256_gcm,
    :aes128_ccm,
    :aes192_ccm,
    :aes256_ccm,
    :chacha20_poly1305
  ]

  @options %{
    cipher: :aes256_cbc,
    tag_size: 16,
    content_type: :data,
    detached: false,
    unprotected_attributes: [],
    authenticated_attributes: [],
    certificates: [],
    crls: [],
    min_rsa_bits: 2048
  }

  @doc "Encrypts `content` for `recipients`; see `Cmsex.encrypt/3`."
  @spec encrypt(binary(), term(), keyword()) ::
          {:ok, binary() | {binary(), binary()}} | {:error, Error.t()}
  def encrypt(content, recipients, opts) do
    content!(content)
    recipients = recipients!(recipients)
    opts = take!(opts, Map.keys(@options))
    cipher = Cipher.new(opts.cipher, opts.tag_size)
    aead? = Cipher.aead?(cipher)

    if opts.authenticated_attributes != [] and not aead?,
      do:
        raise(
          ArgumentError,
          ":authenticated_attributes needs an authenticated cipher, such as :aes256_gcm"
        )

    cek = Cipher.random_key(cipher)

    with {:ok, prepared} <- prepare(recipients, opts, 0, []),
         {:ok, originator} <- originator_info(opts.certificates, opts.crls),
         {:ok, recipient_infos} <- recipient_infos(prepared, cek, 0, []) do
      {cms, ciphertext} =
        if aead?,
          do: auth_enveloped_data(content, cek, cipher, recipient_infos, originator, opts),
          else: enveloped_data(content, cek, cipher, recipient_infos, prepared, originator, opts)

      {:ok, output(cms, ciphertext, opts.detached)}
    end
  end

  @doc "Encrypts `content` with `key`; see `Cmsex.encrypt_with_key/3`."
  @spec encrypt_with_key(binary(), binary(), keyword()) :: {:ok, binary() | {binary(), binary()}}
  def encrypt_with_key(content, key, opts) do
    content!(content)
    opts = take!(opts, [:cipher, :content_type, :detached, :unprotected_attributes])
    cipher = Cipher.new(opts.cipher)

    if Cipher.aead?(cipher),
      do:
        raise(
          ArgumentError,
          "EncryptedData has no place for a tag; use a CBC cipher, or encrypt/3 " <>
            "with a KEK recipient"
        )

    unless is_binary(key) and byte_size(key) == cipher.key_size,
      do: raise(ArgumentError, "the key of #{cipher.name} must be #{cipher.key_size} bytes")

    {ciphertext, nil} = Cipher.encrypt(cipher, key, content)
    attributes = opts.unprotected_attributes

    fields =
      [
        {:int, if(attributes == [], do: 0, else: 2)},
        encrypted_content_info(opts, cipher, ciphertext)
      ] ++ attributes(0xA1, attributes)

    {:ok, output(content_info(:encrypted_data, fields), ciphertext, opts.detached)}
  end

  ## Options

  defp content!(content) do
    unless is_binary(content),
      do: raise(ArgumentError, "the content must be a binary, got: #{inspect(content, limit: 5)}")
  end

  # One recipient, a certificate in DER, or a list of them.
  defp recipients!(%Recipient{} = recipient), do: [recipient]
  defp recipients!(certificate) when is_binary(certificate), do: [recipient!(certificate)]
  defp recipients!([_ | _] = recipients), do: Enum.map(recipients, &recipient!/1)

  defp recipients!(other),
    do:
      raise(
        ArgumentError,
        "expected a Cmsex.Recipient, a DER certificate or a list of them, got: " <>
          inspect(other, limit: 5)
      )

  defp recipient!(%Recipient{} = recipient), do: recipient
  defp recipient!(certificate) when is_binary(certificate), do: Recipient.certificate(certificate)
  defp recipient!(other), do: recipients!(other)

  defp take!(opts, keys) do
    unless Keyword.keyword?(opts),
      do: raise(ArgumentError, "expected a keyword list of options, got: #{inspect(opts)}")

    for {key, value} <- opts do
      unless key in keys, do: raise(ArgumentError, "unknown option #{inspect(key)}")
      check!(key, value)
    end

    opts = @options |> Map.take(keys) |> Map.merge(Map.new(opts))
    %{opts | content_type: OID.name(OID.oid(opts.content_type))}
  end

  defp check!(:cipher, value),
    do: ensure!(value in @ciphers, ":cipher must be one of #{inspect(@ciphers)}", value)

  defp check!(:tag_size, value),
    do: ensure!(is_integer(value), ":tag_size must be an integer", value)

  defp check!(:content_type, value) do
    ensure!(is_atom(value) or is_tuple(value), ":content_type must be an OID", value)
    _ = value |> OID.oid() |> OID.encode()
    :ok
  end

  defp check!(:detached, value),
    do: ensure!(is_boolean(value), ":detached must be a boolean", value)

  defp check!(:unprotected_attributes, value), do: attributes!(:unprotected_attributes, value)

  defp check!(:authenticated_attributes, value) do
    attributes!(:authenticated_attributes, value)

    for %Attribute{type: type} <- value, type in [:content_type, :message_digest] do
      raise ArgumentError,
            "the authenticated attribute #{inspect(type)} is written by the library, or not at all"
    end
  end

  defp check!(key, value) when key in [:certificates, :crls] do
    ensure!(
      is_list(value) and Enum.all?(value, &is_binary/1),
      "#{inspect(key)} must be a list of DER binaries",
      value
    )
  end

  defp check!(:min_rsa_bits, value),
    do:
      ensure!(is_integer(value) and value > 0, ":min_rsa_bits must be a positive integer", value)

  defp attributes!(key, value) do
    ensure!(
      is_list(value) and Enum.all?(value, &match?(%Attribute{}, &1)),
      "#{inspect(key)} must be a list of Cmsex.Attribute",
      value
    )
  end

  defp ensure!(true, _message, _value), do: :ok

  defp ensure!(false, message, value),
    do: raise(ArgumentError, "#{message}, got: #{inspect(value, limit: 5)}")

  ## Recipients

  defp prepare([], _opts, _index, acc), do: {:ok, Enum.reverse(acc)}

  defp prepare([recipient | rest], opts, index, acc) do
    case RecipientKey.prepare(recipient, opts) do
      {:ok, prepared} -> prepare(rest, opts, index + 1, [prepared | acc])
      {:error, reason, detail} -> {:error, %{Error.new(reason, detail) | recipient: index}}
    end
  end

  defp recipient_infos([], _cek, _index, acc), do: {:ok, Enum.reverse(acc)}

  defp recipient_infos([prepared | rest], cek, index, acc) do
    case RecipientKey.encrypt(prepared, cek) do
      {:ok, term} ->
        recipient_infos(rest, cek, index + 1, [{:raw, DER.encode(term)} | acc])

      {:error, reason, detail} ->
        {:error, %{Error.new(reason, detail) | recipient: index}}
    end
  end

  # OriginatorInfo (RFC 5652, 6.1): certs [0] and crls [1], only X.509.
  defp originator_info([], []), do: {:ok, nil}

  defp originator_info(certificates, crls) do
    cond do
      not Enum.all?(certificates, &match?({:ok, _}, Certificate.parse(&1))) ->
        {:error, Error.new(:invalid_certificate)}

      not Enum.all?(crls, &match?({:ok, {0x30, _, _}}, DER.decode(&1))) ->
        {:error, Error.new(:malformed, :crls)}

      true ->
        fields =
          tagged_set(0xA0, Enum.uniq(certificates)) ++ tagged_set(0xA1, Enum.uniq(crls))

        {:ok, {:constructed, 0xA0, fields}}
    end
  end

  ## The messages

  # EnvelopedData (RFC 5652, 6.1), with the version its fields call for.
  defp enveloped_data(content, cek, cipher, recipient_infos, prepared, originator, opts) do
    {ciphertext, nil} = Cipher.encrypt(cipher, cek, content)
    attributes = opts.unprotected_attributes

    version =
      EnvelopedData.version(
        nil,
        originator != nil,
        Enum.map(prepared, &{&1.type, &1.version}),
        attributes != []
      )

    fields =
      [{:int, version}] ++
        List.wrap(originator) ++
        [{:set, recipient_infos}, encrypted_content_info(opts, cipher, ciphertext)] ++
        attributes(0xA1, attributes)

    {content_info(:enveloped_data, fields), ciphertext}
  end

  # AuthEnvelopedData (RFC 5083, 2.1): version 0; the authenticated
  # attributes, with content-type, are the AAD as a SET OF (2.2), and the
  # tag is the mac.
  defp auth_enveloped_data(content, cek, cipher, recipient_infos, originator, opts) do
    authenticated =
      if opts.authenticated_attributes != [] or opts.content_type != :data,
        do: [Attribute.content_type(opts.content_type) | opts.authenticated_attributes],
        else: []

    set = if authenticated != [], do: attribute_set(authenticated), else: <<>>
    {ciphertext, tag} = Cipher.encrypt(cipher, cek, content, set)

    fields =
      [{:int, 0}] ++
        List.wrap(originator) ++
        [{:set, recipient_infos}, encrypted_content_info(opts, cipher, ciphertext)] ++
        if(set == <<>>, do: [], else: [{:raw, DER.retag(set, 0xA1)}]) ++
        [{:octets, tag}] ++
        attributes(0xA2, opts.unprotected_attributes)

    {content_info(:auth_enveloped_data, fields), ciphertext}
  end

  # EncryptedContentInfo: encryptedContent [0] IMPLICIT, primitive.
  defp encrypted_content_info(opts, cipher, ciphertext) do
    content = if opts.detached, do: [], else: [{:primitive, 0x80, ciphertext}]
    {:seq, [{:oid, opts.content_type}, Cipher.identifier(cipher) | content]}
  end

  defp attributes(_tag, []), do: []
  defp attributes(tag, attributes), do: [{:raw, DER.retag(attribute_set(attributes), tag)}]

  defp attribute_set(attributes),
    do: DER.encode({:set, Enum.map(attributes, &{:raw, DER.encode(Attribute.to_term(&1))})})

  defp tagged_set(_tag, []), do: []

  defp tagged_set(tag, ders),
    do: [{:raw, DER.retag(DER.encode({:set, Enum.map(ders, &{:raw, &1})}), tag)}]

  defp content_info(type, fields),
    do: DER.encode({:seq, [{:oid, type}, {:explicit, 0, {:seq, fields}}]})

  defp output(cms, _ciphertext, false), do: cms
  defp output(cms, ciphertext, true), do: {cms, ciphertext}
end
