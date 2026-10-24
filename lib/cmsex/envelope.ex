defmodule Cmsex.Envelope do
  @moduledoc false
  # Writing EnvelopedData (RFC 5652, 6), AuthEnvelopedData (RFC 5083) and
  # EncryptedData (RFC 5652, 8), in DER.
  #
  # Every recipient is checked before anything is encrypted: its
  # certificate read, its key checked against the kind of recipient and its
  # key usage. A new content-encryption key is drawn for each message.

  alias Cmsex.{Attribute, Cipher, Compose, DER, EnvelopedData, Recipient}

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
  @spec encrypt(binary(), Recipient.t() | binary() | [Recipient.t() | binary()], keyword()) ::
          {:ok, binary() | {binary(), binary()}} | {:error, Cmsex.Error.t()}
  def encrypt(content, recipients, opts) do
    Compose.binary!(content)
    recipients = Compose.recipients!(recipients)
    opts = Compose.options!(opts, @options)
    cipher = Cipher.new(opts.cipher, opts.tag_size)
    aead? = Cipher.aead?(cipher)

    if opts.authenticated_attributes != [] and not aead?,
      do:
        raise(
          ArgumentError,
          ":authenticated_attributes needs an authenticated cipher, such as :aes256_gcm"
        )

    cek = Cipher.random_key(cipher)

    with {:ok, prepared} <- Compose.prepare(recipients, opts),
         {:ok, originator} <- Compose.originator_info(opts.certificates, opts.crls),
         {:ok, recipient_infos} <- Compose.recipient_infos(prepared, cek) do
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
    Compose.binary!(content)

    opts =
      Compose.options!(
        opts,
        Map.take(@options, [:cipher, :content_type, :detached, :unprotected_attributes])
      )

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
      ] ++ Compose.attributes(0xA1, attributes)

    {:ok, output(Compose.content_info(:encrypted_data, fields), ciphertext, opts.detached)}
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
        Compose.attributes(0xA1, attributes)

    {Compose.content_info(:enveloped_data, fields), ciphertext}
  end

  # AuthEnvelopedData (RFC 5083, 2.1): version 0; the authenticated
  # attributes, with content-type, are the AAD as a SET OF (2.2), and the
  # tag is the mac.
  defp auth_enveloped_data(content, cek, cipher, recipient_infos, originator, opts) do
    authenticated =
      if opts.authenticated_attributes != [] or opts.content_type != :data,
        do: [Attribute.content_type(opts.content_type) | opts.authenticated_attributes],
        else: []

    set = if authenticated != [], do: Compose.attribute_set(authenticated), else: <<>>
    {ciphertext, tag} = Cipher.encrypt(cipher, cek, content, set)

    fields =
      [{:int, 0}] ++
        List.wrap(originator) ++
        [{:set, recipient_infos}, encrypted_content_info(opts, cipher, ciphertext)] ++
        if(set == <<>>, do: [], else: [{:raw, DER.retag(set, 0xA1)}]) ++
        [{:octets, tag}] ++
        Compose.attributes(0xA2, opts.unprotected_attributes)

    {Compose.content_info(:auth_enveloped_data, fields), ciphertext}
  end

  # EncryptedContentInfo: encryptedContent [0] IMPLICIT, primitive.
  defp encrypted_content_info(opts, cipher, ciphertext) do
    content = if opts.detached, do: [], else: [{:primitive, 0x80, ciphertext}]
    {:seq, [{:oid, opts.content_type}, Cipher.identifier(cipher) | content]}
  end

  defp output(cms, _ciphertext, false), do: cms
  defp output(cms, ciphertext, true), do: {cms, ciphertext}
end
