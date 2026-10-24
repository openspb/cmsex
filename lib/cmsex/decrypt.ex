defmodule Cmsex.Decrypt do
  @moduledoc false
  # Decrypting EnvelopedData (RFC 5652, 6), AuthEnvelopedData (RFC 5083)
  # and EncryptedData (RFC 5652, 8).
  #
  # What can be told before any secret is used is told: a malformed
  # message, an algorithm the library does not implement, credentials that
  # cannot be read or do not match, no recipient for them. After that,
  # whatever goes wrong, a key that does not unwrap, a padding or a tag
  # that does not check, is `:decryption_failed`, with no detail
  # (RFC 3218).

  alias Cmsex.{
    Cipher,
    Decrypted,
    DER,
    EncryptedData,
    EnvelopedData,
    Error,
    Message,
    Options,
    PEM,
    RecipientKey
  }

  @keys Options.limits() ++
          [
            :max_recipients,
            :max_iterations,
            :key,
            :certificate,
            :kek,
            :password,
            :content_key,
            :content
          ]

  @doc "Decrypts a message in DER, BER or PEM; see `Cmsex.decrypt/2`."
  @spec decrypt(binary(), keyword()) :: {:ok, Decrypted.t()} | {:error, Error.t()}
  def decrypt(cms, opts) do
    opts = options!(opts, @keys, :content_key)

    unless opts[:content] == nil or is_binary(opts[:content]),
      do: raise(ArgumentError, ":content must be the encrypted content, a binary")

    with {:ok, der} <- PEM.input(cms),
         {:ok, credentials} <- credentials(opts),
         {:ok, message} <-
           Message.parse(der, opts, [:enveloped_data, :auth_enveloped_data, :encrypted_data]),
         {:ok, ciphertext} <- Message.content(message.encrypted_content, opts[:content]),
         {:ok, cipher} <- cipher(message),
         {:ok, cek, recipient} <- content_key(message, credentials, cipher, opts) do
      with {:ok, content} <- decrypt_content(message, cipher, cek, ciphertext),
           :ok <- authenticated_content_type(message) do
        {:ok,
         %Decrypted{
           content: content,
           content_type: message.content_type,
           recipient: recipient,
           message: message
         }}
      else
        :error -> {:error, Error.new(:decryption_failed)}
        {:error, reason, detail} -> {:error, Error.new(reason, detail)}
      end
    end
  end

  ## Options

  @doc """
  The options of a function that recovers a key from the recipients, as
  `Cmsex.Options.take!/2` takes them, with the credentials checked: a key
  with its certificate, a KEK, a password, or `direct`, the key itself
  under that name. The values are secrets, and are never shown.
  """
  @spec options!(keyword(), [atom()], :content_key | :mac_key) :: map()
  def options!(opts, keys, direct) do
    opts = Options.take!(opts, keys)

    unless Map.has_key?(opts, :key) == Map.has_key?(opts, :certificate),
      do: raise(ArgumentError, ":key and :certificate go together")

    unless Enum.any?([:key, :kek, :password, direct], &Map.has_key?(opts, &1)),
      do:
        raise(
          ArgumentError,
          "expected one of :key and :certificate, :kek, :password or #{inspect(direct)}"
        )

    Enum.each(opts, fn {key, value} -> check!(key, value) end)
    opts
  end

  defp check!(:key, value) do
    ensure!(
      is_binary(value) or is_tuple(value) or is_function(value, 1),
      ":key must be a DER key, a key record or a function of one argument"
    )
  end

  defp check!(:certificate, value),
    do: ensure!(is_binary(value), ":certificate must be a DER certificate")

  defp check!(:kek, value) do
    ensure!(
      match?({id, key} when is_binary(id) and is_binary(key), value),
      ":kek must be {key_identifier, key}, two binaries"
    )
  end

  defp check!(:password, value),
    do: ensure!(is_binary(value) and value != <<>>, ":password must be a non-empty binary")

  defp check!(key, value) when key in [:content_key, :mac_key],
    do: ensure!(is_binary(value) and value != <<>>, "#{inspect(key)} must be a non-empty binary")

  defp check!(_key, _value), do: :ok

  # The values are secrets, and are never shown.
  defp ensure!(true, _message), do: :ok
  defp ensure!(false, message), do: raise(ArgumentError, message)

  @doc "The credentials of `opts`, read; see `Cmsex.RecipientKey.credentials/1`."
  @spec credentials(map()) :: {:ok, map()} | {:error, Error.t()}
  def credentials(opts) do
    case RecipientKey.credentials(opts) do
      {:ok, credentials} -> {:ok, credentials}
      {:error, reason, detail} -> {:error, Error.new(reason, detail)}
    end
  end

  ## The message

  # EnvelopedData and EncryptedData have no place for a tag, so they take
  # CBC; AuthEnvelopedData takes an authenticated cipher (RFC 5083, 2.1).
  defp cipher(message) do
    {oid, _} = alg = message.raw.content_encryption_algorithm

    case Cipher.read(alg) do
      {:ok, cipher} ->
        if Cipher.aead?(cipher) == match?(%EnvelopedData{type: :auth_enveloped_data}, message),
          do: {:ok, cipher},
          else: {:error, Error.new(:unsupported_algorithm, oid)}

      {:error, reason, detail} ->
        {:error, Error.new(reason, detail)}
    end
  end

  ## The content-encryption key

  defp content_key(_message, _credentials, cipher, %{content_key: key}) do
    if byte_size(key) == cipher.key_size,
      do: {:ok, key, nil},
      else: {:error, Error.new(:decryption_failed)}
  end

  defp content_key(%EncryptedData{}, _credentials, _cipher, _opts),
    do: {:error, Error.new(:recipient_not_found)}

  # The first recipient for the credentials that gives a key of the size
  # of the cipher.
  defp content_key(%EnvelopedData{} = message, credentials, cipher, opts) do
    context = %{certificates: message.certificates, max_iterations: opts.max_iterations}

    case RecipientKey.find(message.recipient_infos, credentials, cipher.key_size, context) do
      {:ok, cek, info} -> {:ok, cek, info}
      :error -> {:error, Error.new(:decryption_failed)}
      {:error, reason, detail} -> {:error, Error.new(reason, detail)}
    end
  end

  ## The content

  defp decrypt_content(%EnvelopedData{type: :auth_enveloped_data} = message, cipher, cek, ct) do
    aad =
      case message.raw.authenticated_attributes do
        nil -> <<>>
        raw -> DER.retag(raw, 0x31)
      end

    Cipher.decrypt(cipher, cek, ct, aad, message.mac)
  end

  defp decrypt_content(_message, cipher, cek, ciphertext),
    do: Cipher.decrypt(cipher, cek, ciphertext)

  # RFC 5083, 2.1: authAttrs for content other than id-data, and in them
  # the content-type attribute (RFC 5652, 9.1). Checked once the tag has,
  # since only then are they the sender's.
  defp authenticated_content_type(%EnvelopedData{type: :auth_enveloped_data} = message) do
    %{authenticated_attributes: attributes, content_type: type} = message

    if attributes == nil and type == :data do
      :ok
    else
      case Message.read_attribute(attributes, :content_type) do
        {:ok, ^type} -> :ok
        {:ok, _other} -> {:error, :content_type_mismatch, nil}
        {:error, :missing} -> {:error, :missing_attribute, :content_type}
        {:error, :invalid} -> {:error, :invalid_attribute, :content_type}
      end
    end
  end

  defp authenticated_content_type(_message), do: :ok
end
