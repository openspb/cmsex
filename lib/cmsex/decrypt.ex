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
    opts = options!(opts)

    with {:ok, der} <- PEM.input(cms),
         {:ok, credentials} <- credentials(opts),
         {:ok, message} <-
           Message.parse(der, opts, [:enveloped_data, :auth_enveloped_data, :encrypted_data]),
         {:ok, ciphertext} <- ciphertext(message.encrypted_content, opts[:content]),
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

  defp options!(opts) do
    opts = Options.take!(opts, @keys)

    unless Map.has_key?(opts, :key) == Map.has_key?(opts, :certificate),
      do: raise(ArgumentError, ":key and :certificate go together")

    unless Enum.any?([:key, :kek, :password, :content_key], &Map.has_key?(opts, &1)),
      do:
        raise(
          ArgumentError,
          "expected one of :key and :certificate, :kek, :password or :content_key"
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

  defp check!(:content_key, value),
    do: ensure!(is_binary(value), ":content_key must be a binary")

  defp check!(:content, nil), do: :ok

  defp check!(:content, value),
    do: ensure!(is_binary(value), ":content must be the encrypted content, a binary")

  defp check!(_key, _value), do: :ok

  # The values are secrets, and are never shown.
  defp ensure!(true, _message), do: :ok
  defp ensure!(false, message), do: raise(ArgumentError, message)

  defp credentials(opts) do
    case RecipientKey.credentials(opts) do
      {:ok, credentials} -> {:ok, credentials}
      {:error, reason, detail} -> {:error, Error.new(reason, detail)}
    end
  end

  ## The message

  defp ciphertext(nil, nil), do: {:error, Error.new(:content_required)}
  defp ciphertext(nil, content), do: {:ok, content}
  defp ciphertext(content, nil), do: {:ok, content}
  defp ciphertext(_content, _given), do: {:error, Error.new(:unexpected_content)}

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

  defp content_key(%EnvelopedData{} = message, credentials, cipher, opts) do
    context = %{certificates: message.certificates, max_iterations: opts.max_iterations}

    case RecipientKey.candidates(message.recipient_infos, credentials) do
      [] -> {:error, Error.new(:recipient_not_found)}
      candidates -> try_candidates(candidates, credentials, cipher.key_size, context, nil)
    end
  end

  # The first candidate that gives a key of the size of the cipher. An
  # error that is not about the secrets, such as an algorithm the library
  # does not implement, is kept to be told when none does.
  defp try_candidates([], _credentials, _size, _context, nil),
    do: {:error, Error.new(:decryption_failed)}

  defp try_candidates([], _credentials, _size, _context, {reason, detail}),
    do: {:error, Error.new(reason, detail)}

  defp try_candidates([{_, info, _} = candidate | rest], credentials, size, context, kept) do
    case RecipientKey.recover(candidate, credentials, size, context) do
      {:ok, cek} ->
        {:ok, cek, info}

      :error ->
        try_candidates(rest, credentials, size, context, kept)

      {:error, reason, detail} ->
        try_candidates(rest, credentials, size, context, kept || {reason, detail})
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
