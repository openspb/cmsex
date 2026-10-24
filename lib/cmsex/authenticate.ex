defmodule Cmsex.Authenticate do
  @moduledoc false
  # Writing and verifying AuthenticatedData (RFC 5652, 9): a content, an
  # HMAC (RFC 2104) over it or over its authenticated attributes, and the
  # MAC key wrapped for each recipient as in EnvelopedData.
  #
  # As in decryption, what goes wrong once a secret is used, a key that
  # does not unwrap or a MAC that does not check, is one error,
  # `:invalid_mac`, with no detail. RSA PKCS #1 v1.5 gives a random key
  # when its padding does not check (RFC 3218), so that its failure, too,
  # only shows in the MAC.

  alias Cmsex.{
    Algorithm,
    Attribute,
    Authenticated,
    AuthenticatedData,
    Compose,
    Decrypt,
    DER,
    Digest,
    Error,
    Message,
    Options,
    PEM,
    Recipient,
    RecipientKey
  }

  @options %{
    mac: :hmac_sha256,
    digest: nil,
    content_type: :data,
    detached: nil,
    authenticated_attributes: [],
    unauthenticated_attributes: [],
    certificates: [],
    crls: [],
    min_rsa_bits: 2048
  }

  @hashes %{
    hmac_sha224: :sha224,
    hmac_sha256: :sha256,
    hmac_sha384: :sha384,
    hmac_sha512: :sha512
  }

  @keys Options.limits() ++
          [
            :max_recipients,
            :max_iterations,
            :allow_sha1,
            :key,
            :certificate,
            :kek,
            :password,
            :mac_key,
            :content
          ]

  # The shortest MAC key taken from a message: one shorter than this would
  # let whoever sees the MAC find the key, and then MAC another content.
  @min_key_size 16

  ## Writing

  @doc "An AuthenticatedData of `content` for `recipients`; see `Cmsex.mac/3`."
  @spec mac(Digest.content(), Recipient.t() | binary() | [Recipient.t() | binary()], keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def mac(content, recipients, opts) do
    Compose.content!(content)
    recipients = Compose.recipients!(recipients)
    opts = Compose.options!(opts, @options)
    detached = Compose.detached!(content, opts.detached)
    hash = Map.fetch!(@hashes, opts.mac)
    digest = digest!(content, opts.digest, hash)
    key = :crypto.strong_rand_bytes(key_size(hash))

    with {:ok, prepared} <- Compose.prepare(recipients, opts),
         {:ok, originator} <- Compose.originator_info(opts.certificates, opts.crls),
         {:ok, recipient_infos} <- Compose.recipient_infos(prepared, key) do
      {authenticated, mac} = authenticate(content, hash, digest, key, opts)

      # RFC 5652, 9.1: version 0, since only X.509 certificates and CRLs
      # are written.
      fields =
        [{:int, 0}] ++
          List.wrap(originator) ++
          [{:set, recipient_infos}, Algorithm.mac_identifier(hash)] ++
          authenticated.digest_algorithm ++
          [Compose.encap_content_info(opts.content_type, if(detached, do: nil, else: content))] ++
          authenticated.attributes ++
          [{:octets, mac}] ++
          Compose.attributes(0xA3, opts.unauthenticated_attributes)

      {:ok, Compose.content_info(:auth_data, fields)}
    end
  end

  # The MAC key: as long as the output of the hash (RFC 2104, 3), and 32
  # bytes for SHA-224, so that AES key wrap, which takes multiples of 8
  # bytes, can carry it.
  defp key_size(:sha224), do: 32
  defp key_size(hash), do: Digest.size(hash)

  # RFC 5652, 9.2: without authenticated attributes, the MAC is over the
  # content; with them, over their DER as a SET OF, and they hold the
  # content type and the digest of the content. They are written when
  # asked for, for content other than id-data (9.1), and for a ready
  # digest, which cannot be MACed itself.
  defp authenticate(content, hash, digest, key, opts) do
    if opts.authenticated_attributes == [] and opts.content_type == :data and
         not match?({:digest, _, _}, content) do
      {%{digest_algorithm: [], attributes: []}, hmac(hash, key, content)}
    else
      %{^digest => value} = Digest.many(content, [digest])

      set =
        Compose.attribute_set([
          Attribute.content_type(opts.content_type),
          Compose.message_digest(value) | opts.authenticated_attributes
        ])

      digest_id = DER.encode(Algorithm.digest_identifier(digest))

      {%{
         digest_algorithm: [{:raw, DER.retag(digest_id, 0xA1)}],
         attributes: [{:raw, DER.retag(set, 0xA2)}]
       }, hmac(hash, key, set)}
    end
  end

  # The hash of the message-digest attribute: that of a ready digest, of
  # the option, or of the HMAC. A ready digest must be of SHA-2, the only
  # hashes written.
  defp digest!({:digest, hash, _value}, _given, _mac_hash)
       when hash not in [:sha224, :sha256, :sha384, :sha512],
       do: raise(ArgumentError, "a ready digest must be of SHA-2, got: #{inspect(hash)}")

  defp digest!({:digest, hash, _value}, given, _mac_hash) when given in [nil, hash], do: hash

  defp digest!({:digest, hash, _value}, given, _mac_hash),
    do:
      raise(
        ArgumentError,
        ":digest is #{inspect(given)}, but the ready digest is of #{inspect(hash)}"
      )

  defp digest!(_content, given, mac_hash), do: given || mac_hash

  defp hmac(hash, key, {:stream, enumerable}) do
    enumerable
    |> Enum.reduce(:crypto.mac_init(:hmac, Digest.crypto(hash), key), fn chunk, state ->
      :crypto.mac_update(state, chunk)
    end)
    |> :crypto.mac_final()
  end

  defp hmac(hash, key, data), do: :crypto.mac(:hmac, Digest.crypto(hash), key, data)

  ## Verifying

  @doc "Verifies an AuthenticatedData; see `Cmsex.verify_mac/2`."
  @spec verify_mac(binary(), keyword()) :: {:ok, Authenticated.t()} | {:error, Error.t()}
  def verify_mac(cms, opts) do
    opts = Decrypt.options!(opts, @keys, :mac_key)

    with {:ok, der} <- PEM.input(cms),
         {:ok, credentials} <- Decrypt.credentials(opts),
         {:ok, message} <- Message.parse(der, opts, [:auth_data]),
         {:ok, hash} <- mac_algorithm(message),
         {:ok, digest} <- digest_algorithm(message, opts),
         {:ok, content} <- Message.content(message.content, opts.content),
         :ok <- usable(content, message, digest),
         {:ok, key, recipient} <- mac_key(message, credentials, hash, opts),
         :ok <- check_mac(message, hash, key, content),
         :ok <- attributes(message, digest, content) do
      {:ok,
       %Authenticated{
         content: message.content,
         content_type: message.content_type,
         recipient: recipient,
         message: message
       }}
    end
  end

  defp mac_algorithm(message) do
    case Algorithm.mac(message.raw.mac_algorithm) do
      {:ok, hash} -> {:ok, hash}
      {:error, reason, detail} -> {:error, Error.new(reason, detail)}
    end
  end

  # RFC 5652, 9.1: digestAlgorithm with authenticated attributes, and only
  # with them. SHA-1 in it needs `allow_sha1: true`, as in a signature;
  # HMAC-SHA1 itself does not, since HMAC does not rest on collisions.
  defp digest_algorithm(%AuthenticatedData{raw: raw}, opts) do
    case {raw.authenticated_attributes, raw.digest_algorithm} do
      {nil, nil} ->
        {:ok, nil}

      {attributes, alg} when attributes == nil or alg == nil ->
        {:error, Error.new(:malformed, :digest_algorithm)}

      {_attributes, alg} ->
        with {:ok, hash} <- Algorithm.digest(alg),
             :ok <- Algorithm.allowed_digest(hash, allow_sha1: opts.allow_sha1) do
          {:ok, hash}
        else
          {:error, reason, detail} -> {:error, Error.new(reason, detail)}
        end
    end
  end

  # A ready digest stands for the content only through the
  # message-digest attribute, and only for its own hash.
  defp usable({:digest, _hash, _value}, _message, nil),
    do: {:error, Error.new(:content_required)}

  defp usable({:digest, hash, _value}, _message, digest) when hash != digest,
    do: {:error, Error.new(:content_required, digest)}

  defp usable(_content, _message, _digest), do: :ok

  defp mac_key(_message, _credentials, _hash, %{mac_key: key}), do: {:ok, key, nil}

  defp mac_key(message, credentials, hash, opts) do
    context = %{certificates: message.certificates, max_iterations: opts.max_iterations}
    size = {:at_least, @min_key_size, key_size(hash)}

    case RecipientKey.find(message.recipient_infos, credentials, size, context) do
      {:ok, key, info} -> {:ok, key, info}
      :error -> {:error, Error.new(:invalid_mac)}
      {:error, reason, detail} -> {:error, Error.new(reason, detail)}
    end
  end

  # The authenticated attributes as received, with the SET OF tag (9.2).
  defp check_mac(message, hash, key, content) do
    input =
      case message.raw.authenticated_attributes do
        nil -> content
        raw -> DER.retag(raw, 0x31)
      end

    mac = hmac(hash, key, input)

    if Digest.equal?(mac, message.mac), do: :ok, else: {:error, Error.new(:invalid_mac)}
  end

  # Once the MAC has checked, the attributes are the sender's: the content
  # type, required for content other than id-data (9.1), and the digest
  # of the content (9.3).
  defp attributes(%AuthenticatedData{authenticated_attributes: nil} = message, _digest, _content) do
    if message.content_type == :data,
      do: :ok,
      else: {:error, Error.new(:missing_attribute, :content_type)}
  end

  defp attributes(message, digest, content) do
    %{authenticated_attributes: attributes, content_type: type} = message

    with :ok <- content_type(attributes, type),
         {:ok, value} <- read(attributes, :message_digest) do
      %{^digest => computed} = Digest.many(content, [digest])

      if Digest.equal?(value, computed), do: :ok, else: {:error, Error.new(:digest_mismatch)}
    end
  end

  defp content_type(attributes, type) do
    case read(attributes, :content_type) do
      {:ok, ^type} -> :ok
      {:ok, _other} -> {:error, Error.new(:content_type_mismatch)}
      error -> error
    end
  end

  defp read(attributes, type) do
    case Message.read_attribute(attributes, type) do
      {:ok, value} -> {:ok, value}
      {:error, :missing} -> {:error, Error.new(:missing_attribute, type)}
      {:error, :invalid} -> {:error, Error.new(:invalid_attribute, type)}
    end
  end
end
