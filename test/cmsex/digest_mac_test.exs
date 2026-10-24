defmodule Cmsex.DigestMacTest do
  use ExUnit.Case, async: true

  alias Cmsex.{
    Algorithm,
    Attribute,
    Authenticated,
    AuthenticatedData,
    Certificate,
    DER,
    Digest,
    DigestedData,
    Error,
    KeyWrap,
    OID,
    PEM,
    Recipient,
    RecipientInfo,
    TestPKI
  }

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)

  @content "Attack at dawn, or at least before lunch."

  defp rfc4134(name), do: File.read!(Path.join(@rfc4134, name))

  defp reason({:error, %Error{reason: reason}}), do: reason

  defp error({:error, %Error{reason: reason, detail: detail}}), do: {reason, detail}

  defp message(type, fields),
    do: DER.encode({:seq, [{:oid, type}, {:explicit, 0, {:seq, fields}}]})

  defp attribute_set(attributes),
    do: DER.encode({:set, Enum.map(attributes, &{:raw, DER.encode(Attribute.to_term(&1))})})

  defp message_digest(digest),
    do: %Attribute{type: :message_digest, values: [DER.encode({:octets, digest})]}

  defp hmac(hash, key, data), do: :crypto.mac(:hmac, Digest.crypto(hash), key, data)

  defp kek(size \\ 32), do: :binary.copy(<<size>>, size)

  defp flip_in(cms, part) do
    {offset, _} = :binary.match(cms, part)
    <<before::binary-size(^offset), byte, rest::binary>> = cms
    <<before::binary, Bitwise.bxor(byte, 1), rest::binary>>
  end

  # A recipient: its certificate, with keyEncipherment or keyAgreement, and
  # its key in DER.
  defp party(name, ca) do
    kind = if name in [:x25519, :x448], do: name, else: :other
    usage = if name in [:rsa1024, :rsa2048, :rsa3072], do: [2], else: [4]
    issuer = if kind in [:x25519, :x448], do: [issuer: {ca, {:p256, :ca}}], else: []
    cert = TestPKI.cert(name, [key_usage: usage] ++ issuer)

    key =
      case TestPKI.key(name) do
        {public, _private} = pair when is_binary(public) -> TestPKI.montgomery_pkcs8(kind, pair)
        record -> TestPKI.pkcs8(record)
      end

    %{cert: cert, key: key, opts: [key: key, certificate: cert]}
  end

  ## DigestedData

  describe "digest/2" do
    test "every hash, in DER, version 0 for id-data" do
      for hash <- [:sha224, :sha256, :sha384, :sha512] do
        assert {:ok, cms} = Cmsex.digest(@content, digest: hash)

        assert cms ==
                 message(:digested_data, [
                   {:int, 0},
                   {:seq, [{:oid, hash}]},
                   {:seq, [{:oid, :data}, {:explicit, 0, {:octets, @content}}]},
                   {:octets, Digest.hash(hash, @content)}
                 ])

        assert {:ok, %DigestedData{} = dd} = Cmsex.verify_digest(cms)
        assert {dd.digest_algorithm, dd.content, dd.content_type} == {hash, @content, :data}
      end

      assert Cmsex.digest!(@content) == elem(Cmsex.digest(@content, digest: :sha256), 1)
    end

    test "version 2 for another type of content" do
      cms = Cmsex.digest!(@content, content_type: {1, 2, 3, 4})
      assert {:ok, %DigestedData{version: 2, content_type: {1, 2, 3, 4}}} = Cmsex.decode(cms)
      assert {:ok, %DigestedData{deviations: []}} = Cmsex.verify_digest(cms)

      cms = Cmsex.digest!(@content, content_type: :signed_data)
      assert {:ok, %DigestedData{version: 2, content_type: :signed_data}} = Cmsex.decode(cms)
    end

    test "detached, a stream and a ready digest" do
      detached = Cmsex.digest!(@content, detached: true)
      assert {:ok, %DigestedData{content: nil}} = Cmsex.decode(detached)
      assert reason(Cmsex.verify_digest(detached)) == :content_required
      assert {:ok, %DigestedData{content: nil}} = Cmsex.verify_digest(detached, content: @content)

      chunks = for <<chunk::binary-size(5) <- binary_part(@content, 0, 40)>>, do: chunk
      stream = Cmsex.digest!({:stream, chunks ++ [binary_part(@content, 40, 1)]})
      assert stream == detached
      assert {:ok, _} = Cmsex.verify_digest(stream, content: {:stream, [@content]})

      ready = {:digest, :sha384, Digest.hash(:sha384, @content)}
      cms = Cmsex.digest!(ready)
      assert {:ok, %DigestedData{digest_algorithm: :sha384, content: nil}} = Cmsex.decode(cms)
      assert {:ok, _} = Cmsex.verify_digest(cms, content: @content)
      assert {:ok, _} = Cmsex.verify_digest(cms, content: ready)
      assert Cmsex.digest!(ready, digest: :sha384) == cms

      other = {:digest, :sha256, Digest.hash(:sha256, @content)}
      assert error(Cmsex.verify_digest(cms, content: other)) == {:content_required, :sha384}
    end

    test "a changed content or digest" do
      cms = Cmsex.digest!(@content)
      assert reason(Cmsex.verify_digest(flip_in(cms, "dawn"))) == :digest_mismatch

      digest = Digest.hash(:sha256, @content)
      assert reason(Cmsex.verify_digest(flip_in(cms, digest))) == :digest_mismatch

      detached = Cmsex.digest!(@content, detached: true)
      assert reason(Cmsex.verify_digest(detached, content: "other")) == :digest_mismatch

      assert reason(Cmsex.verify_digest(cms, content: @content)) == :unexpected_content
    end

    test "PEM" do
      pem = @content |> Cmsex.digest!() |> PEM.encode()
      assert {:ok, %DigestedData{content: @content}} = Cmsex.verify_digest(pem)
    end

    test "option errors raise" do
      assert_raise ArgumentError, ~r/unknown option :cipher/, fn ->
        Cmsex.digest(@content, cipher: :aes128_cbc)
      end

      assert_raise ArgumentError, ~r/:digest must be/, fn ->
        Cmsex.digest(@content, digest: :sha1)
      end

      assert_raise ArgumentError, ~r/:digest must be/, fn ->
        Cmsex.digest(@content, digest: :md5)
      end

      assert_raise ArgumentError, ~r/only be detached/, fn ->
        Cmsex.digest({:stream, [@content]}, detached: false)
      end

      assert_raise ArgumentError, ~r/the content must be/, fn -> Cmsex.digest(:content) end

      assert_raise ArgumentError, ~r/must be of SHA-2/, fn ->
        Cmsex.digest({:digest, :sha1, Digest.hash(:sha1, @content)})
      end

      assert_raise ArgumentError, ~r/the ready digest is of :sha256/, fn ->
        Cmsex.digest({:digest, :sha256, Digest.hash(:sha256, @content)}, digest: :sha512)
      end

      assert_raise ArgumentError, ~r/unknown option :key/, fn ->
        Cmsex.verify_digest(Cmsex.digest!(@content), key: "k")
      end
    end
  end

  describe "verify_digest/2" do
    test "RFC 4134 6.0, SHA-1, with allow_sha1" do
      cms = rfc4134("6.0.bin")
      assert error(Cmsex.verify_digest(cms)) == {:weak_algorithm, :sha1}

      assert {:ok, %DigestedData{digest_algorithm: :sha1, content: content}} =
               Cmsex.verify_digest(cms, allow_sha1: true)

      assert content == rfc4134("ExContent.bin")
    end

    defp digested(alg, digest, version \\ 0) do
      message(:digested_data, [
        {:int, version},
        alg,
        {:seq, [{:oid, :data}, {:explicit, 0, {:octets, @content}}]},
        {:octets, digest}
      ])
    end

    test "MD5 is never taken; an unknown algorithm is unsupported" do
      cms = digested({:seq, [{:oid, :md5}, :null]}, :crypto.hash(:md5, @content))
      assert error(Cmsex.verify_digest(cms, allow_sha1: true)) == {:weak_algorithm, :md5}

      cms = digested({:seq, [{:oid, {1, 2, 3}}]}, "x")
      assert error(Cmsex.verify_digest(cms)) == {:unsupported_algorithm, {1, 2, 3}}

      cms = digested({:seq, [{:oid, :sha256}, {:int, 1}]}, "x")
      assert reason(Cmsex.verify_digest(cms)) == :malformed
    end

    test "NULL parameters and a version that is off are taken" do
      digest = Digest.hash(:sha256, @content)
      assert {:ok, _} = Cmsex.verify_digest(digested({:seq, [{:oid, :sha256}, :null]}, digest))

      assert {:ok, %DigestedData{deviations: [:digested_data_version]}} =
               Cmsex.verify_digest(digested({:seq, [{:oid, :sha256}]}, digest, 2))
    end

    test "another type of message" do
      cms = Cmsex.encrypt_with_key!(@content, kek(32))
      assert reason(Cmsex.verify_digest(cms)) == :unsupported_content_type
      assert reason(Cmsex.verify_digest("not a message")) == reason(Cmsex.decode("not a message"))
    end
  end

  ## AuthenticatedData

  describe "mac/3 and verify_mac/2 with a KEK" do
    test "every HMAC, the MAC over the content" do
      for {mac, hash, size} <- [
            {:hmac_sha224, :sha224, 32},
            {:hmac_sha256, :sha256, 32},
            {:hmac_sha384, :sha384, 48},
            {:hmac_sha512, :sha512, 64}
          ] do
        assert {:ok, cms} = Cmsex.mac(@content, Recipient.kek(kek(), "k1"), mac: mac)

        assert {:ok, %AuthenticatedData{} = ad} = Cmsex.decode(cms)
        assert ad.version == 0
        assert ad.mac_algorithm == mac
        assert {ad.digest_algorithm, ad.authenticated_attributes} == {nil, nil}
        assert {ad.content_type, ad.content} == {:data, @content}
        assert [%RecipientInfo{type: :kek, rid: {:kek, "k1"}} = info] = ad.recipient_infos

        # The key is as long as the hash, 32 bytes for SHA-224, and the MAC
        # is over the content octets (RFC 5652, 9.2).
        assert {:ok, key} = KeyWrap.unwrap(kek(), info.encrypted_key)
        assert byte_size(key) == size
        assert ad.mac == hmac(hash, key, @content)

        # RFC 4231, 3.1: NULL parameters.
        assert ad.raw.mac_algorithm == {OID.oid(mac), {0x05, <<>>, <<5, 0>>}}

        assert {:ok, %Authenticated{} = result} = Cmsex.verify_mac(cms, kek: {"k1", kek()})
        assert {result.content, result.content_type} == {@content, :data}
        assert result.recipient == info
        assert result.message == ad
      end
    end

    test "a wrong key, or a changed content or MAC, all give :invalid_mac" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"))
      {:ok, ad} = Cmsex.decode(cms)

      assert error(Cmsex.verify_mac(cms, kek: {"k1", kek(16)})) == {:invalid_mac, nil}

      assert error(Cmsex.verify_mac(cms, kek: {"k1", :binary.copy(<<1>>, 32)})) ==
               {:invalid_mac, nil}

      assert error(Cmsex.verify_mac(flip_in(cms, "dawn"), kek: {"k1", kek()})) ==
               {:invalid_mac, nil}

      assert error(Cmsex.verify_mac(flip_in(cms, ad.mac), kek: {"k1", kek()})) ==
               {:invalid_mac, nil}

      [info] = ad.recipient_infos
      changed = flip_in(cms, info.encrypted_key)
      assert error(Cmsex.verify_mac(changed, kek: {"k1", kek()})) == {:invalid_mac, nil}
    end

    test "no recipient for the credentials" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"))
      assert reason(Cmsex.verify_mac(cms, kek: {"k2", kek()})) == :recipient_not_found
      assert reason(Cmsex.verify_mac(cms, password: "pw")) == :recipient_not_found
    end

    test "the MAC key itself" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"))
      {:ok, %AuthenticatedData{recipient_infos: [info]}} = Cmsex.decode(cms)
      {:ok, key} = KeyWrap.unwrap(kek(), info.encrypted_key)

      assert {:ok, %Authenticated{recipient: nil}} = Cmsex.verify_mac(cms, mac_key: key)
      assert reason(Cmsex.verify_mac(cms, mac_key: binary_part(key, 0, 31))) == :invalid_mac
    end

    test "PEM, and an AES key wrap with padding" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(24), "k1", key_wrap: :aes192_wrap_pad))
      pem = PEM.encode(cms)
      assert {:ok, %Authenticated{}} = Cmsex.verify_mac(pem, kek: {"k1", kek(24)})
    end
  end

  describe "mac/3 with other recipients" do
    setup do
      %{ca: TestPKI.cert({:p256, :ca}, ca: true)}
    end

    test "a password" do
      recipient = Recipient.password("correct horse", iterations: 1000)
      cms = Cmsex.mac!(@content, recipient, mac: :hmac_sha512)

      assert {:ok, %Authenticated{recipient: %{type: :password}}} =
               Cmsex.verify_mac(cms, password: "correct horse")

      assert reason(Cmsex.verify_mac(cms, password: "wrong horse")) == :invalid_mac
    end

    test "certificates: RSA-OAEP, ECDH and X25519", %{ca: ca} do
      for name <- [:rsa2048, :p256, :p384, :brainpool256, :x25519, :x448] do
        party = party(name, ca)
        cms = Cmsex.mac!(@content, party.cert)
        assert {:ok, %Authenticated{content: @content}} = Cmsex.verify_mac(cms, party.opts)

        changed = flip_in(cms, "dawn")
        assert reason(Cmsex.verify_mac(changed, party.opts)) == :invalid_mac
      end
    end

    test "many recipients, each verifies", %{ca: ca} do
      bob = party(:p256, ca)

      recipients = [
        bob.cert,
        Recipient.kek(kek(), "k1"),
        Recipient.password("pw", iterations: 10)
      ]

      cms = Cmsex.mac!(@content, recipients)

      assert {:ok, %AuthenticatedData{recipient_infos: infos}} = Cmsex.decode(cms)
      assert Enum.map(infos, & &1.type) == [:key_agreement, :kek, :password]

      assert {:ok, _} = Cmsex.verify_mac(cms, bob.opts)
      assert {:ok, _} = Cmsex.verify_mac(cms, kek: {"k1", kek()})
      assert {:ok, _} = Cmsex.verify_mac(cms, password: "pw")
    end

    test "a recipient that cannot be used carries its position", %{ca: ca} do
      weak = party(:rsa1024, ca)

      assert {:error, %Error{reason: :weak_key, recipient: 1}} =
               Cmsex.mac(@content, [Recipient.kek(kek(), "k1"), weak.cert])

      signer = TestPKI.cert(:ed25519)

      assert {:error, %Error{reason: :invalid_recipient, detail: :key_type, recipient: 0}} =
               Cmsex.mac(@content, signer)
    end

    test "the OriginatorInfo", %{ca: ca} do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"), certificates: [ca])
      assert {:ok, %AuthenticatedData{certificates: [^ca], version: 0}} = Cmsex.decode(cms)
      assert {:ok, _} = Cmsex.verify_mac(cms, kek: {"k1", kek()})

      assert reason(Cmsex.mac(@content, Recipient.kek(kek(), "k1"), certificates: ["x"])) ==
               :invalid_certificate
    end
  end

  describe "authenticated attributes" do
    test "written for another content type, with content-type and message-digest" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"), content_type: {1, 2, 3, 4})
      {:ok, ad} = Cmsex.decode(cms)

      assert ad.digest_algorithm == :sha256
      assert Enum.map(ad.authenticated_attributes, & &1.type) == [:content_type, :message_digest]

      # The MAC is over the DER of the attributes, with the SET OF tag.
      [info] = ad.recipient_infos
      {:ok, key} = KeyWrap.unwrap(kek(), info.encrypted_key)
      assert ad.mac == hmac(:sha256, key, DER.retag(ad.raw.authenticated_attributes, 0x31))

      assert {:ok, %Authenticated{content_type: {1, 2, 3, 4}}} =
               Cmsex.verify_mac(cms, kek: {"k1", kek()})
    end

    test "attributes of the caller, and the digest of the HMAC or another" do
      extra = Attribute.signing_time(~U[2026-10-24 10:00:00Z])

      cms =
        Cmsex.mac!(@content, Recipient.kek(kek(), "k1"),
          mac: :hmac_sha384,
          authenticated_attributes: [extra]
        )

      {:ok, ad} = Cmsex.decode(cms)
      assert ad.digest_algorithm == :sha384
      assert extra in ad.authenticated_attributes
      assert {:ok, _} = Cmsex.verify_mac(cms, kek: {"k1", kek()})

      cms =
        Cmsex.mac!(@content, Recipient.kek(kek(), "k1"),
          authenticated_attributes: [extra],
          digest: :sha512
        )

      assert {:ok, %AuthenticatedData{digest_algorithm: :sha512, mac_algorithm: :hmac_sha256}} =
               Cmsex.decode(cms)

      assert {:ok, _} = Cmsex.verify_mac(cms, kek: {"k1", kek()})
    end

    test "a changed content gives :digest_mismatch once the MAC has checked" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"), content_type: {1, 2, 3})

      assert reason(Cmsex.verify_mac(flip_in(cms, "dawn"), kek: {"k1", kek()})) ==
               :digest_mismatch

      {:ok, ad} = Cmsex.decode(cms)
      changed = flip_in(cms, ad.raw.authenticated_attributes)
      assert reason(Cmsex.verify_mac(changed, kek: {"k1", kek()})) in [:invalid_mac, :malformed]
    end

    test "the library writes content-type and message-digest itself" do
      for type <- [:content_type, :message_digest] do
        attribute = %Attribute{type: type, values: [DER.encode({:octets, "x"})]}

        assert_raise ArgumentError, ~r/written by the library/, fn ->
          Cmsex.mac(@content, Recipient.kek(kek(), "k1"), authenticated_attributes: [attribute])
        end
      end
    end
  end

  describe "detached content, streams and ready digests" do
    test "detached" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"), detached: true)
      assert {:ok, %AuthenticatedData{content: nil}} = Cmsex.decode(cms)

      opts = [kek: {"k1", kek()}]
      assert reason(Cmsex.verify_mac(cms, opts)) == :content_required

      assert {:ok, %Authenticated{content: nil}} =
               Cmsex.verify_mac(cms, opts ++ [content: @content])

      assert {:ok, _} = Cmsex.verify_mac(cms, opts ++ [content: {:stream, [@content]}])
      assert reason(Cmsex.verify_mac(cms, opts ++ [content: "other"])) == :invalid_mac

      # Without attributes, the MAC needs the content itself.
      ready = {:digest, :sha256, Digest.hash(:sha256, @content)}
      assert reason(Cmsex.verify_mac(cms, opts ++ [content: ready])) == :content_required

      attached = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"))

      assert reason(Cmsex.verify_mac(attached, opts ++ [content: @content])) ==
               :unexpected_content
    end

    test "a stream, read once" do
      chunks = ["Attack at dawn, ", "or at least ", "before lunch."]
      cms = Cmsex.mac!({:stream, chunks}, Recipient.kek(kek(), "k1"))

      assert {:ok, %AuthenticatedData{content: nil, authenticated_attributes: nil}} =
               Cmsex.decode(cms)

      assert {:ok, _} = Cmsex.verify_mac(cms, kek: {"k1", kek()}, content: @content)

      assert_raise ArgumentError, ~r/only be detached/, fn ->
        Cmsex.mac({:stream, chunks}, Recipient.kek(kek(), "k1"), detached: false)
      end
    end

    test "a ready digest makes authenticated attributes" do
      ready = {:digest, :sha384, Digest.hash(:sha384, @content)}
      cms = Cmsex.mac!(ready, Recipient.kek(kek(), "k1"))
      {:ok, ad} = Cmsex.decode(cms)
      assert {ad.digest_algorithm, ad.mac_algorithm, ad.content} == {:sha384, :hmac_sha256, nil}

      opts = [kek: {"k1", kek()}]
      assert {:ok, _} = Cmsex.verify_mac(cms, opts ++ [content: @content])
      assert {:ok, _} = Cmsex.verify_mac(cms, opts ++ [content: ready])

      other = {:digest, :sha256, Digest.hash(:sha256, @content)}

      assert error(Cmsex.verify_mac(cms, opts ++ [content: other])) ==
               {:content_required, :sha384}

      assert reason(Cmsex.verify_mac(cms, opts ++ [content: "other"])) == :digest_mismatch

      assert_raise ArgumentError,
                   ~r/:digest is :sha256, but the ready digest is of :sha384/,
                   fn ->
                     Cmsex.mac(ready, Recipient.kek(kek(), "k1"), digest: :sha256)
                   end

      # Before anything is done with the recipients.
      assert_raise ArgumentError, ~r/:digest is :sha256/, fn ->
        Cmsex.mac(ready, "not a certificate", digest: :sha256)
      end

      assert_raise ArgumentError, ~r/must be of SHA-2, got: :sha1/, fn ->
        Cmsex.mac({:digest, :sha1, Digest.hash(:sha1, @content)}, Recipient.kek(kek(), "k1"))
      end
    end
  end

  # Messages built here, for what the library does not write: a KEK
  # recipient of kek() with `key`, and the MAC over what the fields give.
  describe "messages from elsewhere" do
    # AES key wrap, with padding for a key it cannot take otherwise.
    defp kekri(mac_key) do
      {wrap, wrapped} =
        if byte_size(mac_key) >= 16 and rem(byte_size(mac_key), 8) == 0,
          do: {:aes256_wrap, KeyWrap.wrap(kek(), mac_key)},
          else: {:aes256_wrap_pad, KeyWrap.wrap_with_padding(kek(), mac_key)}

      {:constructed, 0xA2,
       [{:int, 4}, {:seq, [{:octets, "k1"}]}, {:seq, [{:oid, wrap}]}, {:octets, wrapped}]}
    end

    defp auth_data(opts) do
      key = Keyword.get(opts, :key, :binary.copy(<<7>>, 32))
      hash = Keyword.get(opts, :hash, :sha256)
      attributes = Keyword.get(opts, :attributes)
      set = attributes && attribute_set(attributes)
      digest_alg = Keyword.get(opts, :digest_alg, attributes && {:seq, [{:oid, :sha256}]})
      mac = Keyword.get_lazy(opts, :mac, fn -> hmac(hash, key, set || @content) end)

      message(
        :auth_data,
        [
          {:int, Keyword.get(opts, :version, 0)},
          {:set, [kekri(key)]},
          Keyword.get_lazy(opts, :mac_alg, fn -> Algorithm.mac_identifier(hash) end)
        ] ++
          if(digest_alg, do: [{:raw, DER.retag(DER.encode(digest_alg), 0xA1)}], else: []) ++
          [
            {:seq,
             [
               {:oid, Keyword.get(opts, :content_type, :data)},
               {:explicit, 0, {:octets, @content}}
             ]}
          ] ++
          if(set, do: [{:raw, DER.retag(set, 0xA2)}], else: []) ++
          [{:octets, mac}]
      )
    end

    defp verify(cms, opts \\ []), do: Cmsex.verify_mac(cms, [kek: {"k1", kek()}] ++ opts)

    defp attributes(type \\ :data, digest \\ Digest.hash(:sha256, @content)),
      do: [Attribute.content_type(type), message_digest(digest)]

    test "the one built here verifies" do
      assert {:ok, %Authenticated{}} = verify(auth_data([]))
      assert {:ok, %Authenticated{}} = verify(auth_data(attributes: attributes()))
    end

    test "HMAC-SHA1, under both OIDs, absent or NULL, needs no allow_sha1" do
      for alg <- [
            {:seq, [{:oid, :hmac_sha1}]},
            {:seq, [{:oid, :hmac_sha1}, :null]},
            {:seq, [{:oid, :hmac_with_sha1}, :null]}
          ] do
        assert {:ok, %Authenticated{}} = verify(auth_data(hash: :sha1, mac_alg: alg))
      end

      alg = {:seq, [{:oid, :hmac_sha256}]}
      assert {:ok, _} = verify(auth_data(mac_alg: alg))
    end

    test "unknown or malformed MAC algorithms" do
      cms = auth_data(mac_alg: {:seq, [{:oid, {1, 2, 3}}]})
      assert error(verify(cms)) == {:unsupported_algorithm, {1, 2, 3}}

      cms = auth_data(mac_alg: {:seq, [{:oid, :hmac_sha256}, {:int, 1}]})
      assert reason(verify(cms)) == :malformed
    end

    test "a SHA-1 digest needs allow_sha1; MD5 is never taken" do
      sha1 = attributes(:data, Digest.hash(:sha1, @content))
      cms = auth_data(attributes: sha1, digest_alg: {:seq, [{:oid, :sha1}]})
      assert error(verify(cms)) == {:weak_algorithm, :sha1}
      assert {:ok, _} = verify(cms, allow_sha1: true)

      md5 = attributes(:data, :crypto.hash(:md5, @content))
      cms = auth_data(attributes: md5, digest_alg: {:seq, [{:oid, :md5}]})
      assert error(verify(cms, allow_sha1: true)) == {:weak_algorithm, :md5}
    end

    test "digestAlgorithm and authAttrs go together" do
      cms = auth_data(digest_alg: {:seq, [{:oid, :sha256}]})
      assert error(verify(cms)) == {:malformed, :digest_algorithm}

      cms = auth_data(attributes: attributes(), digest_alg: false)
      assert error(verify(cms)) == {:malformed, :digest_algorithm}
    end

    test "the attributes, checked once the MAC has" do
      cms = auth_data(content_type: {1, 2, 3})
      assert error(verify(cms)) == {:missing_attribute, :content_type}

      cms = auth_data(attributes: attributes({1, 2, 3}))
      assert reason(verify(cms)) == :content_type_mismatch

      cms = auth_data(attributes: [Attribute.content_type(:data)])
      assert error(verify(cms)) == {:missing_attribute, :message_digest}

      cms = auth_data(attributes: [message_digest(Digest.hash(:sha256, @content))])
      assert error(verify(cms)) == {:missing_attribute, :content_type}

      cms = auth_data(attributes: attributes(:data, "not the digest"))
      assert reason(verify(cms)) == :digest_mismatch

      twice = %Attribute{
        type: :message_digest,
        values: [DER.encode({:octets, "a"}), DER.encode({:octets, "b"})]
      }

      cms = auth_data(attributes: [Attribute.content_type(:data), twice])
      assert error(verify(cms)) == {:invalid_attribute, :message_digest}

      # The same message with a MAC that does not check says only that.
      cms = auth_data(attributes: attributes({1, 2, 3}), mac: :binary.copy(<<0>>, 32))
      assert reason(verify(cms)) == :invalid_mac
    end

    test "a key shorter than 16 bytes is not taken; a long one is" do
      for {size, result} <- [
            {8, :invalid_mac},
            {15, :invalid_mac},
            {16, :ok},
            {20, :ok},
            {128, :ok}
          ] do
        cms = auth_data(key: :binary.copy(<<9>>, size))

        case result do
          :ok -> assert {:ok, _} = verify(cms)
          reason -> assert reason(verify(cms)) == reason
        end
      end
    end

    test "a truncated MAC does not check" do
      key = :binary.copy(<<7>>, 32)
      mac = hmac(:sha256, key, @content)
      assert reason(verify(auth_data(mac: binary_part(mac, 0, 16)))) == :invalid_mac
      assert reason(verify(auth_data(mac: mac <> <<0>>))) == :invalid_mac
    end

    test "another type of message" do
      cms = Cmsex.encrypt!(@content, Recipient.kek(kek(), "k1"))
      assert reason(verify(cms)) == :unsupported_content_type
    end
  end

  # RFC 3218: a padding that does not check gives a random key, and the
  # failure is that of the MAC.
  describe "PKCS #1 v1.5 key transport" do
    setup do
      ca = TestPKI.cert({:p256, :ca}, ca: true)
      bob = party(:rsa2048, ca)
      {:ok, cert} = Certificate.parse(bob.cert)
      {:rsa, n, e} = cert.public_key
      %{bob: bob, cert: cert, n: n, e: e}
    end

    defp v15_auth_data(cert, encrypted_key, key) do
      ktri =
        {:seq,
         [
           {:int, 0},
           {:seq, [{:raw, cert.issuer}, {:int, cert.serial}]},
           {:seq, [{:oid, :rsa_encryption}, :null]},
           {:octets, encrypted_key}
         ]}

      message(:auth_data, [
        {:int, 0},
        {:set, [ktri]},
        Algorithm.mac_identifier(:sha256),
        {:seq, [{:oid, :data}, {:explicit, 0, {:octets, @content}}]},
        {:octets, hmac(:sha256, key, @content)}
      ])
    end

    test "a good padding, and bad ones that fail as a wrong key", ctx do
      %{bob: bob, cert: cert, n: n, e: e} = ctx
      key = :crypto.strong_rand_bytes(32)
      encrypted = :crypto.public_encrypt(:rsa, key, [e, n], rsa_padding: :rsa_pkcs1_padding)
      assert {:ok, _} = Cmsex.verify_mac(v15_auth_data(cert, encrypted, key), bob.opts)

      ps = :binary.copy(<<0xAB>>, 256 - 3 - 32)

      bad =
        :crypto.public_encrypt(:rsa, <<0, 1, ps::binary, 0, key::binary>>, [e, n],
          rsa_padding: :rsa_no_padding
        )

      other =
        :crypto.public_encrypt(:rsa, :binary.copy(<<1>>, 32), [e, n],
          rsa_padding: :rsa_pkcs1_padding
        )

      for encrypted <- [bad, other, <<1, 2, 3>>] do
        assert error(Cmsex.verify_mac(v15_auth_data(cert, encrypted, key), bob.opts)) ==
                 {:invalid_mac, nil}
      end
    end
  end

  describe "options" do
    test "credentials are required, and checked" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"))

      assert_raise ArgumentError, ~r/:password or :mac_key/, fn -> Cmsex.verify_mac(cms) end

      assert_raise ArgumentError, ~r/unknown option :content_key/, fn ->
        Cmsex.verify_mac(cms, content_key: kek())
      end

      assert_raise ArgumentError, ~r/:mac_key must be a non-empty binary/, fn ->
        Cmsex.verify_mac(cms, mac_key: "")
      end

      assert_raise ArgumentError, ~r/:key and :certificate go together/, fn ->
        Cmsex.verify_mac(cms, key: "k")
      end
    end

    test "writing options" do
      kek = Recipient.kek(kek(), "k1")

      assert_raise ArgumentError, ~r/:mac must be one of/, fn ->
        Cmsex.mac(@content, kek, mac: :hmac_sha1)
      end

      assert_raise ArgumentError, ~r/unknown option :cipher/, fn ->
        Cmsex.mac(@content, kek, cipher: :aes128_cbc)
      end

      assert_raise ArgumentError, ~r/:unauthenticated_attributes must be/, fn ->
        Cmsex.mac(@content, kek, unauthenticated_attributes: ["x"])
      end

      assert_raise ArgumentError, ~r/expected a Cmsex.Recipient/, fn ->
        Cmsex.mac(@content, [])
      end
    end

    test "unauthenticated attributes are written, and not covered" do
      extra = Attribute.content_hint(:data, "a note")
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"), unauthenticated_attributes: [extra])
      assert {:ok, %AuthenticatedData{unauthenticated_attributes: [^extra]}} = Cmsex.decode(cms)
      assert {:ok, _} = Cmsex.verify_mac(cms, kek: {"k1", kek()})

      changed = flip_in(cms, "a note")
      assert {:ok, _} = Cmsex.verify_mac(changed, kek: {"k1", kek()})
    end

    test "the bangs" do
      cms = Cmsex.mac!(@content, Recipient.kek(kek(), "k1"))
      assert %Authenticated{} = Cmsex.verify_mac!(cms, kek: {"k1", kek()})
      assert_raise Error, "invalid MAC", fn -> Cmsex.verify_mac!(cms, kek: {"k1", kek(16)}) end

      assert %DigestedData{} = Cmsex.verify_digest!(Cmsex.digest!(@content))

      assert_raise Error, ~r/digest does not match/, fn ->
        Cmsex.verify_digest!(flip_in(Cmsex.digest!(@content), "dawn"))
      end

      assert_raise Error, ~r/recipient 0: weak key/, fn ->
        Cmsex.mac!(@content, party(:rsa1024, TestPKI.cert({:p256, :ca}, ca: true)).cert)
      end
    end
  end
end
