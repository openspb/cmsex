defmodule Cmsex.EncryptTest do
  use ExUnit.Case, async: true

  alias Cmsex.{
    Attribute,
    Certificate,
    Cipher,
    Decrypted,
    DER,
    EncryptedData,
    EnvelopedData,
    Error,
    KDF,
    KeyWrap,
    PasswordWrap,
    Recipient,
    RecipientInfo,
    TestPKI
  }

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)

  @content "Attack at dawn, or at least before lunch."

  @aead [:aes128_gcm, :aes192_gcm, :aes256_gcm, :aes128_ccm, :aes192_ccm, :aes256_ccm] ++
          [:chacha20_poly1305]

  @ciphers [:aes128_cbc, :aes192_cbc, :aes256_cbc | @aead]

  defp rfc4134(name), do: File.read!(Path.join(@rfc4134, name))

  setup_all do
    %{ca: TestPKI.cert({:p256, :ca}, ca: true)}
  end

  # A recipient: its certificate, with keyEncipherment or keyAgreement, and
  # its key in DER. X25519 and X448 cannot sign their own certificate.
  defp party(name, ctx, opts \\ []) do
    kind = kind(name)
    usage = if kind == :rsa, do: [2], else: [4]
    issuer = if kind in [:x25519, :x448], do: [issuer: {ctx.ca, {:p256, :ca}}], else: []
    cert = TestPKI.cert(name, Keyword.merge([key_usage: usage] ++ issuer, opts))

    key =
      case TestPKI.key(name) do
        {public, _private} = pair when is_binary(public) -> TestPKI.montgomery_pkcs8(kind, pair)
        record -> TestPKI.pkcs8(record)
      end

    %{cert: cert, key: key, opts: [key: key, certificate: cert]}
  end

  defp kind({name, _suffix}), do: kind(name)
  defp kind(name) when name in [:x25519, :x448], do: name
  defp kind(name), do: if(name in [:rsa1024, :rsa2048, :rsa3072], do: :rsa, else: :ec)

  defp reason({:error, %Error{reason: reason}}), do: reason
  defp content({:ok, %Decrypted{content: content}}), do: content

  defp kek(size \\ 32), do: :binary.copy(<<size>>, size)

  ## Messages built here, for what the library does not write

  defp message(type, fields),
    do: DER.encode({:seq, [{:oid, type}, {:explicit, 0, {:seq, fields}}]})

  defp kekri(key, cek, id \\ "k1") do
    wrap = :"aes#{byte_size(key) * 8}_wrap"

    {:constructed, 0xA2,
     [
       {:int, 4},
       {:seq, [{:octets, id}]},
       {:seq, [{:oid, wrap}]},
       {:octets, KeyWrap.wrap(key, cek)}
     ]}
  end

  defp eci(cipher, ciphertext, type \\ :data),
    do: {:seq, [{:oid, type}, Cipher.identifier(cipher), {:primitive, 0x80, ciphertext}]}

  defp attribute_set(attributes),
    do: DER.encode({:set, Enum.map(attributes, &{:raw, DER.encode(Attribute.to_term(&1))})})

  # An AuthEnvelopedData with a KEK recipient, its authAttrs as given.
  defp auth_enveloped(opts) do
    cipher = Cipher.new(:aes256_gcm)
    cek = Cipher.random_key(cipher)
    attributes = Keyword.get(opts, :attributes)
    set = attributes && attribute_set(attributes)
    {ciphertext, tag} = Cipher.encrypt(cipher, cek, @content, set || <<>>)

    message(
      :auth_enveloped_data,
      [
        {:int, 0},
        {:set, [kekri(kek(), cek)]},
        eci(cipher, ciphertext, Keyword.get(opts, :content_type, :data))
      ] ++ if(set, do: [{:raw, DER.retag(set, 0xA1)}], else: []) ++ [{:octets, tag}]
    )
  end

  defp flip_in(cms, part) do
    {offset, _} = :binary.match(cms, part)
    <<before::binary-size(offset), byte, rest::binary>> = cms
    <<before::binary, Bitwise.bxor(byte, 1), rest::binary>>
  end

  ## Round trips

  describe "key transport" do
    test "RSA-OAEP with every cipher, EnvelopedData or AuthEnvelopedData", ctx do
      bob = party(:rsa2048, ctx)

      for cipher <- @ciphers do
        assert {:ok, cms} = Cmsex.encrypt(@content, bob.cert, cipher: cipher)
        assert {:ok, %EnvelopedData{} = ed} = Cmsex.decode(cms)
        assert ed.type == if(cipher in @aead, do: :auth_enveloped_data, else: :enveloped_data)
        assert ed.version == 0
        assert ed.content_encryption_algorithm == cipher
        assert ed.deviations == []
        assert ed.mac != nil == cipher in @aead

        assert {:ok, %Decrypted{} = decrypted} = Cmsex.decrypt(cms, bob.opts)
        assert decrypted.content == @content
        assert decrypted.content_type == :data
        assert decrypted.recipient == hd(ed.recipient_infos)
        assert decrypted.message.type == ed.type
      end
    end

    test "each OAEP digest, with MGF1 of the same; SHA-1 writes the defaults", ctx do
      bob = party(:rsa2048, ctx)

      for digest <- [:sha1, :sha224, :sha256, :sha384, :sha512] do
        recipient = Recipient.certificate(bob.cert, oaep_digest: digest)
        cms = Cmsex.encrypt!(@content, recipient)
        %EnvelopedData{recipient_infos: [ri]} = Cmsex.decode!(cms)

        assert ri.type == :key_transport
        assert ri.key_encryption_algorithm == :rsaes_oaep
        assert ri.deviations == []
        {_oid, params} = ri.raw.key_encryption_algorithm

        assert Cmsex.Algorithm.oaep_params(params) ==
                 {:ok, %{hash: digest, mgf_hash: digest, label: <<>>}}

        if digest == :sha1, do: assert(params == {0x30, <<>>, <<0x30, 0>>})
        assert content(Cmsex.decrypt(cms, bob.opts)) == @content
      end
    end

    test "the subject key identifier makes a version 2 recipient", ctx do
      bob = party(:rsa2048, ctx)
      recipient = Recipient.certificate(bob.cert, identifier: :subject_key_identifier)
      cms = Cmsex.encrypt!(@content, recipient)

      {:ok, cert} = Certificate.parse(bob.cert)
      assert %EnvelopedData{version: 2, recipient_infos: [ri]} = Cmsex.decode!(cms)
      assert ri.version == 2
      assert ri.rid == {:subject_key_identifier, cert.subject_key_identifier}
      assert content(Cmsex.decrypt(cms, bob.opts)) == @content
    end

    test "issuer and serial number name the certificate", ctx do
      bob = party(:rsa2048, ctx)
      {:ok, cert} = Certificate.parse(bob.cert)
      %EnvelopedData{recipient_infos: [ri]} = Cmsex.decode!(Cmsex.encrypt!(@content, bob.cert))
      assert ri.rid == {:issuer_and_serial, cert.issuer, cert.serial}
    end

    test "a 3072-bit key", ctx do
      bob = party(:rsa3072, ctx)
      assert content(Cmsex.decrypt(Cmsex.encrypt!(@content, bob.cert), bob.opts)) == @content
    end
  end

  describe "key agreement" do
    test "the defaults of each curve", ctx do
      cases = [
        {:p256, :std_dh_sha256kdf},
        {:p384, :std_dh_sha384kdf},
        {:p521, :std_dh_sha512kdf},
        {:brainpool256, :std_dh_sha256kdf},
        {:x25519, :std_dh_hkdf_sha256},
        {:x448, :std_dh_hkdf_sha512}
      ]

      for {name, scheme} <- cases, cipher <- [:aes128_cbc, :aes256_gcm] do
        bob = party(name, ctx)
        cms = Cmsex.encrypt!(@content, bob.cert, cipher: cipher)
        %EnvelopedData{recipient_infos: [ri]} = ed = Cmsex.decode!(cms)

        assert ed.version == if(cipher == :aes128_cbc, do: 2, else: 0)
        assert ri.type == :key_agreement
        assert ri.version == 3
        assert ri.key_encryption_algorithm == scheme

        assert ri.key_wrap_algorithm ==
                 if(cipher == :aes128_cbc, do: :aes128_wrap, else: :aes256_wrap)

        assert ri.ukm == nil
        assert ri.deviations == []

        alg = if kind(name) == :ec, do: :ec_public_key, else: kind(name)
        assert {:public_key, ^alg, _public} = ri.originator
        # The parameters of id-ecPublicKey are left out (RFC 5753, 7.1.2).
        assert {_oid, nil} = ri.raw.originator_key

        assert content(Cmsex.decrypt(cms, bob.opts)) == @content
      end
    end

    test "each scheme, key wrap and a ukm", ctx do
      bob = party(:p256, ctx)

      schemes =
        [:std_dh_sha256kdf, :std_dh_sha384kdf, :std_dh_sha512kdf] ++
          [:std_dh_hkdf_sha256, :std_dh_hkdf_sha384, :std_dh_hkdf_sha512]

      wraps = [:aes128_wrap, :aes192_wrap, :aes256_wrap, :aes128_wrap_pad, :aes256_wrap_pad]

      for scheme <- schemes, wrap <- wraps, ukm <- [nil, "some user keying material"] do
        recipient =
          Recipient.certificate(bob.cert, key_agreement: scheme, key_wrap: wrap, ukm: ukm)

        cms = Cmsex.encrypt!(@content, recipient)
        %EnvelopedData{recipient_infos: [ri]} = Cmsex.decode!(cms)

        assert {ri.key_encryption_algorithm, ri.key_wrap_algorithm, ri.ukm} == {scheme, wrap, ukm}
        assert content(Cmsex.decrypt(cms, bob.opts)) == @content
      end
    end

    test "X25519 and X448 with a ukm, which is also the HKDF salt", ctx do
      for name <- [:x25519, :x448] do
        bob = party(name, ctx)
        cms = Cmsex.encrypt!(@content, Recipient.certificate(bob.cert, ukm: "salt and pepper"))
        assert content(Cmsex.decrypt(cms, bob.opts)) == @content
      end
    end

    test "the subject key identifier, as rKeyId", ctx do
      bob = party(:p384, ctx)
      {:ok, cert} = Certificate.parse(bob.cert)
      recipient = Recipient.certificate(bob.cert, identifier: :subject_key_identifier)
      cms = Cmsex.encrypt!(@content, recipient)

      %EnvelopedData{recipient_infos: [ri]} = Cmsex.decode!(cms)
      assert [{{:subject_key_identifier, ski}, _}] = ri.recipient_encrypted_keys
      assert ski == cert.subject_key_identifier
      assert content(Cmsex.decrypt(cms, bob.opts)) == @content
    end

    test "a static key of the sender, named by its certificate (RFC 5753, 3.1.2)", ctx do
      bob = party({:p256, :bob}, ctx)
      alice_cert = TestPKI.cert({:p256, :alice}, key_usage: [4])
      {:ok, alice} = Certificate.parse(alice_cert)
      {:ok, %{public_key: {:ec, :secp256r1, bob_point}} = bob_cert} = Certificate.parse(bob.cert)
      {:ec, :secp256r1, alice_private, _} = TestPKI.private({:p256, :alice})

      cipher = Cipher.new(:aes128_cbc)
      cek = Cipher.random_key(cipher)
      shared = :crypto.compute_key(:ecdh, bob_point, alice_private, :secp256r1)
      wrap_id = DER.encode({:seq, [{:oid, :aes128_wrap}]})
      info = DER.encode({:seq, [{:raw, wrap_id}, {:explicit, 2, {:octets, <<128::32>>}}]})
      kek = KDF.x963(:sha256, shared, info, 16)
      {ciphertext, nil} = Cipher.encrypt(cipher, cek, @content)

      kari =
        {:constructed, 0xA1,
         [
           {:int, 3},
           {:explicit, 0, {:seq, [{:raw, alice.issuer}, {:int, alice.serial}]}},
           {:seq, [{:oid, :std_dh_sha256kdf}, {:raw, wrap_id}]},
           {:seq,
            [
              {:seq,
               [
                 {:seq, [{:raw, bob_cert.issuer}, {:int, bob_cert.serial}]},
                 {:octets, KeyWrap.wrap(kek, cek)}
               ]}
            ]}
         ]}

      build = fn originator ->
        message(
          :enveloped_data,
          [{:int, 2}] ++ originator ++ [{:set, [kari]}, eci(cipher, ciphertext)]
        )
      end

      certs = {:raw, DER.retag(DER.encode({:set, [{:raw, alice_cert}]}), 0xA0)}
      cms = build.([{:constructed, 0xA0, [certs]}])

      assert %EnvelopedData{recipient_infos: [ri]} = Cmsex.decode!(cms)
      assert ri.originator == {:issuer_and_serial, alice.issuer, alice.serial}
      assert content(Cmsex.decrypt(cms, bob.opts)) == @content

      # Without the certificate of the sender, there is no key to agree with.
      assert reason(Cmsex.decrypt(build.([]), bob.opts)) == :decryption_failed
    end

    test "a scheme the library does not implement", ctx do
      bob = party(:p256, ctx)
      cms = Cmsex.encrypt!(@content, bob.cert)
      # std_dh_sha256kdf is 1.3.132.1.11.1; 1.3.132.1.15.1 is ECMQV with SHA-256.
      changed =
        :binary.replace(cms, <<6, 6, 43, 129, 4, 1, 11, 1>>, <<6, 6, 43, 129, 4, 1, 15, 1>>)

      assert {:error, %Error{reason: :unsupported_algorithm, detail: {1, 3, 132, 1, 15, 1}}} =
               Cmsex.decrypt(changed, bob.opts)
    end
  end

  describe "KEK recipients" do
    test "each size of key, with and without padding, a date and another attribute" do
      date = ~U[2026-10-24 10:20:30.123456Z]
      other = {{1, 2, 3, 4}, DER.encode({:utf8, "other"})}

      for size <- [16, 24, 32], pad <- [false, true] do
        wrap = if pad, do: :"aes#{size * 8}_wrap_pad", else: :"aes#{size * 8}_wrap"
        key = kek(size)
        recipient = Recipient.kek(key, "key #{size}", key_wrap: wrap, date: date, other: other)
        cms = Cmsex.encrypt!(@content, recipient)

        assert %EnvelopedData{version: 2, recipient_infos: [ri]} = Cmsex.decode!(cms)
        assert ri.type == :kek
        assert ri.version == 4
        assert ri.rid == {:kek, "key #{size}"}
        assert ri.key_encryption_algorithm == wrap
        assert ri.date == ~U[2026-10-24 10:20:30Z]

        decrypted = Cmsex.decrypt!(cms, kek: {"key #{size}", key})
        assert decrypted.content == @content
        assert decrypted.recipient == ri
      end
    end

    test "the identifier finds the recipient; the key opens it" do
      cms = Cmsex.encrypt!(@content, Recipient.kek(kek(), "mine"))

      assert reason(Cmsex.decrypt(cms, kek: {"other", kek()})) == :recipient_not_found
      assert reason(Cmsex.decrypt(cms, kek: {"mine", kek(16)})) == :decryption_failed

      assert reason(Cmsex.decrypt(cms, kek: {"mine", :binary.copy(<<1>>, 32)})) ==
               :decryption_failed
    end
  end

  describe "password recipients" do
    test "each PRF and key-encryption cipher" do
      for prf <- [:hmac_sha224, :hmac_sha256, :hmac_sha384, :hmac_sha512],
          kek_cipher <- [:aes128_cbc, :aes192_cbc, :aes256_cbc] do
        recipient =
          Recipient.password("hunter2", iterations: 1_000, prf: prf, kek_cipher: kek_cipher)

        cms = Cmsex.encrypt!(@content, recipient)

        assert %EnvelopedData{version: 3, recipient_infos: [ri]} = Cmsex.decode!(cms)
        assert ri.type == :password
        assert ri.version == 0
        assert ri.key_encryption_algorithm == :pwri_kek
        assert ri.key_derivation_algorithm == :pbkdf2

        assert content(Cmsex.decrypt(cms, password: "hunter2")) == @content
        assert reason(Cmsex.decrypt(cms, password: "hunter3")) == :decryption_failed
      end
    end

    test "the default iterations, and the limit on them" do
      cms = Cmsex.encrypt!(@content, Recipient.password("pw", salt: "12345678"))
      assert content(Cmsex.decrypt(cms, password: "pw")) == @content

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_iterations}} =
               Cmsex.decrypt(cms, password: "pw", max_iterations: 599_999)

      assert content(Cmsex.decrypt(cms, password: "pw", max_iterations: 600_000)) == @content
    end

    # RFC 3211, 2.2.1: without keyDerivationAlgorithm the password is the
    # key-encryption key; the PRF of PBKDF2-params defaults to hmacWithSHA1,
    # and a keyLength must be the size of that key.
    test "PBKDF2-params and a password that is the key" do
      cipher = Cipher.new(:aes128_cbc)
      cek = Cipher.random_key(cipher)
      {ciphertext, nil} = Cipher.encrypt(cipher, cek, @content)
      kek_cipher = Cipher.new(:aes256_cbc)

      build = fn derivation, kek ->
        wrapped = PasswordWrap.wrap(:aes_256_cbc, kek, kek_cipher.iv, 16, cek)

        pwri =
          {:constructed, 0xA3,
           [{:int, 0}] ++
             derivation ++
             [
               {:seq, [{:oid, :pwri_kek}, Cipher.identifier(kek_cipher)]},
               {:octets, wrapped}
             ]}

        message(:enveloped_data, [{:int, 3}, {:set, [pwri]}, eci(cipher, ciphertext)])
      end

      raw_key = :binary.copy("k", 32)
      assert content(Cmsex.decrypt(build.([], raw_key), password: raw_key)) == @content
      assert reason(Cmsex.decrypt(build.([], raw_key), password: "k")) == :decryption_failed

      pbkdf2 = fn params -> [{:constructed, 0xA0, [{:oid, :pbkdf2}, {:seq, params}]}] end
      sha1_kek = KDF.pbkdf2(:sha1, "pw", "saltsalt", 5, 32)
      cms = build.(pbkdf2.([{:octets, "saltsalt"}, {:int, 5}]), sha1_kek)
      assert content(Cmsex.decrypt(cms, password: "pw")) == @content

      cms = build.(pbkdf2.([{:octets, "saltsalt"}, {:int, 5}, {:int, 32}]), sha1_kek)
      assert content(Cmsex.decrypt(cms, password: "pw")) == @content

      cms = build.(pbkdf2.([{:octets, "saltsalt"}, {:int, 5}, {:int, 16}]), sha1_kek)
      assert reason(Cmsex.decrypt(cms, password: "pw")) == :decryption_failed

      md5 = {:seq, [{:oid, {1, 2, 840, 113_549, 2, 5}}, :null]}
      cms = build.(pbkdf2.([{:octets, "saltsalt"}, {:int, 5}, md5]), sha1_kek)

      assert {:error, %Error{reason: :unsupported_algorithm, detail: {1, 2, 840, 113_549, 2, 5}}} =
               Cmsex.decrypt(cms, password: "pw")
    end
  end

  describe "several recipients" do
    test "each one decrypts, and the recipient found is told", ctx do
      rsa = party(:rsa2048, ctx)
      ec = party(:p384, ctx)
      x = party(:x25519, ctx)

      recipients = [
        rsa.cert,
        ec.cert,
        x.cert,
        Recipient.kek(kek(), "k"),
        Recipient.password("pw", iterations: 1_000)
      ]

      cms = Cmsex.encrypt!(@content, recipients, cipher: :aes256_gcm)
      %EnvelopedData{recipient_infos: infos} = Cmsex.decode!(cms)
      assert length(infos) == 5

      for opts <- [rsa.opts, ec.opts, x.opts, [kek: {"k", kek()}], [password: "pw"]] do
        assert {:ok, %Decrypted{content: @content, recipient: ri}} = Cmsex.decrypt(cms, opts)
        assert ri in infos
      end

      # The password first, then the key, which is the one that opens it.
      opts = [password: "wrong", kek: {"k", kek()}]
      assert {:ok, %Decrypted{recipient: %RecipientInfo{type: :kek}}} = Cmsex.decrypt(cms, opts)
    end

    test "a recipient that is not in the message", ctx do
      cms = Cmsex.encrypt!(@content, party(:rsa2048, ctx).cert)
      other = party({:rsa2048, :other}, ctx)
      ec = party(:p256, ctx)

      assert reason(Cmsex.decrypt(cms, other.opts)) == :recipient_not_found
      assert reason(Cmsex.decrypt(cms, ec.opts)) == :recipient_not_found
      assert reason(Cmsex.decrypt(cms, password: "pw")) == :recipient_not_found
    end
  end

  describe "the message" do
    test "detached encrypted content", ctx do
      bob = party(:rsa2048, ctx)

      for cipher <- [:aes256_cbc, :aes128_gcm] do
        assert {:ok, {cms, ciphertext}} =
                 Cmsex.encrypt(@content, bob.cert, cipher: cipher, detached: true)

        assert %EnvelopedData{encrypted_content: nil} = Cmsex.decode!(cms)
        assert reason(Cmsex.decrypt(cms, bob.opts)) == :content_required
        assert content(Cmsex.decrypt(cms, [content: ciphertext] ++ bob.opts)) == @content
      end

      attached = Cmsex.encrypt!(@content, bob.cert)
      assert reason(Cmsex.decrypt(attached, [content: "x"] ++ bob.opts)) == :unexpected_content
    end

    test "unprotected attributes and OriginatorInfo raise the version", ctx do
      bob = party(:rsa2048, ctx)
      attribute = Attribute.new({1, 2, 3, 4}, [DER.encode({:utf8, "unprotected"})])
      crl = File.read!(Path.expand("../fixtures/generated/ca.crl", __DIR__))

      cms = Cmsex.encrypt!(@content, bob.cert, unprotected_attributes: [attribute])
      assert %EnvelopedData{version: 2, unprotected_attributes: [^attribute]} = Cmsex.decode!(cms)

      cms = Cmsex.encrypt!(@content, bob.cert, certificates: [ctx.ca, ctx.ca], crls: [crl])

      assert %EnvelopedData{version: 2, certificates: [ca], crls: [^crl]} = Cmsex.decode!(cms)
      assert ca == ctx.ca
      assert content(Cmsex.decrypt(cms, bob.opts)) == @content

      gcm =
        Cmsex.encrypt!(@content, bob.cert,
          cipher: :aes128_gcm,
          unprotected_attributes: [attribute]
        )

      assert %EnvelopedData{version: 0, unprotected_attributes: [^attribute]} = Cmsex.decode!(gcm)
      assert content(Cmsex.decrypt(gcm, bob.opts)) == @content
    end

    test "another content type", ctx do
      bob = party(:rsa2048, ctx)

      for cipher <- [:aes256_cbc, :aes256_gcm] do
        cms = Cmsex.encrypt!(@content, bob.cert, cipher: cipher, content_type: :signed_data)
        ed = Cmsex.decode!(cms)
        assert ed.content_type == :signed_data

        if cipher == :aes256_gcm,
          do: assert([%Attribute{type: :content_type}] = ed.authenticated_attributes)

        assert {:ok, %Decrypted{content_type: :signed_data}} = Cmsex.decrypt(cms, bob.opts)
      end
    end

    test "PEM", ctx do
      bob = party(:rsa2048, ctx)
      pem = Cmsex.PEM.encode(Cmsex.encrypt!(@content, bob.cert))
      assert content(Cmsex.decrypt(pem, bob.opts)) == @content
    end

    test "a message of another type", ctx do
      bob = party(:rsa2048, ctx)

      assert reason(Cmsex.decrypt(rfc4134("4.1.bin"), bob.opts)) == :unsupported_content_type

      assert reason(Cmsex.decrypt("not a message", bob.opts)) ==
               reason(Cmsex.decode("not a message"))
    end
  end

  describe "AuthEnvelopedData" do
    test "the authenticated attributes, with content-type, are covered by the tag", ctx do
      bob = party(:rsa2048, ctx)
      attribute = Attribute.new({1, 2, 3, 4}, [DER.encode({:utf8, "authenticated"})])

      cms =
        Cmsex.encrypt!(@content, bob.cert,
          cipher: :aes256_gcm,
          authenticated_attributes: [attribute]
        )

      assert %EnvelopedData{authenticated_attributes: attributes, raw: raw} = Cmsex.decode!(cms)
      assert Enum.map(attributes, & &1.type) |> Enum.sort() == [:content_type, {1, 2, 3, 4}]
      assert content(Cmsex.decrypt(cms, bob.opts)) == @content

      # A change to an authenticated attribute breaks the tag.
      changed = flip_in(cms, "authenticated")
      assert byte_size(changed) == byte_size(cms) and raw.authenticated_attributes != nil
      assert reason(Cmsex.decrypt(changed, bob.opts)) == :decryption_failed
    end

    test "a changed ciphertext or tag", ctx do
      bob = party(:rsa2048, ctx)

      for cipher <- @aead do
        cms = Cmsex.encrypt!(@content, bob.cert, cipher: cipher)
        ed = Cmsex.decode!(cms)

        assert reason(Cmsex.decrypt(flip_in(cms, ed.encrypted_content), bob.opts)) ==
                 :decryption_failed

        assert reason(Cmsex.decrypt(flip_in(cms, ed.mac), bob.opts)) == :decryption_failed
      end
    end

    test "the content-type attribute" do
      opts = [kek: {"k1", kek()}]
      assert content(Cmsex.decrypt(auth_enveloped([]), opts)) == @content

      cms = auth_enveloped(content_type: :signed_data)

      assert {:error, %Error{reason: :missing_attribute, detail: :content_type}} =
               Cmsex.decrypt(cms, opts)

      cms = auth_enveloped(attributes: [Attribute.content_type(:signed_data)])
      assert reason(Cmsex.decrypt(cms, opts)) == :content_type_mismatch

      cms = auth_enveloped(attributes: [Attribute.new({1, 2, 3}, [<<5, 0>>])])

      assert {:error, %Error{reason: :missing_attribute, detail: :content_type}} =
               Cmsex.decrypt(cms, opts)

      twice = Attribute.new(:content_type, [DER.encode({:oid, :data}), DER.encode({:oid, :data})])
      cms = auth_enveloped(attributes: [twice])
      assert {:error, %Error{reason: :invalid_attribute}} = Cmsex.decrypt(cms, opts)

      cms =
        auth_enveloped(
          content_type: :signed_data,
          attributes: [Attribute.content_type(:signed_data)]
        )

      assert {:ok, %Decrypted{content_type: :signed_data}} = Cmsex.decrypt(cms, opts)
    end

    test "the cipher must fit the type" do
      cbc = Cipher.new(:aes256_cbc)
      gcm = Cipher.new(:aes256_gcm)
      cek = :binary.copy(<<7>>, 32)
      {cbc_text, nil} = Cipher.encrypt(cbc, cek, @content)
      {gcm_text, tag} = Cipher.encrypt(gcm, cek, @content)
      opts = [kek: {"k1", kek()}]

      enveloped =
        message(:enveloped_data, [{:int, 2}, {:set, [kekri(kek(), cek)]}, eci(gcm, gcm_text)])

      assert {:error,
              %Error{reason: :unsupported_algorithm, detail: {2, 16, 840, 1, 101, 3, 4, 1, 46}}} =
               Cmsex.decrypt(enveloped, opts)

      auth =
        message(:auth_enveloped_data, [
          {:int, 0},
          {:set, [kekri(kek(), cek)]},
          eci(cbc, cbc_text),
          {:octets, tag}
        ])

      assert reason(Cmsex.decrypt(auth, opts)) == :unsupported_algorithm
    end
  end

  describe "EncryptedData" do
    test "a key managed by other means" do
      for cipher <- [:aes128_cbc, :aes192_cbc, :aes256_cbc] do
        key = Cipher.random_key(Cipher.new(cipher))
        cms = Cmsex.encrypt_with_key!(@content, key, cipher: cipher)

        assert %EncryptedData{version: 0, content_encryption_algorithm: ^cipher} =
                 Cmsex.decode!(cms)

        assert {:ok, %Decrypted{recipient: nil} = decrypted} =
                 Cmsex.decrypt(cms, content_key: key)

        assert decrypted.content == @content
        assert reason(Cmsex.decrypt(cms, password: "pw")) == :recipient_not_found
      end
    end

    test "unprotected attributes, detached content and another type" do
      key = kek(32)
      attribute = Attribute.new({1, 2, 3, 4}, [<<5, 0>>])

      {cms, ciphertext} =
        Cmsex.encrypt_with_key!(@content, key,
          unprotected_attributes: [attribute],
          detached: true,
          content_type: :signed_data
        )

      assert %EncryptedData{
               version: 2,
               encrypted_content: nil,
               unprotected_attributes: [^attribute]
             } =
               Cmsex.decode!(cms)

      assert {:ok, %Decrypted{content: @content, content_type: :signed_data}} =
               Cmsex.decrypt(cms, content_key: key, content: ciphertext)
    end

    test "a wrong key, of the right size or not" do
      cms = Cmsex.encrypt_with_key!(@content, kek(32))
      # A wrong CBC key gives a wrong padding nearly always, and garbage
      # otherwise: CBC has no integrity check.
      result = Cmsex.decrypt(cms, content_key: :binary.copy(<<9>>, 32))
      assert reason(result) == :decryption_failed or content(result) != @content
      assert reason(Cmsex.decrypt(cms, content_key: kek(16))) == :decryption_failed
    end

    test "the key and the cipher are checked" do
      assert_raise ArgumentError, ~r/must be 32 bytes/, fn ->
        Cmsex.encrypt_with_key(@content, kek(16))
      end

      assert_raise ArgumentError, ~r/no place for a tag/, fn ->
        Cmsex.encrypt_with_key(@content, kek(32), cipher: :aes256_gcm)
      end

      assert_raise ArgumentError, ~r/unknown option/, fn ->
        Cmsex.encrypt_with_key(@content, kek(32), authenticated_attributes: [])
      end
    end

    test "the content key of an EnvelopedData skips the recipients", ctx do
      bob = party(:rsa2048, ctx)
      cms = Cmsex.encrypt!(@content, bob.cert, cipher: :aes128_gcm)
      %Decrypted{} = Cmsex.decrypt!(cms, bob.opts)

      assert reason(Cmsex.decrypt(cms, content_key: kek(16))) == :decryption_failed
      assert reason(Cmsex.decrypt(cms, content_key: kek(32))) == :decryption_failed
    end
  end

  describe "RFC 4134" do
    setup do
      %{
        bob: [key: rfc4134("BobPrivRSAEncrypt.pri"), certificate: rfc4134("BobRSASignByCarl.cer")]
      }
    end

    test "5.1: PKCS #1 v1.5 key transport and Triple-DES", %{bob: bob} do
      assert {:ok, %Decrypted{} = decrypted} = Cmsex.decrypt(rfc4134("5.1.bin"), bob)
      assert decrypted.content == "This is some sample content."
      assert decrypted.recipient.key_encryption_algorithm == :rsa_encryption
    end

    test "5.2: RC2, where the :crypto of the system has it", %{bob: bob} do
      result = Cmsex.decrypt(rfc4134("5.2.bin"), bob)

      if :rc2_cbc in :crypto.supports(:ciphers),
        do: assert(content(result) == "This is some sample content."),
        else: assert({:error, %Error{reason: :not_available, detail: :rc2_cbc}} = result)
    end

    test "7.1 and 7.2: EncryptedData" do
      key = Base.decode16!("737C791F25EAD0E04629254352F7DC6291E5CB26917ADA32")

      for name <- ["7.1.bin", "7.2.bin"] do
        assert content(Cmsex.decrypt(rfc4134(name), content_key: key)) ==
                 "This is some sample content."
      end
    end

    test "the key and certificate of another recipient", %{bob: bob} do
      alice = rfc4134("AliceRSASignByCarl.cer")

      assert reason(Cmsex.decrypt(rfc4134("5.1.bin"), Keyword.put(bob, :certificate, alice))) ==
               :key_certificate_mismatch
    end
  end

  # RFC 3218, 2.3: a PKCS #1 v1.5 padding that does not check gives a
  # random key, so the failure is that of the content, the same as a wrong
  # key. AES-GCM makes the failure certain here; with CBC a random key
  # decrypts to garbage once in about 256 times.
  describe "PKCS #1 v1.5 key transport" do
    setup ctx do
      bob = party(:rsa2048, ctx)
      {:ok, cert} = Certificate.parse(bob.cert)
      {:rsa, n, e} = cert.public_key
      %{bob: bob, cert: cert, n: n, e: e}
    end

    defp v15_message(cert, encrypted_key, cek) do
      cipher = Cipher.new(:aes256_gcm)
      {ciphertext, tag} = Cipher.encrypt(cipher, cek, @content)

      ktri =
        {:seq,
         [
           {:int, 0},
           {:seq, [{:raw, cert.issuer}, {:int, cert.serial}]},
           {:seq, [{:oid, :rsa_encryption}, :null]},
           {:octets, encrypted_key}
         ]}

      message(:auth_enveloped_data, [
        {:int, 0},
        {:set, [ktri]},
        eci(cipher, ciphertext),
        {:octets, tag}
      ])
    end

    defp raw_rsa(block, n, e),
      do: :crypto.public_encrypt(:rsa, block, [e, n], rsa_padding: :rsa_no_padding)

    test "a good padding", %{bob: bob, cert: cert, n: n, e: e} do
      cek = :crypto.strong_rand_bytes(32)
      encrypted = :crypto.public_encrypt(:rsa, cek, [e, n], rsa_padding: :rsa_pkcs1_padding)
      assert content(Cmsex.decrypt(v15_message(cert, encrypted, cek), bob.opts)) == @content

      # A leading zero of the ciphertext may be left out by the sender.
      ps = :binary.copy(<<0xAB>>, 256 - 3 - 32)
      block = <<0, 2, ps::binary, 0, cek::binary>>
      encrypted = raw_rsa(block, n, e)
      assert content(Cmsex.decrypt(v15_message(cert, encrypted, cek), bob.opts)) == @content
    end

    test "bad paddings and a wrong size all fail alike", %{bob: bob, cert: cert, n: n, e: e} do
      cek = :crypto.strong_rand_bytes(32)
      ps = :binary.copy(<<0xAB>>, 256 - 3 - 32)

      blocks = [
        <<0, 1, ps::binary, 0, cek::binary>>,
        <<0, 2, 0, binary_part(ps, 1, byte_size(ps) - 1)::binary, 0, cek::binary>>,
        <<0, 2, ps::binary, 1, cek::binary>>,
        <<0, 2, binary_part(ps, 0, 7)::binary, 0, :binary.copy(<<1>>, 256 - 10)::binary>>
      ]

      short =
        :crypto.public_encrypt(:rsa, binary_part(cek, 0, 16), [e, n],
          rsa_padding: :rsa_pkcs1_padding
        )

      too_big = :binary.copy(<<0xFF>>, 256)

      for encrypted <- [short, too_big, <<1, 2, 3>> | Enum.map(blocks, &raw_rsa(&1, n, e))] do
        assert {:error, %Error{reason: :decryption_failed, detail: nil}} =
                 Cmsex.decrypt(v15_message(cert, encrypted, cek), bob.opts)
      end
    end
  end

  describe "a key in a function" do
    test "RSA-OAEP and PKCS #1 v1.5", ctx do
      bob = party(:rsa2048, ctx)
      {:rsa, crypto_key, _n, _e} = TestPKI.private(:rsa2048)
      cms = Cmsex.encrypt!(@content, Recipient.certificate(bob.cert, oaep_digest: :sha384))

      fun = fn
        %{operation: :decrypt, padding: :oaep, hash: :sha384, mgf_hash: :sha384, label: ""} = req ->
          {:ok,
           :crypto.private_decrypt(:rsa, req.ciphertext, crypto_key,
             rsa_padding: :rsa_pkcs1_oaep_padding,
             rsa_oaep_md: :sha384,
             rsa_mgf1_md: :sha384
           )}
      end

      assert content(Cmsex.decrypt(cms, key: fun, certificate: bob.cert)) == @content

      failing = fn _request -> {:error, :hsm_offline} end
      assert reason(Cmsex.decrypt(cms, key: failing, certificate: bob.cert)) == :decryption_failed

      bob_4134 = rfc4134("BobRSASignByCarl.cer")
      {:ok, bob_key} = Cmsex.Key.parse(rfc4134("BobPrivRSAEncrypt.pri"))
      {:rsa, key_4134, _, _} = bob_key

      v15_4134 = fn %{operation: :decrypt, padding: :pkcs1, ciphertext: ct} ->
        {:ok, :crypto.private_decrypt(:rsa, ct, key_4134, rsa_padding: :rsa_pkcs1_padding)}
      end

      assert content(Cmsex.decrypt(rfc4134("5.1.bin"), key: v15_4134, certificate: bob_4134)) ==
               "This is some sample content."
    end

    test "ECDH, X25519 and X448", ctx do
      for name <- [:p256, :x25519, :x448] do
        bob = party(name, ctx)
        cms = Cmsex.encrypt!(@content, bob.cert)

        fun =
          case TestPKI.private(name) do
            {:ec, curve, private, _point} ->
              fn %{operation: :agree, curve: ^curve, public_key: peer} ->
                {:ok, :crypto.compute_key(:ecdh, peer, private, Cmsex.Key.crypto_curve(curve))}
              end

            {type, private, _public} ->
              fn %{operation: :agree, curve: ^type, public_key: peer} ->
                {:ok, :crypto.compute_key(:ecdh, peer, private, type)}
              end
          end

        assert content(Cmsex.decrypt(cms, key: fun, certificate: bob.cert)) == @content

        zero = fn _request -> {:ok, :binary.copy(<<0>>, 32)} end
        assert reason(Cmsex.decrypt(cms, key: zero, certificate: bob.cert)) == :decryption_failed
      end
    end
  end

  ## Checks

  describe "recipients that cannot be used" do
    test "the key usage of the certificate", ctx do
      good = party(:rsa2048, ctx)
      signing_only = party({:rsa2048, :signing}, ctx, key_usage: [0])
      no_extension = party({:rsa2048, :plain}, ctx, key_usage: nil)
      ec_transport = party({:p256, :transport}, ctx, key_usage: [2])

      assert {:error,
              %Error{reason: :invalid_recipient, detail: :key_usage, recipient: 1} = error} =
               Cmsex.encrypt(@content, [good.cert, signing_only.cert])

      assert Exception.message(error) == "recipient 1: invalid recipient (:key_usage)"
      assert {:ok, _} = Cmsex.encrypt(@content, no_extension.cert)

      assert {:error, %Error{reason: :invalid_recipient, detail: :key_usage, recipient: 0}} =
               Cmsex.encrypt(@content, ec_transport.cert)
    end

    test "keys that only sign" do
      ed25519 = TestPKI.cert(:ed25519, key_usage: nil)
      pss = TestPKI.cert({:rsa2048, :pss}, key_usage: nil, pss_key: true)

      for cert <- [ed25519, pss] do
        assert {:error, %Error{reason: :invalid_recipient, detail: :key_type}} =
                 Cmsex.encrypt(@content, cert)
      end
    end

    test "a short RSA key", ctx do
      weak = party(:rsa1024, ctx)

      assert {:error, %Error{reason: :weak_key, detail: 1024, recipient: 0}} =
               Cmsex.encrypt(@content, weak.cert)

      cms = Cmsex.encrypt!(@content, weak.cert, min_rsa_bits: 1024)
      assert content(Cmsex.decrypt(cms, weak.opts)) == @content
    end

    test "a certificate that cannot be read, or has no subject key identifier", ctx do
      assert {:error, %Error{reason: :invalid_certificate, recipient: 0}} =
               Cmsex.encrypt(@content, "not a certificate")

      no_ski = party({:rsa2048, :no_ski}, ctx, ski: false)
      recipient = Recipient.certificate(no_ski.cert, identifier: :subject_key_identifier)

      assert {:error, %Error{reason: :invalid_certificate, detail: :subject_key_identifier}} =
               Cmsex.encrypt(@content, recipient)

      assert {:error, %Error{reason: :invalid_certificate}} =
               Cmsex.encrypt(@content, party(:rsa2048, ctx).cert, certificates: ["junk"])
    end

    test "an EC point that is not on the curve", ctx do
      bob = party(:p256, ctx)
      {:ok, cert} = Certificate.parse(bob.cert)
      {:ec, _, <<4, x::binary-size(32), y::binary-size(32)>>} = cert.public_key
      off_curve = <<4, x::binary, :crypto.exor(y, <<1::256>>)::binary>>
      changed = :binary.replace(bob.cert, cert.public_key |> elem(2), off_curve)

      assert {:error, %Error{reason: :invalid_recipient, detail: :public_key}} =
               Cmsex.encrypt(@content, changed)
    end
  end

  describe "options" do
    test "of encrypt/3", ctx do
      bob = party(:rsa2048, ctx).cert

      assert_raise ArgumentError, ~r/:cipher must be one of/, fn ->
        Cmsex.encrypt(@content, bob, cipher: :des_ede3_cbc)
      end

      assert_raise ArgumentError, ~r/needs an authenticated cipher/, fn ->
        Cmsex.encrypt(@content, bob,
          authenticated_attributes: [Attribute.new({1, 2}, [<<5, 0>>])]
        )
      end

      assert_raise ArgumentError, ~r/written by the library/, fn ->
        Cmsex.encrypt(@content, bob,
          cipher: :aes128_gcm,
          authenticated_attributes: [Attribute.content_type(:data)]
        )
      end

      assert_raise ArgumentError, ~r/invalid tag size/, fn ->
        Cmsex.encrypt(@content, bob, cipher: :chacha20_poly1305, tag_size: 12)
      end

      assert_raise ArgumentError, ~r/the content must be a binary/, fn ->
        Cmsex.encrypt({:stream, ["a"]}, bob)
      end

      assert_raise ArgumentError, ~r/expected a Cmsex.Recipient/, fn ->
        Cmsex.encrypt(@content, [])
      end

      assert_raise ArgumentError, ~r/unknown option :signers/, fn ->
        Cmsex.encrypt(@content, bob, signers: :all)
      end

      for size <- [12, 13, 14, 15, 16] do
        cms = Cmsex.encrypt!(@content, bob, cipher: :aes128_gcm, tag_size: size)
        assert byte_size(Cmsex.decode!(cms).mac) == size
      end
    end

    test "content of the wrong kind is not shown", ctx do
      bob = party(:rsa2048, ctx).cert
      secret = ["the secret", " content"]

      for call <- [
            fn -> Cmsex.encrypt(secret, bob) end,
            fn -> Cmsex.encrypt_with_key(secret, kek()) end,
            fn -> Cmsex.mac(secret, Recipient.kek(kek(), "id")) end,
            fn -> Cmsex.digest(secret) end,
            fn -> Cmsex.verify("a message", content: secret) end
          ] do
        message = Exception.message(catch_error(call.()))
        assert message =~ "got a list"
        refute message =~ "secret"
      end
    end

    test "of the recipients" do
      cert = "a certificate"

      for opts <- [
            [oaep_digest: :md5],
            [identifier: :name],
            [key_agreement: :std_dh_sha1kdf],
            [key_wrap: :cms3des_wrap],
            [ukm: ""],
            [colour: :blue]
          ] do
        assert_raise ArgumentError, fn -> Recipient.certificate(cert, opts) end
      end

      assert_raise ArgumentError, ~r/16, 24 or 32 bytes/, fn -> Recipient.kek("short", "id") end
      assert_raise ArgumentError, ~r/must not be empty/, fn -> Recipient.kek(kek(), "") end

      assert_raise ArgumentError, ~r/of the size of the key/, fn ->
        Recipient.kek(kek(16), "id", key_wrap: :aes256_wrap)
      end

      assert_raise ArgumentError, ~r/:date/, fn -> Recipient.kek(kek(), "id", date: "today") end

      assert_raise ArgumentError, ~r/:other/, fn ->
        Recipient.kek(kek(), "id", other: {{1, 2}, "x"})
      end

      assert_raise ArgumentError, ~r/must not be empty/, fn -> Recipient.password("") end
      assert_raise ArgumentError, ~r/:salt/, fn -> Recipient.password("pw", salt: "short") end

      assert_raise ArgumentError, ~r/:iterations/, fn ->
        Recipient.password("pw", iterations: 0)
      end

      assert_raise ArgumentError, ~r/:prf/, fn ->
        Recipient.password("pw", prf: :hmac_with_sha1)
      end

      assert_raise ArgumentError, ~r/:kek_cipher/, fn ->
        Recipient.password("pw", kek_cipher: :aes256_gcm)
      end
    end

    test "of decrypt/2", ctx do
      bob = party(:rsa2048, ctx)
      cms = Cmsex.encrypt!(@content, bob.cert)

      assert_raise ArgumentError, ~r/expected one of/, fn -> Cmsex.decrypt(cms) end
      assert_raise ArgumentError, ~r/go together/, fn -> Cmsex.decrypt(cms, key: bob.key) end
      assert_raise ArgumentError, ~r/:kek must be/, fn -> Cmsex.decrypt(cms, kek: kek()) end
      assert_raise ArgumentError, ~r/:password/, fn -> Cmsex.decrypt(cms, password: "") end

      assert_raise ArgumentError, ~r/:content must be/, fn ->
        Cmsex.decrypt(cms, [content: {:stream, ["x"]}] ++ bob.opts)
      end

      assert_raise ArgumentError, ~r/unknown option/, fn -> Cmsex.decrypt(cms, trust: []) end

      # A secret is never shown.
      error = catch_error(Cmsex.decrypt(cms, password: "", kek: {"id", "secret key"}))
      refute Exception.message(error) =~ "secret key"
    end

    test "credentials that cannot be read", ctx do
      bob = party(:rsa2048, ctx)
      other = party({:rsa2048, :other}, ctx)
      cms = Cmsex.encrypt!(@content, bob.cert)

      assert reason(Cmsex.decrypt(cms, key: "junk", certificate: bob.cert)) == :invalid_key
      assert reason(Cmsex.decrypt(cms, key: bob.key, certificate: "junk")) == :invalid_certificate

      assert reason(Cmsex.decrypt(cms, key: other.key, certificate: bob.cert)) ==
               :key_certificate_mismatch
    end
  end

  test "Inspect leaves the secrets and the content out", ctx do
    bob = party(:rsa2048, ctx)
    decrypted = Cmsex.decrypt!(Cmsex.encrypt!(@content, bob.cert), bob.opts)

    refute inspect(decrypted) =~ "Attack"
    refute inspect(Recipient.password("my password")) =~ "my password"
    refute inspect(Recipient.kek("0123456789abcdef", "id")) =~ "0123456789abcdef"
  end

  test "a changed encrypted key", ctx do
    bob = party(:rsa2048, ctx)
    cms = Cmsex.encrypt!(@content, bob.cert)
    %EnvelopedData{recipient_infos: [ri]} = Cmsex.decode!(cms)
    assert reason(Cmsex.decrypt(flip_in(cms, ri.encrypted_key), bob.opts)) == :decryption_failed

    cms = Cmsex.encrypt!(@content, Recipient.kek(kek(), "k"))
    %EnvelopedData{recipient_infos: [ri]} = Cmsex.decode!(cms)
    changed = flip_in(cms, ri.encrypted_key)
    assert reason(Cmsex.decrypt(changed, kek: {"k", kek()})) == :decryption_failed

    assert_raise Error, "decryption failed", fn -> Cmsex.decrypt!(changed, kek: {"k", kek()}) end
  end
end
