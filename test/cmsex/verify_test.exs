defmodule Cmsex.VerifyTest do
  use ExUnit.Case, async: true

  alias Cmsex.{Algorithm, Attribute, DER, Digest, Error, PEM, TestCMS, TestPKI, Verified}

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)
  @sample "This is some sample content."
  @dsa_with_sha1 {1, 2, 840, 10_040, 4, 3}

  defp rfc4134(name), do: File.read!(Path.join(@rfc4134, name))

  setup_all do
    root = TestPKI.cert({:p384, :root}, ca: true, subject: "Test Root")
    ca = TestPKI.cert({:p256, :ca}, ca: true, subject: "Test CA", issuer: {root, {:p384, :root}})

    leaves =
      Map.new(
        [:rsa1024, :rsa2048, :p256, :p384, :p521, :brainpool256, :ed25519, :ed448],
        &{&1, TestPKI.cert(&1, issuer: {ca, {:p256, :ca}})}
      )

    %{root: root, ca: ca, certs: leaves}
  end

  # A message with the content inside, the certificates of `keys` and one
  # signer per key.
  defp message(ctx, keys, opts \\ []) do
    {sign_opts, opts} = Keyword.split(opts, [:sign])
    sign_opts = Keyword.get(sign_opts, :sign, [])
    content = Keyword.get(opts, :content, "content")

    signer_infos =
      for key <- List.wrap(keys) do
        TestCMS.sign(
          key,
          ctx.certs[key],
          Keyword.put_new(sign_opts, :content, content || "content")
        )
      end

    TestCMS.signed_data(
      Keyword.merge(
        [
          content: content,
          certificates: for(key <- List.wrap(keys), do: ctx.certs[key]),
          signer_infos: signer_infos
        ],
        opts
      )
    )
  end

  defp reason({:error, %Error{reason: reason}}), do: reason
  defp attribute_der(%Attribute{} = attribute), do: DER.encode(Attribute.to_term(attribute))

  describe "RFC 4134 examples" do
    for name <- ["4.2", "4.5"] do
      test "#{name} verifies once SHA-1 and 1024-bit RSA are allowed" do
        der = rfc4134(unquote(name) <> ".bin")

        assert %Error{reason: :weak_algorithm, detail: :sha1, signer: 0} =
                 elem(Cmsex.verify(der), 1)

        assert %Error{reason: :weak_key, detail: 1024} =
                 elem(Cmsex.verify(der, allow_sha1: true), 1)

        assert {:ok, %Verified{} = verified} =
                 Cmsex.verify(der, allow_sha1: true, min_rsa_bits: 1024)

        assert verified.content == @sample
        assert verified.content_type == :data
        assert [signer] = verified.signers
        assert signer.index == 0
        assert signer.certificate == rfc4134("AliceRSASignByCarl.cer")
        assert signer.signing_time == nil
        assert signer.path == nil
        assert signer.deviations == []
        assert signer.countersignatures == []
      end

      test "#{name} validates up to Carl's root" do
        der = rfc4134(unquote(name) <> ".bin")
        carl = rfc4134("CarlRSASelf.cer")
        opts = [allow_sha1: true, min_rsa_bits: 1024]

        assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der, [trust: [carl]] ++ opts)
        assert signer.path == [carl, rfc4134("AliceRSASignByCarl.cer")]

        other = rfc4134("CarlDSSSelf.cer")
        assert :untrusted == reason(Cmsex.verify(der, [trust: [other]] ++ opts))
      end
    end

    for name <- ["4.1", "4.4", "4.6", "4.7", "4.10"] do
      test "#{name} is DSA, which is not supported" do
        assert {:error, %Error{reason: :unsupported_algorithm, detail: @dsa_with_sha1, signer: 0}} =
                 Cmsex.verify(rfc4134(unquote(name) <> ".bin"), allow_sha1: true)
      end
    end

    test "4.4 has an RSA countersignature, verified on its own" do
      der = rfc4134("4.4.bin")
      opts = [allow_sha1: true, min_rsa_bits: 1024]

      assert {:ok, counter} = Cmsex.verify_countersignature(der, [0, 0], opts)
      assert counter.index == 0
      assert counter.certificate == rfc4134("AliceRSASignByCarl.cer")
      assert %DateTime{} = counter.signing_time
      assert counter.countersignatures == []

      carl = rfc4134("CarlRSASelf.cer")

      assert {:ok, %{path: [^carl, _alice]}} =
               Cmsex.verify_countersignature(der, [0, 0], [trust: [carl]] ++ opts)

      assert {:error, %Error{reason: :weak_algorithm, signer: [0, 0]}} =
               Cmsex.verify_countersignature(der, [0, 0])

      # The signer above, in DSA, still fails in verify/2.
      assert :unsupported_algorithm ==
               reason(Cmsex.verify(der, [countersignatures: true] ++ opts))
    end

    test "4.3 is detached" do
      der = rfc4134("4.3.bin")
      assert :content_required == reason(Cmsex.verify(der))

      assert {:error, %Error{reason: :unsupported_algorithm}} =
               Cmsex.verify(der, content: rfc4134("ExContent.bin"), allow_sha1: true)
    end

    test "4.11 has no signers" do
      assert :no_signers == reason(Cmsex.verify(rfc4134("4.11.bin")))
      assert :no_signers == reason(Cmsex.verify_each(rfc4134("4.11.bin")))
    end
  end

  describe "signature schemes" do
    @schemes [
      {"RSA PKCS #1 v1.5 with SHA-256", :rsa2048, []},
      {"RSA PKCS #1 v1.5 with SHA-224", :rsa2048, [digest: :sha224]},
      {"RSA PKCS #1 v1.5 with SHA-384", :rsa2048, [digest: :sha384]},
      {"RSA PKCS #1 v1.5 with SHA-512", :rsa2048, [digest: :sha512]},
      {"RSASSA-PSS with SHA-256", :rsa2048, [pss: true]},
      {"RSASSA-PSS with SHA-384", :rsa2048, [pss: true, digest: :sha384]},
      {"RSASSA-PSS with SHA-512", :rsa2048, [pss: true, digest: :sha512]},
      {"ECDSA P-256", :p256, []},
      {"ECDSA P-384", :p384, [digest: :sha384]},
      {"ECDSA P-521", :p521, [digest: :sha512]},
      {"ECDSA brainpoolP256r1", :brainpool256, []},
      {"Ed25519", :ed25519, []},
      {"Ed448", :ed448, []}
    ]

    for {name, key, opts} <- @schemes do
      test "#{name}", ctx do
        key = unquote(key)
        der = message(ctx, key, sign: unquote(opts))

        assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der)
        assert signer.certificate == ctx.certs[key]
        assert signer.deviations == []
      end

      test "#{name}, without signed attributes", ctx do
        der = message(ctx, unquote(key), sign: [attributes: false] ++ unquote(opts))
        assert {:ok, %Verified{signers: [%{signer_info: si}]}} = Cmsex.verify(der)
        assert si.signed_attributes == nil
      end

      test "#{name}, with a changed signature", ctx do
        der = message(ctx, unquote(key), sign: [tamper: true] ++ unquote(opts))
        assert {:error, %Error{reason: :invalid_signature, signer: 0}} = Cmsex.verify(der)

        der = message(ctx, unquote(key), sign: [tamper: true, attributes: false] ++ unquote(opts))
        assert :invalid_signature == reason(Cmsex.verify(der))
      end
    end

    test "the combined RSA OIDs", ctx do
      for hash <- [:sha256, :sha384, :sha512] do
        oid = :"#{hash}_with_rsa_encryption"
        sign = [digest: hash, signature_algorithm: {:seq, [{:oid, oid}, :null]}]
        assert {:ok, _} = Cmsex.verify(message(ctx, :rsa2048, sign: sign))

        sign = [digest: hash, signature_algorithm: {:seq, [{:oid, oid}]}]
        assert {:ok, _} = Cmsex.verify(message(ctx, :rsa2048, sign: sign))
      end
    end

    test "a key whose certificate is id-RSASSA-PSS", ctx do
      cert = TestPKI.cert(:rsa2048, issuer: {ctx.ca, {:p256, :ca}}, pss_key: %{hash: :sha256})
      ctx = put_in(ctx.certs[:rsa2048], cert)

      assert {:ok, _} = Cmsex.verify(message(ctx, :rsa2048, sign: [pss: true]))

      assert {:error, %Error{reason: :algorithm_mismatch, detail: :rsassa_pss}} =
               Cmsex.verify(message(ctx, :rsa2048, sign: [pss: true, digest: :sha384]))

      assert :key_mismatch == reason(Cmsex.verify(message(ctx, :rsa2048)))

      cert = TestPKI.cert(:rsa2048, issuer: {ctx.ca, {:p256, :ca}}, pss_key: true)
      ctx = put_in(ctx.certs[:rsa2048], cert)
      assert {:ok, _} = Cmsex.verify(message(ctx, :rsa2048, sign: [pss: true, digest: :sha384]))
    end
  end

  describe "algorithm policy" do
    test "SHA-1 needs allow_sha1", ctx do
      sign = [digest: :sha1, signature_algorithm: {:seq, [{:oid, :ecdsa_with_sha1}]}]

      for der <- [message(ctx, :p256, sign: sign), message(ctx, :rsa2048, sign: [digest: :sha1])] do
        assert {:error, %Error{reason: :weak_algorithm, detail: :sha1}} = Cmsex.verify(der)
        assert {:ok, _} = Cmsex.verify(der, allow_sha1: true)
      end
    end

    test "MD5 is never accepted", ctx do
      der = message(ctx, :rsa2048, sign: [digest: :md5])
      assert {:error, %Error{reason: :weak_algorithm, detail: :md5}} = Cmsex.verify(der)

      assert {:error, %Error{reason: :weak_algorithm, detail: :md5}} =
               Cmsex.verify(der, allow_sha1: true)
    end

    test "RSA keys below min_rsa_bits", ctx do
      der = message(ctx, :rsa1024)
      assert {:error, %Error{reason: :weak_key, detail: 1024}} = Cmsex.verify(der)
      assert {:ok, _} = Cmsex.verify(der, min_rsa_bits: 1024)
      assert :weak_key == reason(Cmsex.verify(message(ctx, :rsa2048), min_rsa_bits: 3072))
    end

    test "a combined OID that names another hash", ctx do
      sign = [signature_algorithm: {:seq, [{:oid, :sha384_with_rsa_encryption}, :null]}]

      assert {:error, %Error{reason: :algorithm_mismatch, detail: {:sha256, :sha384}}} =
               Cmsex.verify(message(ctx, :rsa2048, sign: sign))

      sign = [signature_algorithm: {:seq, [{:oid, :ecdsa_with_sha512}]}]
      assert :algorithm_mismatch == reason(Cmsex.verify(message(ctx, :p256, sign: sign)))
    end

    test "an algorithm for another kind of key", ctx do
      sign = [signature_algorithm: {:seq, [{:oid, :ecdsa_with_sha256}]}]
      assert :key_mismatch == reason(Cmsex.verify(message(ctx, :rsa2048, sign: sign)))

      sign = [signature_algorithm: {:seq, [{:oid, :ed25519}]}, digest: :sha512]
      assert :key_mismatch == reason(Cmsex.verify(message(ctx, :p256, sign: sign)))
    end

    test "an unknown signature algorithm", ctx do
      sign = [signature_algorithm: {:seq, [{:oid, {1, 2, 3, 4}}]}]

      assert {:error, %Error{reason: :unsupported_algorithm, detail: {1, 2, 3, 4}}} =
               Cmsex.verify(message(ctx, :p256, sign: sign))
    end

    test "an unknown digest algorithm", ctx do
      {:ok, c} = Cmsex.Certificate.parse(ctx.certs[:p256])

      si =
        TestCMS.signer_info(
          sid: {:issuer_and_serial, c.issuer, c.serial},
          digest: {:seq, [{:oid, {1, 2, 3, 5}}]},
          signature_algorithm: {:seq, [{:oid, :ecdsa_with_sha256}]}
        )

      der = TestCMS.signed_data(certificates: [ctx.certs[:p256]], signer_infos: [si])

      assert {:error, %Error{reason: :unsupported_algorithm, detail: {1, 2, 3, 5}}} =
               Cmsex.verify(der)
    end

    test "Ed25519 with another SHA-2 is a deviation, or an error when strict", ctx do
      der = message(ctx, :ed25519, sign: [digest: :sha256])

      assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der)
      assert signer.deviations == [:ed25519_digest]

      assert {:error, %Error{reason: :algorithm_mismatch, detail: {:sha256, :ed25519}}} =
               Cmsex.verify(der, ed25519_digest: :strict)

      assert {:ok, _} = Cmsex.verify(message(ctx, :ed25519), ed25519_digest: :strict)
    end

    test "Ed448 takes SHAKE256 only", ctx do
      der = message(ctx, :ed448, sign: [digest: :sha512])
      assert :algorithm_mismatch == reason(Cmsex.verify(der))

      der = message(ctx, :ed448, sign: [digest: :shake256])
      assert :algorithm_mismatch == reason(Cmsex.verify(der))

      der = message(ctx, :ed448, sign: [digest: :shake256_len, attributes: false])
      assert :algorithm_mismatch == reason(Cmsex.verify(der))
    end
  end

  describe "content" do
    test "a detached message takes its content", ctx do
      der = message(ctx, :p256, content: nil, sign: [content: "detached"])

      assert :content_required == reason(Cmsex.verify(der))
      assert {:ok, %Verified{content: nil}} = Cmsex.verify(der, content: "detached")
      assert :digest_mismatch == reason(Cmsex.verify(der, content: "changed"))
    end

    test "as a stream", ctx do
      content = :binary.copy("0123456789", 1000)
      der = message(ctx, [:p256, :ed25519], content: nil, sign: [content: content])
      stream = Stream.map(0..99, &binary_part(content, &1 * 100, 100))

      assert {:ok, %Verified{signers: [_, _]}} = Cmsex.verify(der, content: {:stream, stream})
    end

    test "as a digest", ctx do
      der = message(ctx, :p256, content: nil, sign: [content: "detached"])
      digest = Digest.hash(:sha256, "detached")

      assert {:ok, _} = Cmsex.verify(der, content: {:digest, :sha256, digest})

      assert :digest_mismatch ==
               reason(Cmsex.verify(der, content: {:digest, :sha256, <<0::256>>}))

      assert {:error, %Error{reason: :content_required, detail: :sha256}} =
               Cmsex.verify(der, content: {:digest, :sha384, Digest.hash(:sha384, "detached")})
    end

    test "a digest is not enough for EdDSA without signed attributes", ctx do
      der = message(ctx, :ed25519, content: nil, sign: [content: "detached", attributes: false])
      digest = Digest.hash(:sha512, "detached")

      assert :content_required == reason(Cmsex.verify(der, content: {:digest, :sha512, digest}))
      assert {:ok, _} = Cmsex.verify(der, content: "detached")
      assert {:ok, _} = Cmsex.verify(der, content: {:stream, ["detac", "hed"]})
    end

    test "content given for a message that carries its own", ctx do
      der = message(ctx, :p256)
      assert :unexpected_content == reason(Cmsex.verify(der, content: "content"))
    end

    test "changed content", ctx do
      der = message(ctx, :p256, content: "changed", sign: [content: "content"])
      assert {:error, %Error{reason: :digest_mismatch, signer: 0}} = Cmsex.verify(der)

      der = message(ctx, :p256, content: "changed", sign: [attributes: false, content: "content"])
      assert :invalid_signature == reason(Cmsex.verify(der))
    end

    test "in BER and in PEM", ctx do
      der = message(ctx, [:rsa2048, :p256])

      assert {:ok, %Verified{content: "content", signers: [_, _]}} =
               Cmsex.verify(TestCMS.to_ber(der))

      assert {:ok, %Verified{signers: [_, _]}} = Cmsex.verify(PEM.encode(der))
    end

    test "another content type", ctx do
      type = {1, 2, 840, 113_549, 1, 9, 16, 1, 4}
      der = message(ctx, :p256, content_type: type, sign: [content_type: type])

      assert {:ok, %Verified{content_type: :tst_info}} = Cmsex.verify(der)

      der = message(ctx, :p256, content_type: type)
      assert :content_type_mismatch == reason(Cmsex.verify(der))

      der = message(ctx, :p256, content_type: type, sign: [attributes: false])

      assert {:error, %Error{reason: :missing_attribute, detail: :content_type}} =
               Cmsex.verify(der)
    end
  end

  describe "PKCS #7 content (RFC 2315, 9.3)" do
    test "the digest covers the content octets of the value", ctx do
      type = {1, 2, 3, 4}
      value = DER.encode({:seq, [{:int, 5}, {:utf8, "x"}]})
      octets = DER.encode({:int, 5}) <> DER.encode({:utf8, "x"})
      signer = TestCMS.sign(:p256, ctx.certs[:p256], content: octets, content_type: type)

      der =
        TestCMS.signed_data(
          content: {:raw, value},
          content_type: type,
          certificates: [ctx.certs[:p256]],
          signer_infos: [signer]
        )

      assert {:ok, %Verified{content: ^octets, signed_data: sd}} = Cmsex.verify(der)
      assert sd.pkcs7_content == value
    end
  end

  describe "signed attributes" do
    test "a missing content type", ctx do
      der = message(ctx, :p256, sign: [content_type: nil])

      assert {:error, %Error{reason: :missing_attribute, detail: :content_type}} =
               Cmsex.verify(der)
    end

    test "a missing message digest", ctx do
      cert = ctx.certs[:p256]
      {:ok, c} = Cmsex.Certificate.parse(cert)

      si =
        TestCMS.signer_info(
          sid: {:issuer_and_serial, c.issuer, c.serial},
          signed: [TestCMS.attribute(:content_type, [{:oid, :data}])],
          signature_algorithm: {:seq, [{:oid, :ecdsa_with_sha256}]}
        )

      der = TestCMS.signed_data(certificates: [cert], signer_infos: [si])

      assert {:error, %Error{reason: :missing_attribute, detail: :message_digest}} =
               Cmsex.verify(der)
    end

    test "repeated attributes and attributes with two values", ctx do
      md = TestCMS.attribute(:message_digest, [{:octets, Digest.hash(:sha256, "content")}])
      der = message(ctx, :p256, sign: [extra: [md]])

      assert {:error, %Error{reason: :invalid_attribute, detail: :message_digest}} =
               Cmsex.verify(der)

      two = TestCMS.attribute(:content_type, [{:oid, :data}, {:oid, :signed_data}])
      der = message(ctx, :p256, sign: [content_type: nil, extra: [two]])

      assert {:error, %Error{reason: :invalid_attribute, detail: :content_type}} =
               Cmsex.verify(der)
    end

    test "a message digest of the wrong value or size", ctx do
      der = message(ctx, :p256, sign: [message_digest: <<0::256>>])
      assert :digest_mismatch == reason(Cmsex.verify(der))

      der = message(ctx, :p256, sign: [message_digest: <<0::160>>])
      assert :digest_mismatch == reason(Cmsex.verify(der))
    end

    test "the signing time is returned", ctx do
      time = ~U[2026-10-23 12:00:00Z]
      der = message(ctx, :p256, sign: [extra: [attribute_der(Attribute.signing_time(time))]])

      assert {:ok, %Verified{signers: [%{signing_time: ^time}]}} = Cmsex.verify(der)

      bad = TestCMS.attribute(:signing_time, [{:int, 1}])

      assert {:error, %Error{reason: :invalid_attribute, detail: :signing_time}} =
               Cmsex.verify(message(ctx, :p256, sign: [extra: [bad]]))
    end

    test "they are covered by the signature", ctx do
      time = Attribute.signing_time(~U[2026-10-23 12:00:00Z])
      der = message(ctx, :p256, sign: [extra: [attribute_der(time)]])
      changed = :binary.replace(der, "261023120000Z", "261023120001Z")

      assert changed != der
      assert :invalid_signature == reason(Cmsex.verify(changed))
    end

    test "unknown attributes are kept", ctx do
      extra = TestCMS.attribute({1, 2, 3, 4}, [{:utf8, "hi"}])
      der = message(ctx, :p256, sign: [extra: [extra]])

      assert {:ok, %Verified{signers: [%{signer_info: si}]}} = Cmsex.verify(der)

      assert %Attribute{type: {1, 2, 3, 4}, values: [<<0x0C, 2, "hi">>]} =
               Cmsex.SignerInfo.attribute(si, {1, 2, 3, 4})
    end
  end

  describe "CMSAlgorithmProtection (RFC 6211)" do
    defp protection(digest, signature, extra \\ []) do
      value =
        DER.encode({:seq, [digest, {:raw, DER.retag(DER.encode(signature), 0xA1)}] ++ extra})

      TestCMS.attribute(:cms_algorithm_protection, [{:raw, value}])
    end

    @sha256 {:seq, [{:oid, :sha256}]}
    @ecdsa {:seq, [{:oid, :ecdsa_with_sha256}]}

    test "that agrees with the signer", ctx do
      der = message(ctx, :p256, sign: [extra: [protection(@sha256, @ecdsa)]])
      assert {:ok, _} = Cmsex.verify(der)
    end

    test "that agrees modulo encoding", ctx do
      digest = {:seq, [{:oid, :sha256}, :null]}
      der = message(ctx, :p256, sign: [extra: [protection(digest, @ecdsa)]])
      assert {:ok, _} = Cmsex.verify(der)

      rsa = {:seq, [{:oid, :rsa_encryption}]}
      der = message(ctx, :rsa2048, sign: [extra: [protection(@sha256, rsa)]])
      assert {:ok, _} = Cmsex.verify(der)
    end

    test "that names other algorithms", ctx do
      sha384 = {:seq, [{:oid, :sha384}]}
      der = message(ctx, :p256, sign: [extra: [protection(sha384, @ecdsa)]])

      assert {:error, %Error{reason: :algorithm_mismatch, detail: :cms_algorithm_protection}} =
               Cmsex.verify(der)

      other = {:seq, [{:oid, :ecdsa_with_sha384}]}
      der = message(ctx, :p256, sign: [extra: [protection(@sha256, other)]])
      assert :algorithm_mismatch == reason(Cmsex.verify(der))
    end

    test "malformed, with a MAC algorithm, or twice", ctx do
      mac = {:raw, DER.retag(DER.encode({:seq, [{:oid, {1, 2, 3}}]}), 0xA2)}

      for extra <- [
            [protection(@sha256, @ecdsa, [mac])],
            [TestCMS.attribute(:cms_algorithm_protection, [{:seq, [@sha256]}])],
            [TestCMS.attribute(:cms_algorithm_protection, [{:int, 1}])],
            [protection(@sha256, @ecdsa), protection(@sha256, @ecdsa)]
          ] do
        assert {:error, %Error{reason: :invalid_attribute, detail: :cms_algorithm_protection}} =
                 Cmsex.verify(message(ctx, :p256, sign: [extra: extra]))
      end
    end
  end

  describe "signing-certificate attributes" do
    test "signing-certificate-v2", ctx do
      cert = ctx.certs[:p256]

      for opts <- [[], [hash: :sha384], [hash: :sha512, issuer_serial: false]] do
        attribute = attribute_der(Attribute.signing_certificate_v2(cert, opts))
        assert {:ok, _} = Cmsex.verify(message(ctx, :p256, sign: [extra: [attribute]]))
      end
    end

    test "signing-certificate-v2 for another certificate", ctx do
      attribute = attribute_der(Attribute.signing_certificate_v2(ctx.certs[:p384]))

      assert :signing_certificate_mismatch ==
               reason(Cmsex.verify(message(ctx, :p256, sign: [extra: [attribute]])))
    end

    test "signing-certificate-v2 with another serial number", ctx do
      cert = ctx.certs[:p256]
      {:ok, c} = Cmsex.Certificate.parse(cert)
      issuer_serial = {:seq, [{:seq, [{:explicit, 4, {:raw, c.issuer}}]}, {:int, c.serial + 1}]}
      id = {:seq, [{:octets, Digest.hash(:sha256, cert)}, issuer_serial]}
      attribute = TestCMS.attribute(:signing_certificate_v2, [{:seq, [{:seq, [id]}]}])

      assert :signing_certificate_mismatch ==
               reason(Cmsex.verify(message(ctx, :p256, sign: [extra: [attribute]])))
    end

    test "signing-certificate (v1, SHA-1)", ctx do
      cert = ctx.certs[:p256]
      ess = fn hash -> [{:seq, [{:seq, [{:seq, [{:octets, hash}]}]}]}] end

      good = TestCMS.attribute(:signing_certificate, ess.(Digest.hash(:sha1, cert)))
      assert {:ok, _} = Cmsex.verify(message(ctx, :p256, sign: [extra: [good]]))

      bad = TestCMS.attribute(:signing_certificate, ess.(<<0::160>>))

      assert :signing_certificate_mismatch ==
               reason(Cmsex.verify(message(ctx, :p256, sign: [extra: [bad]])))
    end

    test "malformed", ctx do
      for type <- [:signing_certificate, :signing_certificate_v2],
          value <- [{:int, 1}, {:seq, []}, {:seq, [{:seq, [{:seq, [{:int, 1}]}]}]}] do
        attribute = TestCMS.attribute(type, [value])

        assert {:error, %Error{reason: :invalid_attribute, detail: ^type}} =
                 Cmsex.verify(message(ctx, :p256, sign: [extra: [attribute]]))
      end
    end

    test "the constructor checks its arguments", ctx do
      assert_raise ArgumentError, fn -> Attribute.signing_certificate_v2("not a certificate") end

      assert_raise ArgumentError, fn ->
        Attribute.signing_certificate_v2(ctx.certs[:p256], hash: :sha1)
      end

      assert_raise ArgumentError, fn ->
        Attribute.signing_certificate_v2(ctx.certs[:p256], other: 1)
      end
    end
  end

  describe "signers" do
    test "every signer is returned", ctx do
      der = message(ctx, [:rsa2048, :p256, :ed25519])

      assert {:ok, %Verified{signers: signers}} = Cmsex.verify(der)
      assert Enum.map(signers, & &1.index) == [0, 1, 2]

      assert Enum.map(signers, & &1.certificate) ==
               Enum.map([:rsa2048, :p256, :ed25519], &ctx.certs[&1])
    end

    test "signers: :all fails at the first signer that does not verify", ctx do
      good = TestCMS.sign(:p256, ctx.certs[:p256])
      bad = TestCMS.sign(:p384, ctx.certs[:p384], tamper: true)

      der =
        TestCMS.signed_data(
          certificates: [ctx.certs[:p256], ctx.certs[:p384]],
          signer_infos: [good, bad]
        )

      assert {:error, %Error{reason: :invalid_signature, signer: 1} = error} = Cmsex.verify(der)
      assert Exception.message(error) == "signer 1: invalid signature"

      assert {:ok, %Verified{signers: [%{index: 0}]}} = Cmsex.verify(der, signers: :any)

      assert {:ok, _sd, [{_, {:ok, %{index: 0}}}, {_, {:error, %Error{signer: 1}}}]} =
               Cmsex.verify_each(der)

      der = TestCMS.signed_data(certificates: [ctx.certs[:p384]], signer_infos: [bad, bad])

      assert {:error, %Error{reason: :invalid_signature, signer: 0}} =
               Cmsex.verify(der, signers: :any)
    end

    test "a signer whose certificate is not in the message", ctx do
      der = message(ctx, :p256, certificates: nil)

      assert {:error, %Error{reason: :signer_not_found, signer: 0}} = Cmsex.verify(der)
      assert {:ok, _} = Cmsex.verify(der, certificates: [ctx.certs[:p256]])
      assert :signer_not_found == reason(Cmsex.verify(der, certificates: [ctx.certs[:p384]]))
      assert :invalid_certificate == reason(Cmsex.verify(der, certificates: ["junk"]))
    end

    test "unreadable certificates in the message are skipped", ctx do
      der = message(ctx, :p256, certificates: [DER.encode({:seq, [{:int, 1}]}), ctx.certs[:p256]])
      assert {:ok, _} = Cmsex.verify(der)
    end

    test "by subject key identifier", ctx do
      der = message(ctx, [:p256, :rsa2048], sign: [sid: :ski])

      assert {:ok, %Verified{signers: [one, two]}} = Cmsex.verify(der)
      assert one.signer_info.version == 3
      assert two.certificate == ctx.certs[:rsa2048]

      der = message(ctx, :p256, sign: [sid: {:subject_key_identifier, "unknown"}])
      assert :signer_not_found == reason(Cmsex.verify(der))
    end

    test "an issuer written with other string types and case", ctx do
      {:ok, c} = Cmsex.Certificate.parse(ctx.certs[:p256])

      issuer =
        DER.encode(
          {:seq,
           [
             {:set, [{:seq, [{:oid, {2, 5, 4, 6}}, {:printable, "br"}]}]},
             {:set, [{:seq, [{:oid, {2, 5, 4, 10}}, {:printable, "CMSEX  Tests"}]}]},
             {:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {:printable, "test ca"}]}]}
           ]}
        )

      assert issuer != c.issuer
      der = message(ctx, :p256, sign: [sid: {:issuer_and_serial, issuer, c.serial}])
      assert {:ok, _} = Cmsex.verify(der)
    end

    test "every certificate with the identifier is tried", ctx do
      {:ok, real} = Cmsex.Certificate.parse(ctx.certs[:p256])

      fake =
        TestPKI.cert({:p256, :fake},
          issuer: {ctx.ca, {:p256, :ca}},
          serial: real.serial,
          subject: "Test p256"
        )

      signer = TestCMS.sign(:p256, ctx.certs[:p256])

      for certificates <- [[fake, ctx.certs[:p256]], [ctx.certs[:p256], fake]] do
        der = TestCMS.signed_data(certificates: certificates, signer_infos: [signer])
        assert {:ok, %Verified{signers: [%{certificate: cert}]}} = Cmsex.verify(der)
        assert cert == ctx.certs[:p256]
      end

      der = TestCMS.signed_data(certificates: [fake], signer_infos: [signer])
      assert :invalid_signature == reason(Cmsex.verify(der))

      # The error is that of the candidate that went furthest.
      rsa = TestPKI.cert(:rsa2048, issuer: {ctx.ca, {:p256, :ca}}, serial: real.serial)
      der = TestCMS.signed_data(certificates: [rsa, fake], signer_infos: [signer])
      assert :invalid_signature == reason(Cmsex.verify(der))
    end

    test "the deviations of the SignerInfo are returned", ctx do
      der = message(ctx, :p256, sign: [version: 3])

      assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der)
      assert signer.deviations == [:signer_info_version]
    end
  end

  describe "trust" do
    test "a path up to a trusted root", ctx do
      der = message(ctx, :p256, certificates: [ctx.certs[:p256], ctx.ca])

      assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der, trust: [ctx.root])
      assert signer.path == [ctx.root, ctx.ca, ctx.certs[:p256]]
    end

    test "intermediates from the options", ctx do
      der = message(ctx, :p256)

      assert {:error, %Error{reason: :untrusted, detail: :no_path}} =
               Cmsex.verify(der, trust: [ctx.root])

      assert {:ok, %Verified{signers: [%{path: [_, _, _]}]}} =
               Cmsex.verify(der, trust: [ctx.root], certificates: [ctx.ca])
    end

    test "the order of the certificates does not matter", ctx do
      other = TestPKI.cert({:p256, :other_ca}, ca: true, subject: "Test CA")
      der = message(ctx, :p256, certificates: [other, ctx.ca, ctx.root, ctx.certs[:p256]])

      assert {:ok, %Verified{signers: [%{path: path}]}} = Cmsex.verify(der, trust: [ctx.root])
      assert path == [ctx.root, ctx.ca, ctx.certs[:p256]]
    end

    test "a root that did not issue the path", ctx do
      other = TestPKI.cert({:p384, :other_root}, ca: true, subject: "Test Root")
      der = message(ctx, :p256, certificates: [ctx.certs[:p256], ctx.ca])

      assert {:error, %Error{reason: :untrusted, signer: 0}} = Cmsex.verify(der, trust: [other])
      assert :untrusted == reason(Cmsex.verify(der, trust: []))
    end

    test "a signer that is itself trusted" do
      self_signed = TestPKI.cert({:p256, :self})
      signer = TestCMS.sign({:p256, :self}, self_signed)
      der = TestCMS.signed_data(certificates: [self_signed], signer_infos: [signer])

      assert {:ok, %Verified{signers: [%{path: [^self_signed]}]}} =
               Cmsex.verify(der, trust: [self_signed])
    end

    test "a certificate that may not sign", ctx do
      cert = TestPKI.cert({:p256, :encrypt}, issuer: {ctx.ca, {:p256, :ca}}, key_usage: [2])
      signer = TestCMS.sign({:p256, :encrypt}, cert)
      der = TestCMS.signed_data(certificates: [cert, ctx.ca], signer_infos: [signer])

      assert {:ok, _} = Cmsex.verify(der)

      assert {:error, %Error{reason: :untrusted, detail: :key_usage}} =
               Cmsex.verify(der, trust: [ctx.root])
    end

    test "an expired certificate", ctx do
      past = DateTime.add(DateTime.utc_now(), -86_400)

      cert =
        TestPKI.cert({:p256, :expired},
          issuer: {ctx.ca, {:p256, :ca}},
          not_before: DateTime.add(past, -86_400),
          not_after: past
        )

      signer = TestCMS.sign({:p256, :expired}, cert)
      der = TestCMS.signed_data(certificates: [cert, ctx.ca], signer_infos: [signer])

      assert {:error, %Error{reason: :untrusted, detail: :cert_expired}} =
               Cmsex.verify(der, trust: [ctx.root])
    end

    test "options for the path validation", ctx do
      der = message(ctx, :p256, certificates: [ctx.certs[:p256], ctx.ca])

      reject = fn
        _cert, :valid_peer, _state -> {:fail, :revoked}
        _cert, {:extension, _}, state -> {:unknown, state}
        _cert, :valid, state -> {:valid, state}
        _cert, {:bad_cert, reason}, _state -> {:fail, reason}
      end

      assert {:error, %Error{reason: :untrusted, detail: :revoked}} =
               Cmsex.verify(der, trust: [ctx.root], path_validation: [verify_fun: {reject, nil}])
    end
  end

  describe "countersignatures" do
    defp countersigned(ctx, counter_opts \\ []) do
      main = TestCMS.sign(:p256, ctx.certs[:p256])
      counter = counter(ctx, :ed25519, main, counter_opts)
      certificates = [ctx.certs[:p256], ctx.certs[:ed25519]]
      {main, counter, certificates}
    end

    defp counter(ctx, key, parent, opts) do
      opts = Keyword.merge([content: TestCMS.signature_of(parent), content_type: nil], opts)
      TestCMS.sign(key, ctx.certs[key], opts)
    end

    defp with_counters(signer_info, counters),
      do:
        TestCMS.put_unsigned(signer_info, [
          TestCMS.attribute(:countersignature, Enum.map(counters, &{:raw, &1}))
        ])

    test "verified with countersignatures: true", ctx do
      {main, counter, certificates} = countersigned(ctx)
      si = with_counters(main, [counter])
      der = TestCMS.signed_data(certificates: certificates, signer_infos: [si])

      assert {:ok, %Verified{signers: [%{countersignatures: []}]}} = Cmsex.verify(der)

      assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der, countersignatures: true)
      assert [counter] = signer.countersignatures
      assert counter.index == 0
      assert counter.certificate == ctx.certs[:ed25519]
      assert counter.countersignatures == []
    end

    test "with trust, the countersigner's path too", ctx do
      {main, counter, certificates} = countersigned(ctx)
      si = with_counters(main, [counter])
      der = TestCMS.signed_data(certificates: [ctx.ca | certificates], signer_infos: [si])

      assert {:ok, %Verified{signers: [signer]}} =
               Cmsex.verify(der, countersignatures: true, trust: [ctx.root])

      assert [%{path: [_, _, cert]}] = signer.countersignatures
      assert cert == ctx.certs[:ed25519]
    end

    test "without signed attributes", ctx do
      main = TestCMS.sign(:p256, ctx.certs[:p256])

      counters = [
        counter(ctx, :ed25519, main, attributes: false),
        counter(ctx, :rsa2048, main, attributes: false)
      ]

      der =
        TestCMS.signed_data(
          certificates: [ctx.certs[:p256], ctx.certs[:ed25519], ctx.certs[:rsa2048]],
          signer_infos: [with_counters(main, counters)]
        )

      assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der, countersignatures: true)
      assert length(signer.countersignatures) == 2
    end

    test "that does not verify", ctx do
      {main, counter, certificates} = countersigned(ctx, tamper: true)

      der =
        TestCMS.signed_data(
          certificates: certificates,
          signer_infos: [with_counters(main, [counter])]
        )

      assert {:ok, _} = Cmsex.verify(der)

      assert {:error, %Error{reason: :invalid_signature, signer: [0, 0]} = error} =
               Cmsex.verify(der, countersignatures: true)

      assert Exception.message(error) == "countersignature 0 of signer 0: invalid signature"
    end

    test "over something else", ctx do
      {main, counter, certificates} = countersigned(ctx, content: "something else")

      der =
        TestCMS.signed_data(
          certificates: certificates,
          signer_infos: [with_counters(main, [counter])]
        )

      assert {:error, %Error{reason: :digest_mismatch, signer: [0, 0]}} =
               Cmsex.verify(der, countersignatures: true)
    end

    test "with a content type", ctx do
      {main, counter, certificates} = countersigned(ctx, content_type: :data)

      der =
        TestCMS.signed_data(
          certificates: certificates,
          signer_infos: [with_counters(main, [counter])]
        )

      assert {:error, %Error{reason: :invalid_attribute, detail: :content_type, signer: [0, 0]}} =
               Cmsex.verify(der, countersignatures: true)
    end

    test "nested", ctx do
      main = TestCMS.sign(:p256, ctx.certs[:p256])
      inner = counter(ctx, :ed25519, main, [])
      outer = counter(ctx, :p384, inner, [])
      bad = counter(ctx, :p384, inner, tamper: true)
      certificates = Enum.map([:p256, :ed25519, :p384], &ctx.certs[&1])

      si = with_counters(main, [with_counters(inner, [outer])])
      der = TestCMS.signed_data(certificates: certificates, signer_infos: [si])

      assert {:ok, %Verified{signers: [signer]}} = Cmsex.verify(der, countersignatures: true)
      assert [%{countersignatures: [%{certificate: cert}]}] = signer.countersignatures
      assert cert == ctx.certs[:p384]

      si = with_counters(main, [with_counters(inner, [outer, bad])])
      der = TestCMS.signed_data(certificates: certificates, signer_infos: [si])

      assert {:error, %Error{reason: :invalid_signature, signer: [0, 0, index]}} =
               Cmsex.verify(der, countersignatures: true)

      assert index in [0, 1]
    end

    test "unreadable", ctx do
      main = TestCMS.sign(:p256, ctx.certs[:p256])
      si = with_counters(main, [DER.encode({:seq, [{:int, 1}]})])
      der = TestCMS.signed_data(certificates: [ctx.certs[:p256]], signer_infos: [si])

      assert {:ok, _} = Cmsex.verify(der)

      assert {:error, %Error{reason: :malformed, signer: [0, 0]}} =
               Cmsex.verify(der, countersignatures: true)
    end

    test "more than max_signers", ctx do
      {main, counter, certificates} = countersigned(ctx)
      si = with_counters(main, [counter, counter, counter])
      der = TestCMS.signed_data(certificates: certificates, signer_infos: [si])

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_signers, signer: 0}} =
               Cmsex.verify(der, countersignatures: true, max_signers: 2)
    end
  end

  describe "options" do
    test "are checked", ctx do
      der = message(ctx, :p256)

      for opts <- [
            [unknown: 1],
            [content: 1],
            [content: {:digest, :sha256, "short"}],
            [content: {:digest, :sha3, <<0::256>>}],
            [content: {:stream, 1}],
            [certificates: "cert"],
            [certificates: [1]],
            [trust: "root"],
            [signers: :some],
            [path_validation: :none],
            [countersignatures: 1],
            [allow_sha1: "yes"],
            [min_rsa_bits: 0],
            [ed25519_digest: :loose],
            [max_signers: -1],
            :not_a_list
          ] do
        assert_raise ArgumentError, fn -> Cmsex.verify(der, opts) end
      end

      assert_raise ArgumentError, fn -> Cmsex.verify_each(der, signers: :any) end
    end

    test "verify! returns the result or raises", ctx do
      assert %Verified{} = Cmsex.verify!(message(ctx, :p256))

      assert_raise Error,
                   "signer 0: the message-digest attribute does not match the content",
                   fn ->
                     Cmsex.verify!(
                       message(ctx, :p256, content: "changed", sign: [content: "content"])
                     )
                   end
    end

    test "malformed input", _ctx do
      assert :malformed == reason(Cmsex.verify(<<0x30, 0x03, 1, 2>>))
      assert :invalid_pem == reason(Cmsex.verify("-----BEGIN CMS-----\n!!\n-----END CMS-----"))
      assert :malformed == reason(Cmsex.verify("not a message"))
      assert_raise ArgumentError, fn -> Cmsex.verify(:not_binary) end
    end
  end

  describe "the signature input" do
    # The signature with signed attributes covers the DER SET OF, not the
    # [0] IMPLICIT tag (RFC 5652, 5.4).
    test "is the SET, not the [0]", ctx do
      private = TestPKI.private(:p256)
      {:ok, c} = Cmsex.Certificate.parse(ctx.certs[:p256])
      md = TestCMS.attribute(:message_digest, [{:octets, Digest.hash(:sha256, "content")}])
      ct = TestCMS.attribute(:content_type, [{:oid, :data}])
      set = DER.encode({:set, [{:raw, ct}, {:raw, md}]})
      implicit = DER.retag(set, 0xA0)

      sign = fn tbs ->
        TestCMS.signer_info(
          sid: {:issuer_and_serial, c.issuer, c.serial},
          signed: {:raw, implicit},
          signature_algorithm: Algorithm.signature_identifier(:ecdsa, :sha256),
          signature: Cmsex.Key.sign(private, :ecdsa, :sha256, Digest.hash(:sha256, tbs), nil)
        )
      end

      good = TestCMS.signed_data(certificates: [ctx.certs[:p256]], signer_infos: [sign.(set)])
      bad = TestCMS.signed_data(certificates: [ctx.certs[:p256]], signer_infos: [sign.(implicit)])

      assert {:ok, _} = Cmsex.verify(good)
      assert :invalid_signature == reason(Cmsex.verify(bad))
    end
  end
end
