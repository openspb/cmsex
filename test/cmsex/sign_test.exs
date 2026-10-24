defmodule Cmsex.SignTest do
  use ExUnit.Case, async: true

  alias Cmsex.{
    Attribute,
    DER,
    Digest,
    Error,
    PEM,
    SignedData,
    Signer,
    SignerInfo,
    TestCMS,
    TestPKI
  }

  setup_all do
    root = TestPKI.cert({:p384, :root}, ca: true, subject: "Test Root")
    ca = TestPKI.cert({:p256, :ca}, ca: true, subject: "Test CA", issuer: {root, {:p384, :root}})

    certs =
      Map.new(
        [:rsa1024, :rsa2048, :p256, :p384, :p521, :brainpool256, :ed25519, :ed448],
        &{&1, TestPKI.cert(&1, issuer: {ca, {:p256, :ca}})}
      )

    %{root: root, ca: ca, certs: certs}
  end

  defp signer(ctx, key, fields \\ []),
    do: Map.merge(%{certificate: ctx.certs[key], key: TestPKI.key(key)}, Map.new(fields))

  defp reason({:error, %Error{reason: reason}}), do: reason

  defp signer_info(cms) do
    [si] = Cmsex.decode!(cms).signer_infos
    si
  end

  defp signed_types(si), do: si.signed_attributes |> Enum.map(& &1.type) |> Enum.sort()

  describe "signature schemes" do
    @schemes [
      {"RSA PKCS #1 v1.5", :rsa2048, [], :sha256, :rsa_encryption},
      {"RSA PKCS #1 v1.5 with SHA-224", :rsa2048, [digest: :sha224], :sha224, :rsa_encryption},
      {"RSA PKCS #1 v1.5 with SHA-384", :rsa2048, [digest: :sha384], :sha384, :rsa_encryption},
      {"RSA PKCS #1 v1.5 with SHA-512", :rsa2048, [digest: :sha512], :sha512, :rsa_encryption},
      {"RSASSA-PSS", :rsa2048, [rsa_padding: :pss], :sha256, :rsassa_pss},
      {"RSASSA-PSS with SHA-384", :rsa2048, [rsa_padding: :pss, digest: :sha384], :sha384,
       :rsassa_pss},
      {"RSASSA-PSS with SHA-512", :rsa2048, [rsa_padding: :pss, digest: :sha512], :sha512,
       :rsassa_pss},
      {"ECDSA P-256", :p256, [], :sha256, :ecdsa_with_sha256},
      {"ECDSA P-384", :p384, [digest: :sha384], :sha384, :ecdsa_with_sha384},
      {"ECDSA P-521", :p521, [digest: :sha512], :sha512, :ecdsa_with_sha512},
      {"ECDSA brainpoolP256r1", :brainpool256, [], :sha256, :ecdsa_with_sha256},
      {"Ed25519", :ed25519, [], :sha512, :ed25519},
      {"Ed448", :ed448, [], :shake256_len, :ed448}
    ]

    for {name, key, fields, digest, algorithm} <- @schemes do
      test "#{name}", ctx do
        assert {:ok, cms} = Cmsex.sign("content", signer(ctx, unquote(key), unquote(fields)))
        assert DER.der?(cms)

        assert {:ok, %{signers: [signer]} = verified} = Cmsex.verify(cms)
        assert verified.content == "content"
        assert signer.certificate == ctx.certs[unquote(key)]
        assert signer.deviations == []
        assert %DateTime{} = signer.signing_time

        sd = verified.signed_data
        assert sd.version == 1
        assert sd.digest_algorithms == [unquote(digest)]
        assert sd.certificates == [ctx.certs[unquote(key)]]
        assert sd.deviations == []

        si = signer.signer_info
        assert si.version == 1
        assert si.digest_algorithm == unquote(digest)
        assert si.signature_algorithm == unquote(algorithm)

        assert signed_types(si) ==
                 [:cms_algorithm_protection, :content_type, :message_digest, :signing_time]
      end

      test "#{name}, without signed attributes", ctx do
        assert {:ok, cms} =
                 Cmsex.sign("content", signer(ctx, unquote(key), unquote(fields)),
                   no_attributes: true
                 )

        assert {:ok, %{signers: [%{signer_info: si, signing_time: nil}]}} = Cmsex.verify(cms)
        assert si.signed_attributes == nil

        if unquote(key) == :ed448, do: assert(si.digest_algorithm == :shake256)
      end

      test "#{name}, detached", ctx do
        assert {:ok, p7s} =
                 Cmsex.sign("content", signer(ctx, unquote(key), unquote(fields)), detached: true)

        assert Cmsex.decode!(p7s).content == nil
        assert {:ok, %{content: nil}} = Cmsex.verify(p7s, content: "content")
        assert :digest_mismatch == reason(Cmsex.verify(p7s, content: "other"))
      end
    end

    test "the same bytes as an independent encoder", ctx do
      time = ~U[2026-10-23 12:00:00Z]
      extra = [DER.encode(Attribute.to_term(Attribute.signing_time(time)))]

      for {key, digest} <- [ed25519: :sha512, rsa2048: :sha256] do
        fields = [signing_time: time, algorithm_protection: false]
        {:ok, cms} = Cmsex.sign("content", signer(ctx, key, fields))

        expected =
          TestCMS.signed_data(
            digest_algorithms: [digest],
            certificates: [ctx.certs[key]],
            signer_infos: [TestCMS.sign(key, ctx.certs[key], extra: extra)]
          )

        assert cms == expected
      end
    end

    test "a key whose certificate is id-RSASSA-PSS", ctx do
      cert = TestPKI.cert(:rsa2048, issuer: {ctx.ca, {:p256, :ca}}, pss_key: %{hash: :sha384})
      signer = %{certificate: cert, key: TestPKI.key(:rsa2048)}

      assert {:ok, cms} = Cmsex.sign("content", signer)
      si = signer_info(cms)
      assert si.signature_algorithm == :rsassa_pss
      assert si.digest_algorithm == :sha384
      assert si.signature_parameters.salt_length == 48
      assert {:ok, _} = Cmsex.verify(cms)

      assert {:error, %Error{reason: :algorithm_mismatch, signer: 0}} =
               Cmsex.sign("content", Map.put(signer, :digest, :sha256))

      cert = TestPKI.cert(:rsa2048, issuer: {ctx.ca, {:p256, :ca}}, pss_key: true)
      assert {:ok, cms} = Cmsex.sign("content", %{signer | certificate: cert})
      assert signer_info(cms).signature_algorithm == :rsassa_pss
      assert {:ok, _} = Cmsex.verify(cms)
    end
  end

  describe "keys" do
    test "in PKCS #8, as records and as decoded PrivateKeyInfo", ctx do
      for key <- [:rsa2048, :p256, :ed25519, :ed448] do
        record = TestPKI.key(key)
        pkcs8 = TestPKI.pkcs8(record)

        for form <- [record, pkcs8, :public_key.der_decode(:PrivateKeyInfo, pkcs8)] do
          assert {:ok, cms} = Cmsex.sign("content", signer(ctx, key, key: form))
          assert {:ok, _} = Cmsex.verify(cms)
        end
      end
    end

    test "that cannot be read, or are not the certificate's", ctx do
      assert {:error, %Error{reason: :invalid_key, signer: 0}} =
               Cmsex.sign("content", signer(ctx, :p256, key: "junk"))

      assert :key_certificate_mismatch ==
               reason(Cmsex.sign("content", signer(ctx, :p256, key: TestPKI.key(:p384))))

      assert :key_certificate_mismatch ==
               reason(
                 Cmsex.sign("content", signer(ctx, :p256, key: TestPKI.key({:p256, :other})))
               )

      assert {:error, %Error{reason: :invalid_certificate, signer: 0}} =
               Cmsex.sign("content", signer(ctx, :p256, certificate: "junk"))
    end

    test "that do not sign", ctx do
      cert = TestPKI.cert(:x25519, issuer: {ctx.ca, {:p256, :ca}})
      key = TestPKI.montgomery_pkcs8(:x25519, TestPKI.key(:x25519))

      assert :key_mismatch == reason(Cmsex.sign("content", %{certificate: cert, key: key}))
    end

    test "RSA below min_rsa_bits", ctx do
      assert {:error, %Error{reason: :weak_key, detail: 1024}} =
               Cmsex.sign("content", signer(ctx, :rsa1024))

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :rsa1024), min_rsa_bits: 1024)
      assert {:ok, _} = Cmsex.verify(cms, min_rsa_bits: 1024)

      assert :weak_key == reason(Cmsex.sign("content", signer(ctx, :rsa2048), min_rsa_bits: 3072))
    end

    test "EdDSA takes its own digest", ctx do
      assert {:error, %Error{reason: :algorithm_mismatch, detail: {:sha256, :ed25519}}} =
               Cmsex.sign("content", signer(ctx, :ed25519, digest: :sha256))

      assert {:ok, _} = Cmsex.sign("content", signer(ctx, :ed25519, digest: :sha512))

      assert {:error, %Error{reason: :algorithm_mismatch, detail: {:sha512, :ed448}}} =
               Cmsex.sign("content", signer(ctx, :ed448, digest: :sha512))
    end

    test "SHA-1 is never used", ctx do
      assert_raise ArgumentError, fn ->
        Cmsex.sign("content", signer(ctx, :p256, digest: :sha1))
      end

      assert_raise ArgumentError, fn ->
        Cmsex.sign("content", signer(ctx, :p256), digest: :sha1)
      end
    end
  end

  describe "a key as a function" do
    defp external(key, test_pid \\ nil) do
      private = TestPKI.private(key)

      fn request ->
        if test_pid, do: send(test_pid, {:request, request})
        data = request.digest || request.tbs
        {:ok, Cmsex.Key.sign(private, request.scheme, request.hash, data, request.pss)}
      end
    end

    test "signs for each scheme", ctx do
      for {key, fields} <- [
            rsa2048: [],
            rsa2048: [rsa_padding: :pss],
            p256: [],
            p384: [digest: :sha384],
            ed25519: [],
            ed448: []
          ] do
        fields = [key: external(key, self())] ++ fields
        assert {:ok, cms} = Cmsex.sign("content", signer(ctx, key, fields))
        assert {:ok, _} = Cmsex.verify(cms)

        assert_received {:request, request}
        si = signer_info(cms)
        assert request.tbs == SignerInfo.signed_attributes_tbs(si)

        case request.scheme do
          scheme when scheme in [:ed25519, :ed448] ->
            assert request.hash == nil
            assert request.digest == nil

          _ ->
            assert request.digest == Digest.hash(request.hash, request.tbs)
        end
      end
    end

    test "the request", ctx do
      fields = [key: external(:rsa2048, self()), rsa_padding: :pss, digest: :sha384]
      assert {:ok, _} = Cmsex.sign("content", signer(ctx, :rsa2048, fields))

      assert_received {:request, request}
      assert request.scheme == :rsa_pss
      assert request.hash == :sha384
      assert request.pss == %{hash: :sha384, mgf_hash: :sha384, salt_length: 48, trailer_field: 1}
      assert byte_size(request.digest) == 48

      assert {:ok, _} =
               Cmsex.sign("content", signer(ctx, :ed25519, key: external(:ed25519, self())),
                 no_attributes: true
               )

      assert_received {:request, %{tbs: "content", digest: nil, scheme: :ed25519, pss: nil}}
    end

    test "that fails", ctx do
      fun = fn _ -> {:error, :token_removed} end

      assert {:error, %Error{reason: :signer_failed, detail: :token_removed, signer: 0}} =
               Cmsex.sign("content", signer(ctx, :p256, key: fun))

      fun = fn _ -> :ok end

      assert {:error, %Error{reason: :signer_failed, detail: :unexpected_return}} =
               Cmsex.sign("content", signer(ctx, :p256, key: fun))
    end

    test "with the wrong key", ctx do
      fields = [key: external(:p384)]

      assert {:error, %Error{reason: :signer_failed, detail: :invalid_signature}} =
               Cmsex.sign("content", signer(ctx, :p256, fields))

      fields = [key: external({:p256, :other}), verify_signature: false]
      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, fields))
      assert :invalid_signature == reason(Cmsex.verify(cms))
    end
  end

  describe "content" do
    test "as a stream", ctx do
      content = :binary.copy("0123456789", 10_000)
      stream = Stream.map(0..99, &binary_part(content, &1 * 1000, 1000))

      signers = [
        signer(ctx, :p256),
        signer(ctx, :ed25519),
        signer(ctx, :rsa2048, digest: :sha384)
      ]

      assert {:ok, p7s} = Cmsex.sign({:stream, stream}, signers)
      sd = Cmsex.decode!(p7s)
      assert sd.content == nil
      assert sd.digest_algorithms == [:sha256, :sha384, :sha512]

      assert {:ok, %{signers: [_, _, _]}} = Cmsex.verify(p7s, content: content)
      assert {:ok, %{signers: [_, _, _]}} = Cmsex.verify(p7s, content: {:stream, stream})
    end

    test "as a ready digest", ctx do
      digest = Digest.hash(:sha384, "content")
      assert {:ok, p7s} = Cmsex.sign({:digest, :sha384, digest}, signer(ctx, :p384))
      assert signer_info(p7s).digest_algorithm == :sha384
      assert {:ok, _} = Cmsex.verify(p7s, content: "content")

      assert {:error, %Error{reason: :content_required, detail: :sha256}} =
               Cmsex.sign({:digest, :sha384, digest}, signer(ctx, :p256, digest: :sha256))

      assert :content_required ==
               reason(Cmsex.sign({:digest, :sha384, digest}, signer(ctx, :ed25519)))

      digest = Digest.hash(:sha512, "content")
      assert {:ok, p7s} = Cmsex.sign({:digest, :sha512, digest}, signer(ctx, :ed25519))
      assert {:ok, _} = Cmsex.verify(p7s, content: "content")
    end

    test "a stream or a digest is always detached", ctx do
      digest = {:digest, :sha256, Digest.hash(:sha256, "content")}

      for content <- [{:stream, ["content"]}, digest] do
        assert_raise ArgumentError, fn ->
          Cmsex.sign(content, signer(ctx, :p256), detached: false)
        end

        assert_raise ArgumentError, fn ->
          Cmsex.sign(content, signer(ctx, :p256), no_attributes: true)
        end

        assert {:ok, _} = Cmsex.sign(content, signer(ctx, :p256), detached: true)
      end
    end

    test "another content type", ctx do
      type = {1, 2, 840, 113_549, 1, 9, 16, 1, 4}
      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256), content_type: type)

      assert {:ok, %{content_type: :tst_info, signed_data: sd}} = Cmsex.verify(cms)
      assert sd.version == 3

      assert {:ok, _} = Cmsex.sign("content", signer(ctx, :p256), content_type: :tst_info)

      assert_raise ArgumentError, fn ->
        Cmsex.sign("content", signer(ctx, :p256), content_type: type, no_attributes: true)
      end

      assert_raise ArgumentError, fn ->
        Cmsex.sign("content", signer(ctx, :p256), content_type: :no_such_name)
      end
    end

    test "empty content", ctx do
      assert {:ok, cms} = Cmsex.sign("", signer(ctx, :p256))
      assert {:ok, %{content: ""}} = Cmsex.verify(cms)
    end
  end

  describe "attributes" do
    test "the signing time", ctx do
      time = ~U[2026-10-23 12:34:56.789Z]

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, signing_time: time))
      assert {:ok, %{signers: [%{signing_time: ~U[2026-10-23 12:34:56Z]}]}} = Cmsex.verify(cms)

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, signing_time: false))
      refute :signing_time in signed_types(signer_info(cms))

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256), signing_time: false)
      refute :signing_time in signed_types(signer_info(cms))

      fields = [signing_time: true]
      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, fields), signing_time: false)
      assert :signing_time in signed_types(signer_info(cms))

      before = DateTime.utc_now() |> DateTime.truncate(:second)
      {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256))
      {:ok, signed} = SignerInfo.signing_time(signer_info(cms))
      assert DateTime.compare(signed, before) in [:eq, :gt]
    end

    test "a signing time after 2049 is a GeneralizedTime", ctx do
      time = ~U[2050-01-01 00:00:00Z]
      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, signing_time: time))

      si = signer_info(cms)
      assert si.deviations == []

      assert %Attribute{values: [<<0x18, 15, "20500101000000Z">>]} =
               SignerInfo.attribute(si, :signing_time)

      assert {:ok, %{signers: [%{signing_time: ^time}]}} = Cmsex.verify(cms)
    end

    test "CMSAlgorithmProtection", ctx do
      {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256))

      %Attribute{values: [value]} =
        SignerInfo.attribute(signer_info(cms), :cms_algorithm_protection)

      assert value ==
               DER.encode(
                 {:seq,
                  [
                    {:seq, [{:oid, :sha256}]},
                    {:raw, DER.retag(DER.encode({:seq, [{:oid, :ecdsa_with_sha256}]}), 0xA1)}
                  ]}
               )

      {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, algorithm_protection: false))
      refute :cms_algorithm_protection in signed_types(signer_info(cms))

      {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256), algorithm_protection: false)
      refute :cms_algorithm_protection in signed_types(signer_info(cms))
    end

    test "more signed attributes", ctx do
      attributes = [
        Attribute.signing_certificate_v2(ctx.certs[:p256]),
        Attribute.content_hint(:data, "a test"),
        Attribute.new({1, 2, 3, 4}, [DER.encode({:utf8, "x"})])
      ]

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, signed_attributes: attributes))
      assert {:ok, %{signers: [%{signer_info: si}]}} = Cmsex.verify(cms)

      assert signed_types(si) == [
               :cms_algorithm_protection,
               :content_hint,
               :content_type,
               :message_digest,
               :signing_certificate_v2,
               :signing_time,
               {1, 2, 3, 4}
             ]

      bad = [Attribute.signing_certificate_v2(ctx.certs[:p384])]

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, signed_attributes: bad))
      assert :signing_certificate_mismatch == reason(Cmsex.verify(cms))
    end

    test "that the library writes itself", ctx do
      for attribute <- [
            Attribute.content_type(:data),
            %Attribute{type: :message_digest, values: [DER.encode({:octets, "x"})]},
            Attribute.signing_time(DateTime.utc_now())
          ] do
        assert_raise ArgumentError, fn ->
          Cmsex.sign("content", signer(ctx, :p256, signed_attributes: [attribute]))
        end
      end

      time = Attribute.signing_time(~U[2026-10-23 12:00:00Z])
      fields = [signing_time: false, signed_attributes: [time]]
      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256, fields))
      assert {:ok, %{signers: [%{signing_time: ~U[2026-10-23 12:00:00Z]}]}} = Cmsex.verify(cms)

      assert_raise ArgumentError, fn ->
        Cmsex.sign("content", signer(ctx, :p256, signed_attributes: [time]), no_attributes: true)
      end
    end

    test "unsigned attributes", ctx do
      attribute = Attribute.new({1, 2, 3, 4}, [DER.encode({:int, 7})])

      assert {:ok, cms} =
               Cmsex.sign("content", signer(ctx, :p256, unsigned_attributes: [attribute]))

      assert {:ok, %{signers: [%{signer_info: si}]}} = Cmsex.verify(cms)
      assert si.unsigned_attributes == [attribute]
    end
  end

  describe "signers" do
    test "several", ctx do
      signers = [signer(ctx, :rsa2048), signer(ctx, :p256), signer(ctx, :ed25519)]

      assert {:ok, cms} = Cmsex.sign("content", signers)
      assert {:ok, %{signers: verified, signed_data: sd}} = Cmsex.verify(cms)
      assert length(verified) == 3
      assert sd.digest_algorithms == [:sha256, :sha512]

      assert Enum.sort(sd.certificates) ==
               Enum.sort(Enum.map([:rsa2048, :p256, :ed25519], &ctx.certs[&1]))

      assert DER.der?(cms)
    end

    test "an error carries the position of the signer", ctx do
      signers = [signer(ctx, :p256), signer(ctx, :p384, key: "junk")]
      assert {:error, %Error{reason: :invalid_key, signer: 1}} = Cmsex.sign("content", signers)

      fun = fn _ -> {:error, :busy} end
      signers = [signer(ctx, :p256), signer(ctx, :p384), signer(ctx, :ed25519, key: fun)]
      assert {:error, %Error{reason: :signer_failed, signer: 2}} = Cmsex.sign("content", signers)
    end

    test "as structs, maps and keyword lists", ctx do
      map = signer(ctx, :p256)
      keyword = Map.to_list(signer(ctx, :p384))
      struct = Signer.new!(signer(ctx, :ed25519))

      for signers <- [map, keyword, struct, [map, keyword, struct]] do
        assert {:ok, cms} = Cmsex.sign("content", signers)
        assert {:ok, _} = Cmsex.verify(cms)
      end
    end

    test "by subject key identifier", ctx do
      assert {:ok, cms} =
               Cmsex.sign("content", signer(ctx, :p256, identifier: :subject_key_identifier))

      sd = Cmsex.decode!(cms)
      assert sd.version == 3
      assert [%SignerInfo{version: 3, sid: {:subject_key_identifier, _}}] = sd.signer_infos
      assert {:ok, _} = Cmsex.verify(cms)

      assert {:ok, cms} =
               Cmsex.sign("content", signer(ctx, :p256), identifier: :subject_key_identifier)

      assert Cmsex.decode!(cms).version == 3

      cert = TestPKI.cert({:p256, :no_ski}, issuer: {ctx.ca, {:p256, :ca}}, ski: false)

      signer = %{
        certificate: cert,
        key: TestPKI.key({:p256, :no_ski}),
        identifier: :subject_key_identifier
      }

      assert {:error, %Error{reason: :invalid_certificate, detail: :subject_key_identifier}} =
               Cmsex.sign("content", signer)
    end
  end

  describe "certificates and revocation lists" do
    test "the signers' with their chains, by default", ctx do
      signers = [
        signer(ctx, :p256, chain: [ctx.ca, ctx.root]),
        signer(ctx, :p384, chain: [ctx.ca])
      ]

      assert {:ok, cms} = Cmsex.sign("content", signers)

      certs = Cmsex.certificates!(cms)
      assert Enum.sort(certs) == Enum.sort([ctx.certs[:p256], ctx.certs[:p384], ctx.ca, ctx.root])

      assert {:ok, %{signers: [%{path: [_, _, _]}, %{path: [_, _, _]}]}} =
               Cmsex.verify(cms, trust: [ctx.root])
    end

    test "none, or a given list", ctx do
      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256), certificates: :none)
      assert Cmsex.certificates!(cms) == []
      assert :signer_not_found == reason(Cmsex.verify(cms))
      assert {:ok, _} = Cmsex.verify(cms, certificates: [ctx.certs[:p256]])

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256), certificates: [ctx.ca])
      assert Cmsex.certificates!(cms) == [ctx.ca]

      assert {:error, %Error{reason: :invalid_certificate, signer: nil}} =
               Cmsex.sign("content", signer(ctx, :p256), certificates: ["junk"])

      assert {:error, %Error{reason: :invalid_certificate, detail: :chain, signer: 0}} =
               Cmsex.sign("content", signer(ctx, :p256, chain: ["junk"]))
    end

    test "revocation lists", ctx do
      crl = File.read!(Path.expand("../fixtures/rfc4134/CarlRSACRLEmpty.crl", __DIR__))

      assert {:ok, cms} = Cmsex.sign("content", signer(ctx, :p256), crls: [crl])
      assert Cmsex.decode!(cms).crls == [crl]

      assert {:error, %Error{reason: :malformed, detail: :crls}} =
               Cmsex.sign("content", signer(ctx, :p256), crls: ["junk"])
    end
  end

  describe "certs_only/2" do
    test "writes a bundle", ctx do
      crl = File.read!(Path.expand("../fixtures/rfc4134/CarlRSACRLEmpty.crl", __DIR__))
      certs = [ctx.certs[:p256], ctx.ca, ctx.root]

      assert {:ok, p7b} = Cmsex.certs_only(certs, crls: [crl])
      assert DER.der?(p7b)

      assert %SignedData{} = sd = Cmsex.decode!(p7b)
      assert sd.version == 1
      assert sd.digest_algorithms == []
      assert sd.content == nil
      assert sd.content_type == :data
      assert sd.signer_infos == []
      assert sd.crls == [crl]
      assert Enum.sort(sd.certificates) == Enum.sort(certs)

      assert :no_signers == reason(Cmsex.verify(p7b))
      assert Enum.sort(Cmsex.certificates!(PEM.encode(p7b, :pkcs7))) == Enum.sort(certs)
    end

    test "empty, and with bad input", ctx do
      assert {:ok, p7b} = Cmsex.certs_only([])
      assert Cmsex.certificates!(p7b) == []

      assert :invalid_certificate == reason(Cmsex.certs_only(["junk"]))
      assert :malformed == reason(Cmsex.certs_only([ctx.ca], crls: ["junk"]))
      assert_raise ArgumentError, fn -> Cmsex.certs_only(:no) end
      assert_raise ArgumentError, fn -> Cmsex.certs_only([ctx.ca], other: 1) end
      assert_raise Error, fn -> Cmsex.certs_only!(["junk"]) end
      assert is_binary(Cmsex.certs_only!([ctx.ca]))
    end
  end

  describe "arguments" do
    test "options are checked", ctx do
      signer = signer(ctx, :p256)

      for opts <- [
            [unknown: 1],
            [detached: 1],
            [no_attributes: "yes"],
            [content_type: "data"],
            [certificates: :all],
            [certificates: [1]],
            [crls: "crl"],
            [min_rsa_bits: 0],
            [digest: :md5],
            [rsa_padding: :oaep],
            [identifier: :name],
            [signing_time: "now"],
            [algorithm_protection: nil],
            :not_a_list
          ] do
        assert_raise ArgumentError, fn -> Cmsex.sign("content", signer, opts) end
      end

      for content <- [:atom, {:stream, 1}, {:digest, :sha256, "short"}, ["io", "list"]] do
        assert_raise ArgumentError, fn -> Cmsex.sign(content, signer) end
      end

      for signers <- [[], :signer, "signer", [1]] do
        assert_raise ArgumentError, fn -> Cmsex.sign("content", signers) end
      end
    end

    test "signer fields are checked", ctx do
      good = signer(ctx, :p256)

      for fields <- [
            %{other: 1},
            %{certificate: nil},
            %{key: 1},
            %{key: fn -> :ok end},
            %{chain: "ca"},
            %{digest: :sha1},
            %{rsa_padding: :none},
            %{identifier: :serial},
            %{signing_time: ~D[2026-10-23]},
            %{algorithm_protection: 1},
            %{signed_attributes: [1]},
            %{unsigned_attributes: "x"},
            %{verify_signature: nil}
          ] do
        assert_raise ArgumentError, fn -> Signer.new!(Map.merge(good, fields)) end
      end

      assert_raise ArgumentError, fn -> Signer.new!(%{certificate: ctx.certs[:p256]}) end
      assert_raise ArgumentError, fn -> Signer.new!(%{key: TestPKI.key(:p256)}) end
      assert_raise ArgumentError, fn -> Signer.new!([1, 2]) end
      assert_raise ArgumentError, fn -> Signer.new!("signer") end
    end

    test "the key is not shown", ctx do
      pkcs8 = TestPKI.pkcs8(TestPKI.key(:p256))
      signer = Signer.new!(signer(ctx, :p256, key: pkcs8))
      inspected = inspect(signer, limit: :infinity, printable_limit: :infinity)

      refute inspected =~ "key:"
      refute inspected =~ inspect(pkcs8, limit: :infinity)

      message = Exception.message(catch_error(Signer.new!(%{signer | chain: pkcs8})))
      refute message =~ inspect(binary_part(pkcs8, 0, 8))

      # A key given in place of a signer.
      record = TestPKI.key(:p256)

      for signers <- [record, [record], [pkcs8, ctx.certs[:p256]]] do
        message = Exception.message(catch_error(Cmsex.sign("content", signers)))
        refute message =~ "ECPrivateKey"
        refute message =~ inspect(binary_part(pkcs8, 0, 8))
      end
    end

    test "sign! returns the message or raises", ctx do
      assert is_binary(Cmsex.sign!("content", signer(ctx, :p256)))

      assert_raise Error, "signer 0: the private key cannot be read", fn ->
        Cmsex.sign!("content", signer(ctx, :p256, key: "junk"))
      end
    end
  end
end
