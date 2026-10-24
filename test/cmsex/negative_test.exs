defmodule Cmsex.NegativeTest do
  use ExUnit.Case, async: true

  # The negative corpus: each case starts from a valid message made here
  # and changes one thing. N1 to N40 follow the list of the design notes;
  # several are also checked, in more detail, in verify_test.exs.

  import Bitwise

  alias Cmsex.{Algorithm, DER, Digest, Error, Signer, TestCMS, TestFixtures, TestPKI}

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)
  @content "the content of the negative corpus"
  @time ~U[2026-01-02 03:04:05Z]

  setup_all do
    root = TestPKI.cert({:p256, :negative_root}, ca: true, subject: "Negative Root")
    issuer = {root, {:p256, :negative_root}}
    certs = Map.new([:rsa2048, :rsa_e3, :p256, :ed25519], &{&1, TestPKI.cert(&1, issuer: issuer)})
    %{root: root, certs: certs}
  end

  # A message signed by the library, with a fixed signing time.
  defp signed(ctx, key, opts \\ []) do
    signer = %Signer{certificate: ctx.certs[key], key: TestPKI.key(key), signing_time: @time}
    Cmsex.sign!(@content, signer, opts)
  end

  # A message with one SignerInfo written field by field.
  defp built(ctx, key, opts, signed_data_opts \\ []) do
    signer_info = TestCMS.sign(key, ctx.certs[key], Keyword.put_new(opts, :content, @content))

    [content: @content, certificates: [ctx.certs[key]], signer_infos: [signer_info]]
    |> Keyword.merge(signed_data_opts)
    |> TestCMS.signed_data()
  end

  defp reason({:error, %Error{reason: reason}}), do: reason
  defp reason({:ok, _}), do: :ok

  defp flip_at(bin, offset) do
    <<head::binary-size(offset), byte, rest::binary>> = bin
    <<head::binary, bxor(byte, 1), rest::binary>>
  end

  defp offset_of(bin, pattern) do
    {offset, _length} = :binary.match(bin, pattern)
    offset
  end

  defp attribute(type, values), do: TestCMS.attribute(type, values)

  test "N1: empty input, one byte, garbage", _ctx do
    for input <- ["", <<0x30>>, <<0>>, "not a CMS message at all"] do
      assert reason(Cmsex.decode(input)) == :malformed
      assert reason(Cmsex.verify(input)) == :malformed
    end
  end

  test "N2: a small message cut at every position", ctx do
    der = signed(ctx, :ed25519, no_attributes: true)

    for size <- 0..(byte_size(der) - 1) do
      assert reason(Cmsex.decode(binary_part(der, 0, size))) == :malformed,
             "cut at #{size} of #{byte_size(der)}"
    end
  end

  test "N3: a length longer than the input", ctx do
    <<0x30, 0x82, length::16, rest::binary>> = signed(ctx, :ed25519)
    assert reason(Cmsex.decode(<<0x30, 0x82, length + 10::16, rest::binary>>)) == :malformed
  end

  test "N4: bytes after the ContentInfo", ctx do
    der = signed(ctx, :ed25519)
    assert reason(Cmsex.decode(der <> <<0>>)) == :malformed
    assert reason(Cmsex.decode(der <> der)) == :malformed
  end

  test "N5: nesting beyond max_depth", ctx do
    nested = Enum.reduce(1..40, :null, fn _, inner -> {:seq, [inner]} end)
    der = DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, nested}]})

    assert {:error, %Error{reason: :limit_exceeded, detail: :max_depth}} = Cmsex.decode(der)

    assert {:error, %Error{reason: :limit_exceeded, detail: :max_depth}} =
             Cmsex.decode(signed(ctx, :ed25519), max_depth: 4)
  end

  test "N6: an indefinite length without its end-of-contents", ctx do
    ber = TestCMS.to_ber(signed(ctx, :ed25519))
    assert {:ok, _} = Cmsex.decode(ber)
    assert reason(Cmsex.decode(binary_part(ber, 0, byte_size(ber) - 2))) == :malformed
  end

  test "N7: a ContentInfo with id-envelopedData" do
    der = DER.encode({:seq, [{:oid, :enveloped_data}, {:explicit, 0, {:seq, [{:int, 0}]}}]})
    assert reason(Cmsex.verify(der)) == :unsupported_content_type
  end

  test "N8: a certs-only message in verify/2", ctx do
    assert reason(Cmsex.verify(Cmsex.certs_only!([ctx.certs[:p256]]))) == :no_signers
  end

  test "N9: a detached message without :content", ctx do
    assert reason(Cmsex.verify(signed(ctx, :p256, detached: true))) == :content_required
  end

  test "N10: the content inside and :content", ctx do
    assert reason(Cmsex.verify(signed(ctx, :p256), content: @content)) == :unexpected_content
  end

  test "N11: a byte of the eContent changed", ctx do
    der = signed(ctx, :rsa2048)
    assert reason(Cmsex.verify(flip_at(der, offset_of(der, @content)))) == :digest_mismatch
  end

  test "N12: a byte of the signed attributes changed", ctx do
    der = signed(ctx, :rsa2048)

    # In the signing time, which still reads as a time.
    time = offset_of(der, "260102030405Z")
    assert reason(Cmsex.verify(flip_at(der, time + 11))) == :invalid_signature

    # In the message digest.
    digest = offset_of(der, Digest.hash(:sha256, @content))
    assert reason(Cmsex.verify(flip_at(der, digest))) == :digest_mismatch

    # In a length, which breaks the structure.
    <<_::binary-size(digest - 1), 0x20, _::binary>> = der
    assert reason(Cmsex.verify(flip_at(der, digest - 1))) == :malformed
  end

  test "N13: a byte of the signature changed", ctx do
    der = signed(ctx, :rsa2048)
    {:ok, %{signer_infos: [signer_info]}} = Cmsex.decode(der)
    signature = offset_of(der, signer_info.signature)

    for offset <- [signature, signature + 100, signature + byte_size(signer_info.signature) - 1] do
      assert reason(Cmsex.verify(flip_at(der, offset))) == :invalid_signature
    end
  end

  test "N14: no message-digest", ctx do
    cert = ctx.certs[:p256]
    {:ok, certificate} = Cmsex.Certificate.parse(cert)

    signer_info =
      TestCMS.signer_info(
        sid: {:issuer_and_serial, certificate.issuer, certificate.serial},
        signed: [attribute(:content_type, [{:oid, :data}])],
        signature_algorithm: {:seq, [{:oid, :ecdsa_with_sha256}]}
      )

    der =
      TestCMS.signed_data(content: @content, certificates: [cert], signer_infos: [signer_info])

    assert {:error, %Error{reason: :missing_attribute, detail: :message_digest}} =
             Cmsex.verify(der)
  end

  test "N15: no content-type", ctx do
    assert {:error, %Error{reason: :missing_attribute, detail: :content_type}} =
             Cmsex.verify(built(ctx, :p256, content_type: nil))
  end

  test "N16: a content-type other than the eContentType", ctx do
    assert reason(Cmsex.verify(built(ctx, :p256, content_type: :signed_data))) ==
             :content_type_mismatch
  end

  test "N17: a message-digest with two values", ctx do
    cert = ctx.certs[:p256]
    {:ok, certificate} = Cmsex.Certificate.parse(cert)
    digest = Digest.hash(:sha256, @content)

    signer_info =
      TestCMS.signer_info(
        sid: {:issuer_and_serial, certificate.issuer, certificate.serial},
        signed: [
          attribute(:content_type, [{:oid, :data}]),
          attribute(:message_digest, [{:octets, digest}, {:octets, digest}])
        ],
        signature_algorithm: {:seq, [{:oid, :ecdsa_with_sha256}]}
      )

    der =
      TestCMS.signed_data(content: @content, certificates: [cert], signer_infos: [signer_info])

    assert reason(Cmsex.verify(der)) == :invalid_attribute
  end

  test "N18: a signing-time repeated", ctx do
    time = attribute(:signing_time, [{:time, @time}])
    assert reason(Cmsex.verify(built(ctx, :p256, extra: [time, time]))) == :invalid_attribute
  end

  test "N19: a signing-time that is neither UTCTime nor GeneralizedTime", ctx do
    octets = attribute(:signing_time, [{:octets, "260102030405Z"}])
    assert reason(Cmsex.verify(built(ctx, :p256, extra: [octets]))) == :invalid_attribute

    # 2030 written as GeneralizedTime is tolerated, and said.
    general = attribute(:signing_time, [{:primitive, 0x18, "20300102030405Z"}])
    assert {:ok, %{signers: [signer]}} = Cmsex.verify(built(ctx, :p256, extra: [general]))
    assert signer.signing_time == ~U[2030-01-02 03:04:05Z]
    assert :signing_time_encoding in signer.deviations
  end

  defp protection(digest, signature) do
    attribute(:cms_algorithm_protection, [
      {:seq,
       [Algorithm.digest_identifier(digest), {:raw, DER.retag(DER.encode(signature), 0xA1)}]}
    ])
  end

  test "N20: CMSAlgorithmProtection with another digest", ctx do
    signature = {:seq, [{:oid, :ecdsa_with_sha256}]}

    assert {:ok, _} = Cmsex.verify(built(ctx, :p256, extra: [protection(:sha256, signature)]))

    assert reason(Cmsex.verify(built(ctx, :p256, extra: [protection(:sha384, signature)]))) ==
             :algorithm_mismatch
  end

  test "N21: CMSAlgorithmProtection with a macAlgorithm", ctx do
    mac = {:seq, [{:oid, {1, 2, 840, 113_549, 2, 9}}, :null]}

    value =
      {:seq, [Algorithm.digest_identifier(:sha256), {:raw, DER.retag(DER.encode(mac), 0xA2)}]}

    attr = attribute(:cms_algorithm_protection, [value])
    assert reason(Cmsex.verify(built(ctx, :p256, extra: [attr]))) == :invalid_attribute
  end

  test "N22: sha256WithRSAEncryption with digestAlgorithm sha384", ctx do
    der =
      built(ctx, :rsa2048,
        digest: :sha384,
        signature_algorithm: {:seq, [{:oid, :sha256_with_rsa_encryption}, :null]}
      )

    assert reason(Cmsex.verify(der)) == :algorithm_mismatch
  end

  test "N23: RSASSA-PSS with a hash other than the digest algorithm", ctx do
    der =
      built(ctx, :rsa2048,
        pss: true,
        digest: :sha256,
        signature_algorithm: Algorithm.signature_identifier(:rsa_pss, :sha384)
      )

    assert reason(Cmsex.verify(der)) == :algorithm_mismatch
  end

  test "N24: id-ct-TSTInfo without signed attributes", ctx do
    der = built(ctx, :p256, [attributes: false], content_type: :tst_info)
    assert {:error, %Error{reason: :missing_attribute}} = Cmsex.verify(der)
  end

  test "N25: SHA-1 without allow_sha1" do
    der = TestFixtures.read!("o3_rsa_sha1.p7s")
    assert {:error, %Error{reason: :weak_algorithm, detail: :sha1}} = Cmsex.verify(der)
    assert {:ok, _} = Cmsex.verify(der, allow_sha1: true)
  end

  test "N26: MD5", ctx do
    der =
      built(ctx, :rsa2048,
        digest: :md5,
        signature_algorithm: {:seq, [{:oid, :rsa_encryption}, :null]}
      )

    assert {:error, %Error{reason: :weak_algorithm, detail: :md5}} = Cmsex.verify(der)
    assert {:error, %Error{reason: :weak_algorithm}} = Cmsex.verify(der, allow_sha1: true)
  end

  test "N27: RSA of 1024 bits" do
    der = TestFixtures.read!("o3_rsa1024.p7s")
    assert {:error, %Error{reason: :weak_key, detail: 1024}} = Cmsex.verify(der)
  end

  test "N28: DSA" do
    der = File.read!(Path.join(@rfc4134, "4.1.bin"))
    assert reason(Cmsex.verify(der, allow_sha1: true)) == :unsupported_algorithm
  end

  test "N29: an unknown signature algorithm", ctx do
    # An OID under the arc of RFC 5612 for documentation.
    unknown = {:seq, [{:oid, {1, 3, 6, 1, 4, 1, 32_473, 1}}]}

    assert {:error, %Error{reason: :unsupported_algorithm, detail: {1, 3, 6, 1, 4, 1, 32_473, 1}}} =
             Cmsex.verify(built(ctx, :p256, signature_algorithm: unknown))
  end

  test "N30: a sid with no certificate for it", ctx do
    der = built(ctx, :p256, [], certificates: [ctx.certs[:rsa2048]])
    assert reason(Cmsex.verify(der)) == :signer_not_found
  end

  test "N31: an EC certificate for an rsaEncryption signature", ctx do
    signer_info =
      TestCMS.sign(:rsa2048, ctx.certs[:p256],
        content: @content,
        signature_algorithm: {:seq, [{:oid, :rsa_encryption}, :null]}
      )

    der =
      TestCMS.signed_data(
        content: @content,
        certificates: [ctx.certs[:p256]],
        signer_infos: [signer_info]
      )

    assert reason(Cmsex.verify(der)) == :key_mismatch
  end

  test "N32: a false certificate with the same issuer and serial, before the true one", ctx do
    {:ok, real} = Cmsex.Certificate.parse(ctx.certs[:p256])

    fake =
      TestPKI.cert({:p256, :fake},
        subject: "Test p256",
        serial: real.serial,
        issuer: {ctx.root, {:p256, :negative_root}}
      )

    signer_info = TestCMS.sign(:p256, ctx.certs[:p256], content: @content)

    der =
      TestCMS.signed_data(
        content: @content,
        certificates: [fake, ctx.certs[:p256]],
        signer_infos: [signer_info]
      )

    assert {:ok, %{signers: [signer]}} = Cmsex.verify(der, trust: [ctx.root])
    assert signer.certificate == ctx.certs[:p256]
  end

  defp two_signers(ctx) do
    good = TestCMS.sign(:p256, ctx.certs[:p256], content: @content)
    bad = TestCMS.sign(:ed25519, ctx.certs[:ed25519], content: @content, tamper: true)

    TestCMS.signed_data(
      content: @content,
      digest_algorithms: [:sha256, :sha512],
      certificates: [ctx.certs[:p256], ctx.certs[:ed25519]],
      signer_infos: [good, bad]
    )
  end

  test "N33: two signers, one invalid, signers: :all", ctx do
    assert {:error, %Error{reason: :invalid_signature, signer: 1}} =
             Cmsex.verify(two_signers(ctx))
  end

  test "N34: two signers, one invalid, signers: :any", ctx do
    assert {:ok, %{signers: [signer]}} = Cmsex.verify(two_signers(ctx), signers: :any)
    assert signer.index == 0
    assert signer.certificate == ctx.certs[:p256]
  end

  test "N35: Ed25519 with SHA-256 and ed25519_digest: :strict" do
    der = TestFixtures.read!("o3_ed25519_sha256.p7s")
    assert {:ok, _} = Cmsex.verify(der)
    assert reason(Cmsex.verify(der, ed25519_digest: :strict)) == :algorithm_mismatch
  end

  test "N36: a root that did not issue the chain", ctx do
    other = TestPKI.cert({:p256, :other_root}, ca: true, subject: "Other Root")
    der = signed(ctx, :p256)
    assert {:ok, _} = Cmsex.verify(der, trust: [ctx.root])
    assert reason(Cmsex.verify(der, trust: [other])) == :untrusted
  end

  test "N37: an RSA e=3 signature with garbage after the DigestInfo", ctx do
    {:rsa, _private, n, 3} = TestPKI.private(:rsa_e3)
    size = byte_size(:binary.encode_unsigned(n))

    digest_info =
      DER.encode(
        {:seq, [Algorithm.digest_identifier(:sha256), {:octets, Digest.hash(:sha256, @content)}]}
      )

    # 00 01 FF 00 DigestInfo, then whatever makes a cube: what a verifier
    # that stops after the DigestInfo would take.
    prefix = :binary.decode_unsigned(<<0, 1, 0xFF, 0>> <> digest_info)
    garbage = (size - 4 - byte_size(digest_info)) * 8
    forged = cube_root(((prefix + 1) <<< garbage) - 1)
    assert (forged ** 3) >>> garbage == prefix

    {:ok, certificate} = Cmsex.Certificate.parse(ctx.certs[:rsa_e3])

    signer_info =
      TestCMS.signer_info(
        sid: {:issuer_and_serial, certificate.issuer, certificate.serial},
        signature: <<forged::size(size * 8)>>
      )

    der =
      TestCMS.signed_data(
        content: @content,
        certificates: [ctx.certs[:rsa_e3]],
        signer_infos: [signer_info]
      )

    assert reason(Cmsex.verify(der)) == :invalid_signature

    # The same key signs and verifies for real.
    assert {:ok, _} = Cmsex.verify(built(ctx, :rsa_e3, attributes: false))
  end

  # The integer cube root, rounded down, by Newton's method.
  defp cube_root(x) do
    guess = 1 <<< div(bit_size(:binary.encode_unsigned(x)) + 2, 3)
    newton(x, guess)
  end

  defp newton(x, guess) do
    next = div(2 * guess + div(x, guess * guess), 3)
    if next >= guess, do: guess, else: newton(x, next)
  end

  test "N38: 10,000 attributes", ctx do
    extra = for i <- 1..10_000, do: attribute({1, 3, 6, 1, 4, 1, 32_473, 2, i}, [:null])

    assert {:error, %Error{reason: :limit_exceeded, detail: :max_attributes}} =
             Cmsex.decode(built(ctx, :p256, extra: extra))
  end

  test "N39: 10,000 certificates", ctx do
    der = built(ctx, :p256, [], certificates: List.duplicate(ctx.certs[:p256], 10_000))
    assert {:error, %Error{reason: :limit_exceeded}} = Cmsex.decode(der)

    small = built(ctx, :p256, [], certificates: List.duplicate(DER.encode({:seq, []}), 10_000))

    assert {:error, %Error{reason: :limit_exceeded, detail: :max_certificates}} =
             Cmsex.decode(small)
  end

  test "N40: PEM with the label CERTIFICATE", ctx do
    pem = :public_key.pem_encode([{:Certificate, ctx.certs[:p256], :not_encrypted}])
    assert reason(Cmsex.decode(pem)) == :invalid_pem
    assert reason(Cmsex.verify(pem)) == :invalid_pem
  end

  # Found by the fuzz tests: the ASN.1 decoder of :public_key exits, rather
  # than raising, on a keyIdentifier with a private tag.
  test "a signer certificate that :public_key cannot read" do
    root = TestPKI.cert({:p256, :aki_root}, ca: true, ski: false, subject: "AKI Root")
    key_identifier = DER.encode({:seq, [{:primitive, 0xC2, <<1, 2, 3>>}]})
    aki = {:seq, [{:oid, {2, 5, 29, 35}}, {:octets, key_identifier}]}
    leaf = TestPKI.cert(:p256, issuer: {root, {:p256, :aki_root}}, extensions: [aki])
    der = Cmsex.sign!(@content, %Signer{certificate: leaf, key: TestPKI.key(:p256)})

    assert {:ok, _} = Cmsex.verify(der)

    assert {:error, %Error{reason: :untrusted, detail: :invalid_certificate}} =
             Cmsex.verify(der, trust: [root])
  end
end
