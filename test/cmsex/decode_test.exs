defmodule Cmsex.DecodeTest do
  use ExUnit.Case, async: true

  doctest Cmsex.PEM
  doctest Cmsex.Attribute

  alias Cmsex.{Attribute, DER, Error, PEM, SignedData, SignerInfo, TestCMS, TestPKI}

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)

  defp rfc4134(name), do: File.read!(Path.join(@rfc4134, name))

  defp reason({:error, %Error{reason: reason}}), do: reason

  describe "RFC 4134 examples" do
    @expected %{
      "4.1" => {1, :data, 1, 0, [{1, :issuer_and_serial, :dsa_with_sha1}]},
      "4.2" => {1, :data, 1, 0, [{1, :issuer_and_serial, :rsa_encryption}]},
      "4.3" => {1, :data, 1, 0, [{1, :issuer_and_serial, :dsa_with_sha1}]},
      "4.4" => {1, :data, 3, 1, [{1, :issuer_and_serial, :dsa_with_sha1}]},
      "4.5" => {1, :data, 2, 0, [{1, :issuer_and_serial, :rsa_encryption}]},
      "4.6" =>
        {1, :data, 2, 0,
         [{1, :issuer_and_serial, :dsa_with_sha1}, {1, :issuer_and_serial, :dsa_with_sha1}]},
      "4.7" => {3, :data, 1, 0, [{3, :subject_key_identifier, :dsa_with_sha1}]},
      "4.10" => {1, :data, 1, 0, [{1, :issuer_and_serial, :dsa_with_sha1}]},
      "4.11" => {1, :data, 2, 1, []}
    }

    for {name, {version, type, certs, crls, signers}} <- @expected do
      test "#{name} decodes" do
        assert {:ok, %SignedData{} = sd} = Cmsex.decode(rfc4134(unquote(name) <> ".bin"))
        assert sd.version == unquote(version)
        assert sd.content_type == unquote(type)
        assert length(sd.certificates) == unquote(certs)
        assert length(sd.crls) == unquote(crls)
        assert sd.deviations == []

        assert for(
                 si <- sd.signer_infos,
                 do: {si.version, elem(si.sid, 0), si.signature_algorithm}
               ) ==
                 unquote(Macro.escape(signers))

        for si <- sd.signer_infos do
          assert si.digest_algorithm == :sha1
          assert si.deviations == []
        end
      end
    end

    test "the content is the example content, and 4.3 is detached" do
      content = rfc4134("ExContent.bin")
      assert Cmsex.decode!(rfc4134("4.2.bin")).content == content
      assert Cmsex.decode!(rfc4134("4.3.bin")).content == nil
    end

    test "the certificates are those of the examples, in the order of the message" do
      assert Cmsex.certificates(rfc4134("4.5.bin")) ==
               {:ok, [rfc4134("CarlRSASelf.cer"), rfc4134("AliceRSASignByCarl.cer")]}

      assert Cmsex.certificates!(rfc4134("4.11.bin")) ==
               [rfc4134("CarlDSSSelf.cer"), rfc4134("AliceDSSSignByCarlNoInherit.cer")]

      assert Cmsex.decode!(rfc4134("4.11.bin")).crls == [rfc4134("CarlDSSCRLForAll.crl")]
    end

    test "4.4 has signed attributes, a content hint and a countersignature" do
      [si] = Cmsex.decode!(rfc4134("4.4.bin")).signer_infos

      assert Enum.map(si.signed_attributes, & &1.type) ==
               [:content_type, :signing_time, :message_digest]

      assert SignerInfo.content_type(si) == {:ok, :data}
      assert SignerInfo.signing_time(si) == {:ok, ~U[2003-05-14 15:39:00Z]}
      assert {:ok, digest} = SignerInfo.message_digest(si)
      assert digest == :crypto.hash(:sha, rfc4134("ExContent.bin"))

      assert %Attribute{values: [hint]} = SignerInfo.unsigned_attribute(si, :content_hint)
      assert {:ok, _} = DER.decode(hint)
      assert SignerInfo.attribute(si, :content_hint) == nil

      assert {:ok, [counter]} = SignerInfo.countersignatures(si)
      assert %SignerInfo{version: 1, digest_algorithm: :sha1} = counter
      assert SignerInfo.content_type(counter) == :error
      assert {:ok, _} = SignerInfo.message_digest(counter)
    end

    test "4.10 keeps unknown attributes as OIDs" do
      [si] = Cmsex.decode!(rfc4134("4.10.bin")).signer_infos
      assert %Attribute{type: {1, 2, 5555}} = SignerInfo.attribute(si, {1, 2, 5555})
      assert SignerInfo.attribute(si, :smime_capabilities)
      assert SignerInfo.signing_time(si) == :error
    end

    for {name, type} <- [
          {"3.1", {1, 2, 840, 113_549, 1, 7, 1}},
          {"5.1", {1, 2, 840, 113_549, 1, 7, 3}},
          {"6.0", {1, 2, 840, 113_549, 1, 7, 5}},
          {"7.1", {1, 2, 840, 113_549, 1, 7, 6}}
        ] do
      test "#{name} is not a SignedData" do
        assert {:error,
                %Error{reason: :unsupported_content_type, detail: unquote(Macro.escape(type))}} =
                 Cmsex.decode(rfc4134(unquote(name) <> ".bin"))
      end
    end
  end

  describe "PEM" do
    setup do
      %{der: rfc4134("4.2.bin")}
    end

    test "both labels, with text around and CRLF", %{der: der} do
      for label <- [:cms, :pkcs7] do
        pem = PEM.encode(der, label)
        assert {:ok, ^der} = PEM.decode(pem)
        crlf = "Subject: x\r\n\r\n" <> String.replace(pem, "\n", "\r\n") <> "trailer"
        assert Cmsex.decode!(crlf).content == rfc4134("ExContent.bin")
      end
    end

    test "lines of 64 characters", %{der: der} do
      [_begin | lines] = der |> PEM.encode() |> String.split("\n", trim: true)
      {body, ["-----END CMS-----"]} = Enum.split(lines, -1)
      assert Enum.all?(Enum.drop(body, -1), &(byte_size(&1) == 64))
      assert byte_size(List.last(body)) in 1..64
    end

    test "skips blocks with other labels", %{der: der} do
      cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
      assert {:ok, ^der} = PEM.decode(cert <> PEM.encode(der, :pkcs7))
    end

    test "only CMS and PKCS7, with the same label at the end", %{der: der} do
      base64 = Base.encode64(der)

      assert reason(
               Cmsex.decode("-----BEGIN CERTIFICATE-----\n#{base64}\n-----END CERTIFICATE-----\n")
             ) ==
               :invalid_pem

      assert reason(PEM.decode("-----BEGIN CMS-----\n#{base64}\n-----END PKCS7-----\n")) ==
               :invalid_pem

      assert reason(PEM.decode("-----BEGIN CMS-----\n#{base64}")) == :invalid_pem
      assert reason(PEM.decode("-----BEGIN CMS-----\n%%%%\n-----END CMS-----\n")) == :invalid_pem
      assert reason(PEM.decode("no block")) == :invalid_pem
    end

    test "rejects arguments of the wrong type" do
      assert_raise ArgumentError, fn -> PEM.encode("x", :pem) end
      assert_raise ArgumentError, fn -> PEM.encode(:x) end
      assert_raise ArgumentError, fn -> PEM.decode(:x) end
    end
  end

  describe "BER" do
    test "indefinite lengths and segmented content and signatures" do
      der = rfc4134("4.4.bin")
      ber = TestCMS.to_ber(der)
      assert ber != der
      assert :binary.part(ber, 0, 2) == <<0x30, 0x80>>

      from_der = Cmsex.decode!(der)
      from_ber = Cmsex.decode!(ber)
      assert from_ber.content == from_der.content
      assert from_ber.certificates == from_der.certificates
      assert from_ber.crls == from_der.crls

      for {a, b} <- Enum.zip(from_ber.signer_infos, from_der.signer_infos) do
        assert a.signature == b.signature
        assert a.signed_attributes == b.signed_attributes
        assert SignerInfo.signed_attributes_tbs(a) == SignerInfo.signed_attributes_tbs(b)
      end
    end

    test "the example of RFC 4134 3.1 is BER" do
      # ContentInfo of id-data with an indefinite length and segments.
      assert {:ok, {0x30, _, _}} = DER.decode(rfc4134("3.1.bin"))
    end
  end

  describe "fields" do
    test "a certificate bundle" do
      cert = TestPKI.cert(:p256)

      sd =
        Cmsex.decode!(
          TestCMS.signed_data(content: nil, digest_algorithms: [], certificates: [cert])
        )

      assert sd.certificates == [cert]
      assert sd.signer_infos == []
      assert sd.content == nil
      assert sd.deviations == []
    end

    test "PKCS #7 content of another type than an OCTET STRING" do
      value = DER.encode({:seq, [{:oid, {1, 2, 3}}, {:utf8, "inside"}]})
      {:ok, {0x30, inner, _}} = DER.decode(value)

      sd =
        Cmsex.decode!(
          TestCMS.signed_data(
            version: 3,
            content_type: {1, 3, 6, 1, 4, 1, 311, 2, 1, 4},
            content: {:raw, value}
          )
        )

      assert sd.content == inner
      assert sd.pkcs7_content == value
      assert sd.deviations == []

      assert {:error, %Error{reason: :malformed, detail: :signed_data}} =
               Cmsex.decode(TestCMS.signed_data(content: {:raw, value}))
    end

    test "an eContent in segments is joined" do
      content = :crypto.strong_rand_bytes(100)
      ber = TestCMS.to_ber(TestCMS.signed_data(content: content))
      assert Cmsex.decode!(ber).content == content
    end

    test "other certificate choices and revocation information" do
      cert = TestPKI.cert(:p256)
      v1_attr = DER.encode({:constructed, 0xA1, [{:int, 1}]})
      v2_attr = DER.encode({:constructed, 0xA2, [{:int, 2}]})
      other = DER.encode({:constructed, 0xA3, [{:oid, {1, 2, 3}}, :null]})
      other_crl = DER.encode({:constructed, 0xA1, [{:oid, {1, 2, 4}}, :null]})

      cases = [
        {[cert, v1_attr], nil, 3},
        {[cert, v2_attr], nil, 4},
        {[cert, other], nil, 5},
        {[cert], [other_crl], 5}
      ]

      for {certs, crls, version} <- cases do
        sd = Cmsex.decode!(TestCMS.signed_data(version: version, certificates: certs, crls: crls))
        assert sd.deviations == []
        assert sd.certificates == [cert]
        assert sd.other_certificates == certs -- [cert]
        assert sd.other_crls == List.wrap(crls)

        assert Cmsex.decode!(TestCMS.signed_data(version: 1, certificates: certs, crls: crls)).deviations ==
                 [:signed_data_version]
      end
    end

    test "the version of the SignedData" do
      si3 = TestCMS.signer_info(version: 3, sid: {:subject_key_identifier, "key"})
      assert Cmsex.decode!(TestCMS.signed_data(version: 3, signer_infos: [si3])).deviations == []

      assert Cmsex.decode!(TestCMS.signed_data(version: 1, signer_infos: [si3])).deviations ==
               [:signed_data_version]

      assert Cmsex.decode!(TestCMS.signed_data(version: 3, content_type: :tst_info)).deviations ==
               []

      assert Cmsex.decode!(TestCMS.signed_data(version: 1, content_type: :tst_info)).deviations ==
               [:signed_data_version]

      assert Cmsex.decode!(TestCMS.signed_data(version: 2)).deviations == [:signed_data_version]
    end

    test "the signer identifier and its version" do
      issuer = DER.encode({:seq, [{:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {:utf8, "CA"}]}]}]})

      [si] =
        Cmsex.decode!(
          TestCMS.signed_data(
            signer_infos: [TestCMS.signer_info(sid: {:issuer_and_serial, issuer, -5})]
          )
        ).signer_infos

      assert si.sid == {:issuer_and_serial, issuer, -5}
      assert si.deviations == []

      for {version, sid, deviations} <- [
            {3, {:issuer_and_serial, issuer, 7}, [:signer_info_version]},
            {1, {:subject_key_identifier, "ski"}, [:signer_info_version]},
            {3, {:subject_key_identifier, "ski"}, []}
          ] do
        si_der = TestCMS.signer_info(version: version, sid: sid)
        [si] = Cmsex.decode!(TestCMS.signed_data(version: 3, signer_infos: [si_der])).signer_infos
        assert si.sid == sid
        assert si.deviations == deviations
      end
    end

    test "the algorithms and the PSS parameters" do
      pss = {:seq, [{:oid, :rsassa_pss}, {:seq, [{:explicit, 2, {:int, 32}}]}]}
      si = TestCMS.signer_info(digest: :sha384, signature_algorithm: pss)
      [si] = Cmsex.decode!(TestCMS.signed_data(signer_infos: [si])).signer_infos
      assert si.digest_algorithm == :sha384
      assert si.signature_algorithm == :rsassa_pss

      assert si.signature_parameters == %{
               hash: :sha1,
               mgf_hash: :sha1,
               salt_length: 32,
               trailer_field: 1
             }

      unknown = {:seq, [{:oid, {1, 2, 3, 4}}]}
      si = TestCMS.signer_info(digest: {1, 2, 9}, signature_algorithm: unknown)
      [si] = Cmsex.decode!(TestCMS.signed_data(signer_infos: [si])).signer_infos
      assert {si.digest_algorithm, si.signature_algorithm} == {{1, 2, 9}, {1, 2, 3, 4}}
      assert si.signature_parameters == nil
    end
  end

  describe "attributes" do
    defp one_signer(opts) do
      [si] =
        Cmsex.decode!(TestCMS.signed_data(signer_infos: [TestCMS.signer_info(opts)])).signer_infos

      si
    end

    test "the accessors read single values" do
      time = ~U[2030-01-02 03:04:05Z]

      si =
        one_signer(
          signed: [
            TestCMS.attribute(:content_type, [{:oid, :data}]),
            TestCMS.attribute(:message_digest, [{:octets, "digest"}]),
            TestCMS.attribute(:signing_time, [{:utc_time, time}])
          ]
        )

      assert SignerInfo.content_type(si) == {:ok, :data}
      assert SignerInfo.message_digest(si) == {:ok, "digest"}
      assert SignerInfo.signing_time(si) == {:ok, time}
      assert si.deviations == []
    end

    test "missing, repeated and malformed values" do
      digest = TestCMS.attribute(:message_digest, [{:octets, "a"}])
      two_values = TestCMS.attribute(:message_digest, [{:octets, "a"}, {:octets, "b"}])
      not_octets = TestCMS.attribute(:message_digest, [{:int, 1}])

      assert SignerInfo.message_digest(one_signer(signed: [digest])) == {:ok, "a"}
      assert SignerInfo.read_attribute(one_signer([]), :message_digest) == {:error, :missing}

      for signed <- [[digest, digest], [two_values], [not_octets]] do
        si = one_signer(signed: signed)
        assert SignerInfo.read_attribute(si, :message_digest) == {:error, :invalid}
        assert SignerInfo.message_digest(si) == :error
      end
    end

    test "a signing time in GeneralizedTime" do
      in_range = TestCMS.attribute(:signing_time, [{:generalized_time, ~U[2030-01-01 00:00:00Z]}])

      out_of_range =
        TestCMS.attribute(:signing_time, [{:generalized_time, ~U[2050-01-01 00:00:00Z]}])

      si = one_signer(signed: [in_range])
      assert si.deviations == [:signing_time_encoding]
      assert SignerInfo.signing_time(si) == {:ok, ~U[2030-01-01 00:00:00Z]}

      assert one_signer(signed: [out_of_range]).deviations == []
    end

    test "signed attributes that are not DER are kept as received" do
      a = TestCMS.attribute(:content_type, [{:oid, :data}])
      b = TestCMS.attribute(:message_digest, [{:octets, "x"}])
      [first, second] = Enum.sort([a, b])

      unsorted =
        IO.iodata_to_binary([0xA0, DER.encode_length(byte_size(a) + byte_size(b)), second, first])

      si = one_signer(signed: {:raw, unsorted})
      assert si.deviations == [:signed_attributes_not_der]
      assert SignerInfo.signed_attributes_tbs(si) == DER.retag(unsorted, 0x31)
      assert Enum.map(si.signed_attributes, & &1.type) == Enum.map([second, first], &type/1)

      sorted = DER.retag(DER.encode({:set, [{:raw, a}, {:raw, b}]}), 0xA0)
      assert one_signer(signed: {:raw, sorted}).deviations == []
    end

    defp type(der) do
      {:ok, attribute} = DER.decode(der)
      {:ok, %Attribute{type: type}} = Attribute.read(attribute)
      type
    end

    test "constructors" do
      assert Attribute.signing_time(~U[2026-10-23 12:00:00.123Z]).values == [
               DER.encode({:utc_time, ~U[2026-10-23 12:00:00Z]})
             ]

      assert Attribute.signing_time(~U[2050-01-01 00:00:00Z]).values == [
               DER.encode({:generalized_time, ~U[2050-01-01 00:00:00Z]})
             ]

      assert %Attribute{type: :content_hint, values: [hint]} =
               Attribute.content_hint(:signed_data, "inner")

      assert hint == DER.encode({:seq, [{:utf8, "inner"}, {:oid, :signed_data}]})

      assert Attribute.new(:content_type, [DER.encode({:oid, :data})]).type == :content_type
      assert Attribute.new({1, 2, 840, 113_549, 1, 9, 3}, [<<5, 0>>]).type == :content_type
      assert_raise ArgumentError, fn -> Attribute.new(:no_such_name, [<<5, 0>>]) end
      assert_raise ArgumentError, fn -> Attribute.new(:content_type, []) end
      assert_raise ArgumentError, fn -> Attribute.new(:content_type, ["not DER"]) end
      assert_raise ArgumentError, fn -> Attribute.new({7, 1}, [<<5, 0>>]) end
    end
  end

  describe "limits" do
    test "signers, certificates, CRLs and attributes" do
      cert = TestPKI.cert(:p256)
      si = TestCMS.signer_info()
      attr = TestCMS.attribute({1, 2, 3}, [:null])

      cases = [
        {[signer_infos: [si, si, si]], [max_signers: 2], :max_signers},
        {[certificates: [cert, cert, cert]], [max_certificates: 2], :max_certificates},
        {[crls: [cert, cert, cert]], [max_certificates: 2], :max_certificates},
        {[signer_infos: [TestCMS.signer_info(signed: [attr, attr, attr])]], [max_attributes: 2],
         :max_attributes},
        {[signer_infos: [TestCMS.signer_info(unsigned: [attr, attr, attr])]], [max_attributes: 2],
         :max_attributes}
      ]

      for {fields, opts, limit} <- cases do
        der = TestCMS.signed_data(fields)
        assert {:ok, _} = Cmsex.decode(der)
        assert {:error, %Error{reason: :limit_exceeded, detail: ^limit}} = Cmsex.decode(der, opts)
      end
    end

    test "the limit on attributes applies to countersignatures, and their errors carry the path" do
      counter = TestCMS.signer_info(signed: [TestCMS.attribute({1, 2, 3}, [:null])])
      attr = TestCMS.attribute(:countersignature, [{:raw, counter}, {:raw, counter}])

      [si] =
        Cmsex.decode!(TestCMS.signed_data(signer_infos: [TestCMS.signer_info(unsigned: [attr])])).signer_infos

      assert {:ok, [_, _]} = SignerInfo.countersignatures(si)

      assert {:error, %Error{reason: :limit_exceeded}} =
               SignerInfo.countersignatures(si, max_signers: 1)

      broken = TestCMS.attribute(:countersignature, [{:raw, counter}, {:seq, [{:int, 1}]}])

      [si] =
        Cmsex.decode!(
          TestCMS.signed_data(signer_infos: [TestCMS.signer_info(unsigned: [broken])])
        ).signer_infos

      # The values of a SET are in the order of their encodings: the broken
      # one is shorter and comes first.
      assert {:error, %Error{reason: :malformed, signer: [0]} = error} =
               SignerInfo.countersignatures(si)

      assert Exception.message(error) =~ "countersignature"
    end

    test "nesting and the number of elements" do
      der = rfc4134("4.4.bin")

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_depth}} =
               Cmsex.decode(der, max_depth: 5)

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_elements}} =
               Cmsex.decode(der, max_elements: 50)

      deep =
        Enum.reduce(1..40, DER.encode(:null), fn _, acc -> DER.encode({:seq, [{:raw, acc}]}) end)

      assert reason(Cmsex.decode(deep)) == :limit_exceeded
    end

    test "many attributes and many certificates" do
      attr = TestCMS.attribute({1, 2, 3}, [:null])

      many =
        TestCMS.signed_data(
          signer_infos: [TestCMS.signer_info(signed: List.duplicate(attr, 10_000))]
        )

      assert reason(Cmsex.decode(many)) == :limit_exceeded

      cert = TestPKI.cert(:ed25519)
      certs = TestCMS.signed_data(certificates: List.duplicate(cert, 10_000))
      assert reason(Cmsex.decode(certs)) == :limit_exceeded
    end
  end

  describe "malformed input" do
    test "empty, one byte, garbage and trailing data" do
      der = rfc4134("4.2.bin")

      for bad <- [
            "",
            <<0x30>>,
            <<0xFF, 0xFF>>,
            "garbage",
            der <> <<0>>,
            <<0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF>>
          ] do
        assert reason(Cmsex.decode(bad)) == :malformed, inspect(bad)
      end
    end

    test "truncated at every position" do
      der = rfc4134("4.2.bin")

      for size <- 0..(byte_size(der) - 1) do
        assert {:error, %Error{}} = Cmsex.decode(binary_part(der, 0, size))
      end
    end

    test "an indefinite length without its end" do
      ber = TestCMS.to_ber(rfc4134("4.2.bin"))
      assert reason(Cmsex.decode(binary_part(ber, 0, byte_size(ber) - 2))) == :malformed
    end

    test "structures that are not a SignedData" do
      ok = TestCMS.signed_data()

      cases = [
        DER.encode({:seq, [{:oid, :signed_data}]}),
        DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, {:int, 1}}]}),
        DER.encode({:seq, [{:int, 1}, {:explicit, 0, {:int, 1}}]}),
        DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, {:seq, [{:int, 1}]}}]}),
        TestCMS.signed_data(signer_infos: [DER.encode({:seq, [{:int, 1}]})]),
        TestCMS.signed_data(signer_infos: [DER.encode(:null)]),
        TestCMS.signed_data(certificates: [DER.encode(:null)]),
        TestCMS.signed_data(crls: [DER.encode({:constructed, 0xA0, []})]),
        TestCMS.signed_data(signer_infos: [TestCMS.signer_info(signed: [DER.encode(:null)])]),
        TestCMS.signed_data(
          signer_infos: [TestCMS.signer_info(unsigned: [DER.encode({:seq, [{:oid, {1, 2}}]})])]
        )
      ]

      assert {:ok, _} = Cmsex.decode(ok)

      for bad <- cases do
        assert reason(Cmsex.decode(bad)) == :malformed, inspect(DER.decode(bad))
      end
    end

    test "errors in a signer carry its position" do
      bad = DER.encode({:seq, [{:int, 1}]})
      der = TestCMS.signed_data(signer_infos: [TestCMS.signer_info(), bad])
      assert {:error, %Error{reason: :malformed, signer: 1} = error} = Cmsex.decode(der)
      assert Exception.message(error) =~ "signer 1"
      assert_raise Error, fn -> Cmsex.decode!(der) end
      assert_raise Error, fn -> Cmsex.certificates!(der) end
    end
  end

  describe "options" do
    test "unknown options and values of the wrong kind raise" do
      der = TestCMS.signed_data()
      assert_raise ArgumentError, ~r/unknown option/, fn -> Cmsex.decode(der, max_nodes: 1) end
      assert_raise ArgumentError, fn -> Cmsex.decode(der, max_depth: 0) end
      assert_raise ArgumentError, fn -> Cmsex.decode(der, max_signers: :all) end
      assert_raise ArgumentError, fn -> Cmsex.decode(der, [:max_depth]) end
      assert_raise ArgumentError, fn -> Cmsex.decode(der, %{}) end
      assert_raise ArgumentError, fn -> Cmsex.decode(:not_binary) end
    end
  end

  test "inspect leaves out the raw fields" do
    sd = Cmsex.decode!(rfc4134("4.4.bin"))
    refute inspect(sd) =~ "raw:"
    refute inspect(hd(sd.signer_infos)) =~ "raw:"
  end
end
