defmodule Cmsex.DecodeTypesTest do
  use ExUnit.Case, async: true

  alias Cmsex.{
    Attribute,
    AuthenticatedData,
    DER,
    DigestedData,
    EncryptedData,
    EnvelopedData,
    Error,
    RecipientInfo,
    TestPKI
  }

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)

  defp rfc4134(name), do: File.read!(Path.join(@rfc4134, name))

  defp reason({:error, %Error{reason: reason}}), do: reason
  defp detail({:error, %Error{detail: detail}}), do: detail

  @issuer DER.encode({:seq, [{:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {:utf8, "Recipient"}]}]}]})

  # Terms of the parts, for the messages built here.
  defp ias(serial \\ 7), do: {:seq, [{:raw, @issuer}, {:int, serial}]}

  defp ktri(opts \\ []) do
    rid =
      case Keyword.get(opts, :rid, :ias) do
        :ias -> ias()
        {:ski, ski} -> {:primitive, 0x80, ski}
      end

    {:seq,
     [
       {:int, Keyword.get(opts, :version, 0)},
       rid,
       {:seq, [{:oid, :rsa_encryption}, :null]},
       {:octets, "encrypted key"}
     ]}
  end

  defp kari(opts \\ []) do
    originator =
      Keyword.get(
        opts,
        :originator,
        {:constructed, 0xA1, [{:seq, [{:oid, :ec_public_key}]}, {:bits, <<4, 1, 2>>}]}
      )

    ukm = Keyword.get(opts, :ukm)

    {:constructed, 0xA1,
     [
       {:int, Keyword.get(opts, :version, 3)},
       {:explicit, 0, originator},
       ukm && {:explicit, 1, {:octets, ukm}},
       {:seq, [{:oid, :std_dh_sha256kdf}, {:seq, [{:oid, :aes128_wrap}]}]},
       {:seq,
        Keyword.get(opts, :keys, [
          {:seq, [ias(), {:octets, "key 1"}]},
          {:seq, [{:constructed, 0xA0, [{:octets, "ski"}]}, {:octets, "key 2"}]}
        ])}
     ]
     |> Enum.reject(&is_nil/1)}
  end

  defp kekri(opts \\ []) do
    kekid =
      [{:octets, "key id"}, opts[:date] && {:generalized_time, opts[:date]}, opts[:other]]
      |> Enum.reject(&is_nil/1)

    {:constructed, 0xA2,
     [
       {:int, Keyword.get(opts, :version, 4)},
       {:seq, kekid},
       {:seq, [{:oid, :aes256_wrap}]},
       {:octets, :binary.copy(<<1>>, 40)}
     ]}
  end

  defp pwri(opts \\ []) do
    derivation =
      if Keyword.get(opts, :derivation, true) do
        {:constructed, 0xA0,
         [{:oid, :pbkdf2}, {:seq, [{:octets, "salt salt salt s"}, {:int, 1000}]}]}
      end

    {:constructed, 0xA3,
     [
       {:int, Keyword.get(opts, :version, 0)},
       derivation,
       {:seq, [{:oid, :pwri_kek}, {:seq, [{:oid, :aes256_cbc}, {:octets, <<0::128>>}]}]},
       {:octets, :binary.copy(<<2>>, 48)}
     ]
     |> Enum.reject(&is_nil/1)}
  end

  defp ori, do: {:constructed, 0xA4, [{:oid, {1, 2, 3, 4}}, {:utf8, "whatever"}]}

  defp content_info(type, fields),
    do: DER.encode({:seq, [{:oid, type}, {:explicit, 0, {:seq, fields}}]})

  defp encrypted_content_info(opts \\ []) do
    content =
      case Keyword.get(opts, :content, "ciphertext 16 b.") do
        nil -> nil
        {:segments, parts} -> {:constructed, 0xA0, Enum.map(parts, &{:octets, &1})}
        bin -> {:primitive, 0x80, bin}
      end

    {:seq,
     [
       {:oid, Keyword.get(opts, :content_type, :data)},
       Keyword.get(opts, :algorithm, {:seq, [{:oid, :aes256_cbc}, {:octets, <<0::128>>}]}),
       content
     ]
     |> Enum.reject(&is_nil/1)}
  end

  defp attributes(id, values),
    do:
      {:constructed, id, Enum.map(values, fn {type, v} -> {:seq, [{:oid, type}, {:set, v}]} end)}

  defp enveloped(opts) do
    content_info(
      :enveloped_data,
      [
        {:int, Keyword.get(opts, :version, 0)},
        opts[:originator],
        {:constructed, 0x31, Keyword.get(opts, :recipients, [ktri()])},
        encrypted_content_info(Keyword.get(opts, :info, [])),
        opts[:unprotected] && attributes(0xA1, opts[:unprotected])
      ]
      |> Enum.reject(&is_nil/1)
    )
  end

  defp auth_enveloped(opts) do
    content_info(
      :auth_enveloped_data,
      [
        {:int, Keyword.get(opts, :version, 0)},
        {:constructed, 0x31, Keyword.get(opts, :recipients, [kekri()])},
        encrypted_content_info(
          Keyword.get(opts, :info,
            algorithm: {:seq, [{:oid, :aes128_gcm}, {:seq, [{:octets, <<0::96>>}]}]}
          )
        ),
        opts[:authenticated] && attributes(0xA1, opts[:authenticated]),
        {:octets, Keyword.get(opts, :mac, <<9::96>>)},
        opts[:unauthenticated] && attributes(0xA2, opts[:unauthenticated])
      ]
      |> Enum.reject(&is_nil/1)
    )
  end

  @attr {1, 3, 6, 1, 4, 1, 32_473, 9}

  describe "RFC 4134" do
    test "5.1: EnvelopedData to Bob, with Triple-DES" do
      assert {:ok, %EnvelopedData{} = ed} = Cmsex.decode(rfc4134("5.1.bin"))
      assert ed.type == :enveloped_data
      assert ed.version == 0
      assert ed.content_type == :data
      assert ed.content_encryption_algorithm == :des_ede3_cbc
      assert byte_size(ed.encrypted_content) == 32
      assert ed.mac == nil and ed.authenticated_attributes == nil
      assert ed.unprotected_attributes == [] and ed.certificates == []
      assert ed.deviations == []

      assert [%RecipientInfo{} = ri] = ed.recipient_infos
      assert ri.type == :key_transport
      assert ri.version == 0
      assert ri.key_encryption_algorithm == :rsa_encryption
      assert byte_size(ri.encrypted_key) == 128
      assert ri.deviations == []

      {:ok, bob} = Cmsex.Certificate.parse(rfc4134("BobRSASignByCarl.cer"))
      assert ri.rid == {:issuer_and_serial, bob.issuer, bob.serial}
    end

    test "5.2: EnvelopedData with RC2" do
      assert {:ok, %EnvelopedData{content_encryption_algorithm: :rc2_cbc}} =
               Cmsex.decode(rfc4134("5.2.bin"))
    end

    test "6.0: DigestedData with SHA-1" do
      assert {:ok, %DigestedData{} = dd} = Cmsex.decode(rfc4134("6.0.bin"))
      assert dd.version == 0
      assert dd.digest_algorithm == :sha1
      assert dd.content_type == :data
      assert dd.content == rfc4134("ExContent.bin")
      assert dd.digest == :crypto.hash(:sha, dd.content)
      assert dd.deviations == []
    end

    test "7.1 and 7.2: EncryptedData, the second with an unprotected attribute" do
      assert {:ok, %EncryptedData{} = plain} = Cmsex.decode(rfc4134("7.1.bin"))
      assert plain.version == 0
      assert plain.content_encryption_algorithm == :des_ede3_cbc
      assert plain.unprotected_attributes == []
      assert plain.deviations == []

      assert {:ok, %EncryptedData{} = with_attribute} = Cmsex.decode(rfc4134("7.2.bin"))
      assert with_attribute.version == 2

      assert [%Attribute{type: {1, 2, 5555}, values: [value]}] =
               with_attribute.unprotected_attributes

      assert {:ok, {0x04, "This is a test General ASN Attribute, number 1.", _}} =
               DER.decode(value)

      assert with_attribute.deviations == []
    end

    test "3.1: a bare id-data is not a type decode/2 reads" do
      assert {:error,
              %Error{reason: :unsupported_content_type, detail: {1, 2, 840, 113_549, 1, 7, 1}}} =
               Cmsex.decode(rfc4134("3.1.bin"))
    end
  end

  describe "EnvelopedData" do
    test "every kind of recipient" do
      date = ~U[2026-10-24 10:00:00Z]

      der =
        enveloped(
          version: 3,
          recipients: [
            ktri(),
            ktri(rid: {:ski, "key id 1"}, version: 2),
            kari(ukm: "keying material"),
            kekri(date: date, other: {:seq, [{:oid, {1, 2, 3}}]}),
            pwri(),
            ori()
          ]
        )

      assert {:ok, %EnvelopedData{recipient_infos: infos} = ed} = Cmsex.decode(der)
      assert ed.deviations == []
      [ias, ski, kari, kekri, pwri, ori] = infos

      assert ias.rid == {:issuer_and_serial, @issuer, 7}
      assert ski.rid == {:subject_key_identifier, "key id 1"}
      assert Enum.all?(infos, &(&1.deviations == []))

      assert kari.type == :key_agreement
      assert kari.version == 3
      assert kari.key_encryption_algorithm == :std_dh_sha256kdf
      assert kari.key_wrap_algorithm == :aes128_wrap
      assert kari.originator == {:public_key, :ec_public_key, <<4, 1, 2>>}
      assert kari.ukm == "keying material"
      assert kari.encrypted_key == nil

      assert kari.recipient_encrypted_keys == [
               {{:issuer_and_serial, @issuer, 7}, "key 1"},
               {{:subject_key_identifier, "ski"}, "key 2"}
             ]

      assert kekri.type == :kek
      assert kekri.rid == {:kek, "key id"}
      assert kekri.date == date
      assert kekri.key_encryption_algorithm == :aes256_wrap
      assert byte_size(kekri.encrypted_key) == 40

      assert pwri.type == :password
      assert pwri.key_derivation_algorithm == :pbkdf2
      assert pwri.key_encryption_algorithm == :pwri_kek

      assert ori.type == :other
      assert ori.other_type == {1, 2, 3, 4}
      assert ori.version == nil
    end

    test "a key agreement recipient with a certificate as the originator" do
      for {originator, expected} <- [
            {ias(9), {:issuer_and_serial, @issuer, 9}},
            {{:primitive, 0x80, "orig"}, {:subject_key_identifier, "orig"}}
          ] do
        der = enveloped(version: 2, recipients: [kari(originator: originator)])
        assert {:ok, %{recipient_infos: [kari]}} = Cmsex.decode(der)
        assert kari.originator == expected
        assert kari.ukm == nil
      end
    end

    test "the version the fields call for (RFC 5652, 6.1)" do
      cert = TestPKI.cert(:p256)
      originator = {:constructed, 0xA0, [{:constructed, 0xA0, [{:raw, cert}]}]}
      other_cert = {:constructed, 0xA0, [{:constructed, 0xA3, [{:oid, {1, 2}}, :null]}]}
      v2_attribute = {:constructed, 0xA0, [{:constructed, 0xA2, [{:int, 1}]}]}

      cases = [
        {0, []},
        {2, [recipients: [ktri(rid: {:ski, "k"}, version: 2)]]},
        {2, [recipients: [kari()]]},
        {2, [recipients: [kekri()]]},
        {2, [originator: originator]},
        {2, [unprotected: [{@attr, [:null]}]]},
        {3, [recipients: [pwri()]]},
        {3, [recipients: [ktri(), ori()]]},
        {3, [originator: {:constructed, 0xA0, [v2_attribute]}]},
        {4, [originator: {:constructed, 0xA0, [other_cert]}, recipients: [pwri()]]}
      ]

      for {expected, opts} <- cases do
        assert {:ok, %{version: ^expected, deviations: []}} =
                 Cmsex.decode(enveloped([{:version, expected} | opts])),
               "#{expected} #{inspect(opts)}"

        assert {:ok, %{deviations: [:enveloped_data_version]}} =
                 Cmsex.decode(enveloped([{:version, expected + 1} | opts]))
      end
    end

    test "the OriginatorInfo" do
      cert = TestPKI.cert(:p256)

      originator =
        {:constructed, 0xA0,
         [
           {:constructed, 0xA0, [{:raw, cert}]},
           {:constructed, 0xA1, [{:constructed, 0xA1, [:null]}]}
         ]}

      assert {:ok, ed} = Cmsex.decode(enveloped(version: 4, originator: originator))
      assert ed.certificates == [cert]
      assert ed.crls == []
      assert ed.other_crls == [<<0xA1, 2, 5, 0>>]
      assert ed.version == 4 and ed.deviations == []
    end

    test "unprotected attributes, detached and segmented content" do
      der =
        enveloped(
          version: 2,
          unprotected: [{@attr, [{:utf8, "a"}, {:utf8, "b"}]}],
          info: [content: {:segments, ["cipher", "text 16 b."]}]
        )

      assert {:ok, ed} = Cmsex.decode(der)
      assert ed.encrypted_content == "ciphertext 16 b."
      assert [%Attribute{type: @attr, values: [_, _]}] = ed.unprotected_attributes

      assert {:ok, %{encrypted_content: nil}} = Cmsex.decode(enveloped(info: [content: nil]))
    end

    test "recipient info versions out of place are deviations" do
      der = enveloped(version: 2, recipients: [ktri(version: 2), kari(version: 2)])
      assert {:ok, %{recipient_infos: [ktri, kari]}} = Cmsex.decode(der)
      assert ktri.deviations == [:recipient_info_version]
      assert kari.deviations == [:recipient_info_version]
    end

    test "limits" do
      der = enveloped(version: 2, recipients: List.duplicate(kekri(), 3))
      assert {:ok, _} = Cmsex.decode(der, max_recipients: 3)
      assert detail(Cmsex.decode(der, max_recipients: 2)) == :max_recipients

      keys = List.duplicate({:seq, [ias(), {:octets, "k"}]}, 3)
      der = enveloped(version: 2, recipients: [kari(keys: keys)])
      assert {:ok, _} = Cmsex.decode(der, max_recipients: 3)
      assert detail(Cmsex.decode(der, max_recipients: 2)) == :max_recipients

      der = enveloped(version: 2, unprotected: List.duplicate({@attr, [:null]}, 3))
      assert detail(Cmsex.decode(der, max_attributes: 2)) == :max_attributes

      assert_raise ArgumentError, fn -> Cmsex.decode(der, max_recipients: 0) end
    end

    test "malformed" do
      bad = [
        enveloped(recipients: []),
        enveloped(recipients: [{:int, 1}]),
        enveloped(recipients: [{:constructed, 0xA5, [{:int, 1}]}]),
        enveloped(recipients: [kari(keys: [])]),
        enveloped(recipients: [kari(originator: {:int, 1})]),
        enveloped(recipients: [kekri(other: {:int, 1})]),
        enveloped(recipients: [{:seq, [{:int, 0}, ias(), {:octets, "k"}]}]),
        content_info(:enveloped_data, [
          {:int, 0},
          {:constructed, 0x31, [ktri()]},
          {:seq,
           [{:oid, :data}, {:seq, [{:oid, :aes128_cbc}, {:octets, <<0::128>>}]}, {:octets, "x"}]}
        ]),
        content_info(:enveloped_data, [{:int, 0}, {:constructed, 0x31, [ktri()]}]),
        content_info(:enveloped_data, [
          {:int, 0},
          {:constructed, 0x31, [ktri()]},
          encrypted_content_info(),
          {:octets, "extra"}
        ])
      ]

      for der <- bad do
        assert reason(Cmsex.decode(der)) == :malformed, inspect(DER.decode(der))
      end
    end
  end

  describe "AuthEnvelopedData" do
    test "authenticated and unauthenticated attributes, and the tag" do
      der =
        auth_enveloped(
          authenticated: [{:content_type, [{:oid, :data}]}],
          unauthenticated: [{@attr, [:null]}]
        )

      assert {:ok, %EnvelopedData{} = ed} = Cmsex.decode(der)
      assert ed.type == :auth_enveloped_data
      assert ed.version == 0 and ed.deviations == []
      assert ed.content_encryption_algorithm == :aes128_gcm
      assert ed.mac == <<9::96>>
      assert [%Attribute{type: :content_type}] = ed.authenticated_attributes
      assert [%Attribute{type: @attr}] = ed.unprotected_attributes
      assert <<0xA1, _::binary>> = ed.raw.authenticated_attributes

      assert {:ok, %{authenticated_attributes: nil, unprotected_attributes: []}} =
               Cmsex.decode(auth_enveloped([]))

      assert {:ok, %{deviations: [:enveloped_data_version]}} =
               Cmsex.decode(auth_enveloped(version: 2))
    end

    test "malformed: no tag, or fields out of order" do
      no_mac =
        content_info(:auth_enveloped_data, [
          {:int, 0},
          {:constructed, 0x31, [kekri()]},
          encrypted_content_info()
        ])

      assert reason(Cmsex.decode(no_mac)) == :malformed

      out_of_order =
        content_info(:auth_enveloped_data, [
          {:int, 0},
          {:constructed, 0x31, [kekri()]},
          encrypted_content_info(),
          {:octets, "mac"},
          attributes(0xA1, [{@attr, [:null]}])
        ])

      assert reason(Cmsex.decode(out_of_order)) == :malformed
    end
  end

  describe "EncryptedData" do
    test "versions" do
      plain = content_info(:encrypted_data, [{:int, 0}, encrypted_content_info()])
      assert {:ok, %EncryptedData{deviations: []}} = Cmsex.decode(plain)

      odd = content_info(:encrypted_data, [{:int, 2}, encrypted_content_info()])
      assert {:ok, %EncryptedData{deviations: [:encrypted_data_version]}} = Cmsex.decode(odd)

      assert reason(Cmsex.decode(content_info(:encrypted_data, [{:int, 0}]))) == :malformed
    end
  end

  describe "DigestedData" do
    test "another content type is version 2" do
      digested = fn version ->
        content_info(:digested_data, [
          {:int, version},
          {:seq, [{:oid, :sha256}]},
          {:seq, [{:oid, {1, 2, 3}}, {:explicit, 0, {:octets, "x"}}]},
          {:octets, :crypto.hash(:sha256, "x")}
        ])
      end

      assert {:ok, %DigestedData{content_type: {1, 2, 3}, content: "x", deviations: []}} =
               Cmsex.decode(digested.(2))

      assert {:ok, %DigestedData{deviations: [:digested_data_version]}} =
               Cmsex.decode(digested.(0))
    end
  end

  describe "AuthenticatedData" do
    defp auth_data(opts) do
      content_info(
        :auth_data,
        [
          {:int, Keyword.get(opts, :version, 0)},
          opts[:originator],
          {:constructed, 0x31, [pwri()]},
          {:seq, [{:oid, :hmac_sha256}]},
          opts[:digest] && {:constructed, 0xA1, [{:oid, opts[:digest]}]},
          {:seq, [{:oid, :data}, {:explicit, 0, {:octets, "content"}}]},
          opts[:authenticated] && attributes(0xA2, opts[:authenticated]),
          {:octets, "mac value"},
          opts[:unauthenticated] && attributes(0xA3, opts[:unauthenticated])
        ]
        |> Enum.reject(&is_nil/1)
      )
    end

    test "with and without authenticated attributes" do
      assert {:ok, %AuthenticatedData{} = ad} = Cmsex.decode(auth_data([]))
      assert ad.version == 0 and ad.deviations == []
      assert ad.mac_algorithm == :hmac_sha256
      assert ad.digest_algorithm == nil
      assert ad.content == "content"
      assert ad.mac == "mac value"
      assert ad.authenticated_attributes == nil
      assert ad.unauthenticated_attributes == []
      assert [%RecipientInfo{type: :password}] = ad.recipient_infos

      der =
        auth_data(
          digest: :sha256,
          authenticated: [{:content_type, [{:oid, :data}]}],
          unauthenticated: [{@attr, [:null]}]
        )

      assert {:ok, ad} = Cmsex.decode(der)
      assert ad.digest_algorithm == :sha256
      assert [%Attribute{type: :content_type}] = ad.authenticated_attributes
      assert [%Attribute{type: @attr}] = ad.unauthenticated_attributes
      assert <<0xA2, _::binary>> = ad.raw.authenticated_attributes
    end

    test "versions" do
      other =
        {:constructed, 0xA0,
         [{:constructed, 0xA0, [{:constructed, 0xA3, [{:oid, {1, 2}}, :null]}]}]}

      v2 = {:constructed, 0xA0, [{:constructed, 0xA0, [{:constructed, 0xA2, [{:int, 1}]}]}]}

      for {version, originator} <- [{0, nil}, {3, other}, {1, v2}] do
        assert {:ok, %{deviations: []}} =
                 Cmsex.decode(auth_data(version: version, originator: originator))
      end

      assert {:ok, %{deviations: [:auth_data_version]}} = Cmsex.decode(auth_data(version: 2))
    end
  end

  test "certificates/2 still reads only SignedData" do
    assert reason(Cmsex.certificates(rfc4134("5.1.bin"))) == :unsupported_content_type
    assert reason(Cmsex.verify(rfc4134("5.1.bin"))) == :unsupported_content_type
  end
end
