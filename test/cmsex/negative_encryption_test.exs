defmodule Cmsex.NegativeEncryptionTest do
  use ExUnit.Case, async: true

  # The negative corpus of EnvelopedData, AuthEnvelopedData, EncryptedData,
  # AuthenticatedData and DigestedData, as negative_test.exs is that of
  # SignedData: each case starts from a valid message written by the
  # library and changes one thing. Several are also checked, in more
  # detail, in encrypt_test.exs and digest_mac_test.exs, and RSA PKCS #1
  # v1.5 in uniform_error_test.exs.

  import Bitwise

  alias Cmsex.{
    Cipher,
    DER,
    EncryptedFixtures,
    Error,
    KeyWrap,
    Recipient,
    TestPKI
  }

  @content "the content of the negative corpus of encryption"
  @kek :binary.copy(<<0x4B>>, 32)
  @kek_id "negative kek"
  @password "negative password"
  @unknown {1, 3, 6, 1, 4, 1, 32_473, 9}

  setup_all do
    ca = TestPKI.cert({:p256, :negative_ca}, ca: true)
    x25519 = TestPKI.cert(:x25519, key_usage: [4], issuer: {ca, {:p256, :negative_ca}})

    %{
      rsa: EncryptedFixtures.credentials("rsa2048"),
      p256: EncryptedFixtures.credentials("p256"),
      x25519: [
        key: TestPKI.montgomery_pkcs8(:x25519, TestPKI.key(:x25519)),
        certificate: x25519
      ]
    }
  end

  defp signer,
    do: %Cmsex.Signer{certificate: TestPKI.cert(:p256), key: TestPKI.key(:p256)}

  defp kek(opts \\ []), do: Recipient.kek(@kek, @kek_id, opts)
  defp kek_opts(key \\ @kek), do: [kek: {@kek_id, key}]
  defp password, do: Recipient.password(@password, iterations: 1000)

  # Paths from the ContentInfo: the fields of the content, and of its
  # first RecipientInfo.
  @content_path [1, 0]
  defp field(n), do: @content_path ++ [n]
  defp recipient(path), do: @content_path ++ [1, 0 | path]

  defp reason({:error, %Error{reason: reason}}), do: reason
  defp reason({:ok, _}), do: :ok

  defp error({:error, %Error{reason: reason, detail: detail}}), do: {reason, detail}

  ## Changing one thing

  # Replaces the element at `path`, a list of positions from the
  # ContentInfo down (-1 for the last), by what `fun` returns for it: its
  # new bytes, or nil to take it out. The elements above are written again
  # around it, with their own tags.
  defp patch(der, path, fun) do
    {:ok, element} = DER.decode(der)
    patch_element(element, path, fun)
  end

  defp patch_element(element, [], fun), do: fun.(element)

  defp patch_element({id, _content, _raw} = element, [position | rest], fun) do
    children = DER.children(element)
    new = patch_element(Enum.at(children, position), rest, fun)

    raws =
      children
      |> Enum.map(&elem(&1, 2))
      |> List.replace_at(position, new)
      |> Enum.reject(&is_nil/1)

    DER.encode({:constructed, id, Enum.map(raws, &{:raw, &1})})
  end

  defp put(der, path, term), do: patch(der, path, fn _ -> DER.encode(term) end)
  defp drop(der, path), do: patch(der, path, fn _ -> nil end)

  defp flip(der, path, at \\ -1) do
    patch(der, path, fn {_id, content, raw} ->
      # The position in the content, from its end when negative.
      at = if at < 0, do: byte_size(content) + at, else: at
      offset = byte_size(raw) - byte_size(content) + at
      <<head::binary-size(^offset), byte, tail::binary>> = raw
      <<head::binary, bxor(byte, 1), tail::binary>>
    end)
  end

  defp content_of(der, path) do
    {:ok, element} = DER.decode(der)

    {_id, content, _raw} =
      Enum.reduce(path, element, fn position, e -> Enum.at(DER.children(e), position) end)

    content
  end

  defp with_content(der, path, fun),
    do:
      patch(der, path, fn {id, content, _raw} -> DER.encode({:primitive, id, fun.(content)}) end)

  ## EnvelopedData

  describe "EnvelopedData" do
    setup do
      %{cms: Cmsex.encrypt!(@content, kek())}
    end

    test "the base message decrypts", %{cms: cms} do
      assert {:ok, %{content: @content}} = Cmsex.decrypt(cms, kek_opts())
    end

    test "E1: no RecipientInfo", %{cms: cms} do
      assert reason(Cmsex.decrypt(put(cms, field(1), {:set, []}), kek_opts())) == :malformed
    end

    test "E2: a RecipientInfo of an unknown kind", %{cms: cms} do
      changed = put(cms, recipient([]), {:constructed, 0xA7, [{:int, 0}]})
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :malformed
    end

    test "E3: an OtherRecipientInfo only", %{cms: cms} do
      changed = put(cms, recipient([]), {:constructed, 0xA4, [{:oid, @unknown}, :null]})
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :recipient_not_found
    end

    test "E4: detached, without :content" do
      {cms, _ciphertext} = Cmsex.encrypt!(@content, kek(), detached: true)
      assert reason(Cmsex.decrypt(cms, kek_opts())) == :content_required
    end

    test "E5: the encrypted content inside, and :content", %{cms: cms} do
      assert reason(Cmsex.decrypt(cms, kek_opts() ++ [content: "x"])) == :unexpected_content
    end

    test "E6: an unknown content-encryption algorithm", %{cms: cms} do
      changed = put(cms, field(2) ++ [1, 0], {:oid, @unknown})

      assert error(Cmsex.decrypt(changed, kek_opts())) == {:unsupported_algorithm, @unknown}
    end

    test "E7: AES-CBC with an IV of 8 bytes, or none", %{cms: cms} do
      short = put(cms, field(2) ++ [1, 1], {:octets, <<0::64>>})
      none = drop(cms, field(2) ++ [1, 1])

      for changed <- [short, none] do
        assert reason(Cmsex.decrypt(changed, kek_opts())) == :malformed
      end
    end

    test "E8: a ciphertext that is not whole blocks", %{cms: cms} do
      changed = with_content(cms, field(2) ++ [2], &binary_part(&1, 0, byte_size(&1) - 1))
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :decryption_failed
    end

    test "E9: a padding that does not check", %{cms: cms} do
      # The last byte of the block before the last changes the last byte
      # of the padding, which is 14 for this content.
      changed = flip(cms, field(2) ++ [2], -17)
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :decryption_failed
    end

    test "E10: CBC has no integrity: a byte of the IV changed decrypts", %{cms: cms} do
      changed = flip(cms, field(2) ++ [1, 1], 0)
      <<first, rest::binary>> = @content
      assert {:ok, %{content: content}} = Cmsex.decrypt(changed, kek_opts())
      assert content == <<bxor(first, 1), rest::binary>>
    end

    test "E11: AES-GCM in an EnvelopedData", %{cms: cms} do
      gcm = Cipher.identifier(Cipher.new(:aes256_gcm))
      changed = put(cms, field(2) ++ [1], gcm)
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :unsupported_algorithm
    end

    test "E12: more recipients than :max_recipients" do
      cms = Cmsex.encrypt!(@content, [kek(), password()])

      assert error(Cmsex.decrypt(cms, kek_opts() ++ [max_recipients: 1])) ==
               {:limit_exceeded, :max_recipients}
    end

    test "E13: decrypt/2 on a SignedData or a DigestedData" do
      for cms <- [Cmsex.sign!(@content, signer()), Cmsex.digest!(@content)] do
        assert reason(Cmsex.decrypt(cms, kek_opts())) == :unsupported_content_type
      end
    end
  end

  ## AuthEnvelopedData

  describe "AuthEnvelopedData" do
    setup do
      attribute = Cmsex.Attribute.new(@unknown, [DER.encode({:utf8, "covered"})])

      %{
        cms: Cmsex.encrypt!(@content, kek(), cipher: :aes256_gcm),
        with_attributes:
          Cmsex.encrypt!(@content, kek(),
            cipher: :aes256_gcm,
            authenticated_attributes: [attribute]
          )
      }
    end

    test "the base messages decrypt", ctx do
      for cms <- [ctx.cms, ctx.with_attributes] do
        assert {:ok, %{content: @content}} = Cmsex.decrypt(cms, kek_opts())
      end
    end

    test "E14: a byte of the ciphertext changed", %{cms: cms} do
      assert reason(Cmsex.decrypt(flip(cms, field(2) ++ [2], 0), kek_opts())) ==
               :decryption_failed
    end

    test "E15: a byte of the tag changed", %{cms: cms} do
      assert reason(Cmsex.decrypt(flip(cms, field(3)), kek_opts())) == :decryption_failed
    end

    test "E16: the tag cut to 12 bytes, with 16 in the parameters", %{cms: cms} do
      changed = with_content(cms, field(3), &binary_part(&1, 0, 12))
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :decryption_failed
    end

    test "E17: no tag", %{cms: cms} do
      assert reason(Cmsex.decrypt(drop(cms, field(3)), kek_opts())) == :malformed
    end

    test "E18: a byte of the authenticated attributes changed", ctx do
      changed = flip(ctx.with_attributes, field(3))
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :decryption_failed
    end

    test "E19: the authenticated attributes taken out", ctx do
      changed = drop(ctx.with_attributes, field(3))
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :decryption_failed
    end

    test "E20: GCM with an empty nonce, or a tag of 8 bytes", %{cms: cms} do
      empty = put(cms, field(2) ++ [1, 1], {:seq, [{:octets, <<>>}, {:int, 16}]})
      short = put(cms, field(2) ++ [1, 1], {:seq, [{:octets, <<0::96>>}, {:int, 8}]})

      for changed <- [empty, short] do
        assert reason(Cmsex.decrypt(changed, kek_opts())) == :malformed
      end
    end

    test "E21: AES-CBC in an AuthEnvelopedData", %{cms: cms} do
      cbc = Cipher.identifier(Cipher.new(:aes256_cbc))
      changed = put(cms, field(2) ++ [1], cbc)
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :unsupported_algorithm
    end

    test "E22: content other than id-data without authenticated attributes", %{cms: cms} do
      # The content type is not under the tag without them.
      changed = put(cms, field(2) ++ [0], {:oid, :signed_data})

      assert error(Cmsex.decrypt(changed, kek_opts())) ==
               {:missing_attribute, :content_type}
    end

    test "E23: a content-type attribute other than the content type" do
      cms = Cmsex.encrypt!(@content, kek(), cipher: :aes256_gcm, content_type: :signed_data)
      changed = put(cms, field(2) ++ [0], {:oid, :data})
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :content_type_mismatch
    end
  end

  ## KEK recipients

  describe "KEK recipients" do
    setup do
      %{cms: Cmsex.encrypt!(@content, kek())}
    end

    test "E24: a key identifier of another", %{cms: cms} do
      assert reason(Cmsex.decrypt(cms, kek: {"another", @kek})) == :recipient_not_found
    end

    test "E25: a wrong key, of the size of the wrap or not", %{cms: cms} do
      for key <- [:binary.copy(<<0x5A>>, 32), :binary.copy(<<0x4B>>, 16)] do
        assert error(Cmsex.decrypt(cms, kek_opts(key))) == {:decryption_failed, nil}
      end
    end

    test "E26: a byte of the wrapped key changed", %{cms: cms} do
      assert reason(Cmsex.decrypt(flip(cms, recipient([3])), kek_opts())) == :decryption_failed
    end

    test "E27: a wrapped key of another size than the cipher's", %{cms: cms} do
      changed = put(cms, recipient([3]), {:octets, KeyWrap.wrap(@kek, <<1::128>>)})
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :decryption_failed
    end

    test "E28: AES key wrap with parameters", %{cms: cms} do
      changed = put(cms, recipient([2]), {:seq, [{:oid, :aes256_wrap}, :null]})
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :malformed
    end

    test "E29: an unknown key-encryption algorithm", %{cms: cms} do
      changed = put(cms, recipient([2, 0]), {:oid, @unknown})
      assert reason(Cmsex.decrypt(changed, kek_opts())) == :unsupported_algorithm
    end
  end

  ## Password recipients

  describe "password recipients" do
    setup do
      %{cms: Cmsex.encrypt!(@content, password())}
    end

    test "the base message decrypts", %{cms: cms} do
      assert {:ok, %{content: @content}} = Cmsex.decrypt(cms, password: @password)
    end

    test "E30: a wrong password", %{cms: cms} do
      assert error(Cmsex.decrypt(cms, password: "another")) == {:decryption_failed, nil}
    end

    test "E31: more iterations than :max_iterations", %{cms: cms} do
      assert error(Cmsex.decrypt(cms, password: @password, max_iterations: 999)) ==
               {:limit_exceeded, :max_iterations}
    end

    test "E32: an unknown PRF", %{cms: cms} do
      changed = put(cms, recipient([1, 1, -1]), {:seq, [{:oid, @unknown}]})
      assert reason(Cmsex.decrypt(changed, password: @password)) == :unsupported_algorithm
    end

    test "E33: no key derivation algorithm", %{cms: cms} do
      # RFC 3211, 2.2: the password is then the key-encryption key itself.
      changed = drop(cms, recipient([1]))
      assert error(Cmsex.decrypt(changed, password: @password)) == {:decryption_failed, nil}
    end

    test "E34: an unknown cipher in id-alg-PWRI-KEK", %{cms: cms} do
      changed = put(cms, recipient([2, 1, 0]), {:oid, @unknown})
      assert reason(Cmsex.decrypt(changed, password: @password)) == :unsupported_algorithm
    end

    test "E35: a key-encryption algorithm other than id-alg-PWRI-KEK", %{cms: cms} do
      changed = put(cms, recipient([2]), {:seq, [{:oid, :aes256_wrap}]})
      assert reason(Cmsex.decrypt(changed, password: @password)) == :unsupported_algorithm
    end

    test "E36: a byte of the encrypted key changed", %{cms: cms} do
      changed = flip(cms, recipient([3]), 0)
      assert error(Cmsex.decrypt(changed, password: @password)) == {:decryption_failed, nil}
    end
  end

  ## Key transport

  describe "key transport" do
    setup ctx do
      %{cms: Cmsex.encrypt!(@content, ctx.rsa[:certificate])}
    end

    test "the base message decrypts", ctx do
      assert {:ok, %{content: @content}} = Cmsex.decrypt(ctx.cms, ctx.rsa)
    end

    test "E37: the credentials of another recipient", ctx do
      other = EncryptedFixtures.credentials("rsa3072")
      assert reason(Cmsex.decrypt(ctx.cms, other)) == :recipient_not_found
    end

    test "E38: a key that is not that of the certificate", ctx do
      opts = Keyword.put(ctx.rsa, :key, EncryptedFixtures.key("rsa3072"))
      assert reason(Cmsex.decrypt(ctx.cms, opts)) == :key_certificate_mismatch
    end

    test "E39: a byte of the RSA-OAEP encrypted key changed", ctx do
      changed = flip(ctx.cms, recipient([3]), 10)
      assert error(Cmsex.decrypt(changed, ctx.rsa)) == {:decryption_failed, nil}
    end

    test "E40: an OAEP label, or a hash, other than the sender's", ctx do
      sha256 = {:seq, [{:oid, :sha256}]}

      params = fn hash, label ->
        {:seq,
         [
           {:explicit, 0, hash},
           {:explicit, 1, {:seq, [{:oid, :mgf1}, hash]}}
         ] ++
           if(label,
             do: [{:explicit, 2, {:seq, [{:oid, :p_specified}, {:octets, label}]}}],
             else: []
           )}
      end

      labelled = put(ctx.cms, recipient([2, 1]), params.(sha256, "label"))
      sha384 = put(ctx.cms, recipient([2, 1]), params.({:seq, [{:oid, :sha384}]}, nil))

      for changed <- [labelled, sha384] do
        assert error(Cmsex.decrypt(changed, ctx.rsa)) == {:decryption_failed, nil}
      end
    end

    test "E41: rsaEncryption with parameters other than NULL", ctx do
      changed = put(ctx.cms, recipient([2]), {:seq, [{:oid, :rsa_encryption}, {:int, 0}]})
      assert reason(Cmsex.decrypt(changed, ctx.rsa)) == :malformed
    end

    test "E42: PKCS #1 v1.5 whose padding does not check", ctx do
      # The OAEP block is not a PKCS #1 v1.5 one. AES-GCM makes the failure
      # certain, which with CBC is that of a random key.
      cms = Cmsex.encrypt!(@content, ctx.rsa[:certificate], cipher: :aes256_gcm)
      changed = put(cms, recipient([2]), {:seq, [{:oid, :rsa_encryption}, :null]})
      assert error(Cmsex.decrypt(changed, ctx.rsa)) == {:decryption_failed, nil}
    end

    test "E43: an unknown key transport algorithm", ctx do
      changed = put(ctx.cms, recipient([2]), {:seq, [{:oid, @unknown}]})
      assert reason(Cmsex.decrypt(changed, ctx.rsa)) == :unsupported_algorithm
    end
  end

  ## Key agreement

  describe "key agreement" do
    setup ctx do
      %{
        p256: Cmsex.encrypt!(@content, ctx.p256[:certificate]),
        p256_opts: ctx.p256,
        x25519: Cmsex.encrypt!(@content, ctx.x25519[:certificate]),
        x25519_opts: ctx.x25519
      }
    end

    # KeyAgreeRecipientInfo: version, [0] originator, [1] ukm,
    # keyEncryptionAlgorithm, recipientEncryptedKeys.
    @originator_key [1, 0, 1]

    test "the base messages decrypt", ctx do
      assert {:ok, %{content: @content}} = Cmsex.decrypt(ctx.p256, ctx.p256_opts)
      assert {:ok, %{content: @content}} = Cmsex.decrypt(ctx.x25519, ctx.x25519_opts)
    end

    test "E44: an originator key that is not on the curve", ctx do
      changed = flip(ctx.p256, recipient(@originator_key))
      assert error(Cmsex.decrypt(changed, ctx.p256_opts)) == {:decryption_failed, nil}
    end

    test "E45: an originator key of another curve", ctx do
      {:ok, cert} = Cmsex.Certificate.parse(EncryptedFixtures.cert("p384"))
      {:ec, :secp384r1, point} = cert.public_key

      key =
        {:implicit, 1,
         {:seq, [{:seq, [{:oid, :ec_public_key}, {:oid, :secp384r1}]}, {:bits, point}]}}

      changed = put(ctx.p256, recipient([1, 0]), key)

      assert error(Cmsex.decrypt(changed, ctx.p256_opts)) ==
               {:malformed, Cmsex.OID.oid(:ec_public_key)}
    end

    test "E46: an X25519 key of low order", ctx do
      changed =
        patch(ctx.x25519, recipient(@originator_key), fn _ ->
          DER.encode({:bits, <<0::256>>})
        end)

      assert error(Cmsex.decrypt(changed, ctx.x25519_opts)) == {:decryption_failed, nil}
    end

    test "E47: a ukm other than the sender's" do
      creds = EncryptedFixtures.credentials("p256")
      cms = Cmsex.encrypt!(@content, Recipient.certificate(creds[:certificate], ukm: "ukm"))
      assert {:ok, _} = Cmsex.decrypt(cms, creds)
      changed = flip(cms, recipient([2, 0]))
      assert error(Cmsex.decrypt(changed, creds)) == {:decryption_failed, nil}
    end

    test "E48: an unknown key agreement scheme", ctx do
      changed = put(ctx.p256, recipient([2, 0]), {:oid, @unknown})
      assert reason(Cmsex.decrypt(changed, ctx.p256_opts)) == :unsupported_algorithm
    end

    test "E49: a key wrap that is not one", ctx do
      changed = put(ctx.p256, recipient([2, 1]), Cipher.identifier(Cipher.new(:aes256_cbc)))
      assert reason(Cmsex.decrypt(changed, ctx.p256_opts)) == :unsupported_algorithm
    end

    test "E50: an originator named by a certificate the message does not carry", ctx do
      # Without the key of the sender there is no key to agree.
      {:ok, cert} = Cmsex.Certificate.parse(EncryptedFixtures.cert("p256"))
      named = {:seq, [{:raw, cert.issuer}, {:int, cert.serial}]}
      changed = put(ctx.p256, recipient([1, 0]), named)
      assert error(Cmsex.decrypt(changed, ctx.p256_opts)) == {:decryption_failed, nil}
    end
  end

  ## EncryptedData

  describe "EncryptedData" do
    setup do
      %{cms: Cmsex.encrypt_with_key!(@content, @kek)}
    end

    test "E51: a key of the wrong size, or a wrong one", %{cms: cms} do
      assert error(Cmsex.decrypt(cms, content_key: binary_part(@kek, 0, 16))) ==
               {:decryption_failed, nil}

      # With CBC, a wrong key decrypts to garbage once in about 256 times.
      case Cmsex.decrypt(cms, content_key: :binary.copy(<<0x5A>>, 32)) do
        {:ok, %{content: content}} -> assert content != @content
        result -> assert error(result) == {:decryption_failed, nil}
      end
    end

    test "E52: no content key", %{cms: cms} do
      assert reason(Cmsex.decrypt(cms, kek_opts())) == :recipient_not_found
    end
  end

  ## AuthenticatedData

  describe "AuthenticatedData" do
    setup do
      %{
        cms: Cmsex.mac!(@content, kek()),
        with_attributes: Cmsex.mac!(@content, kek(), content_type: :signed_data)
      }
    end

    # AuthenticatedData: version, recipientInfos, macAlgorithm, [1]
    # digestAlgorithm, encapContentInfo, [2] authAttrs, mac. Without the
    # attributes, the encapContentInfo is the fourth and the MAC the fifth.

    # The MAC key, unwrapped with the KEK.
    defp mac_key(cms) do
      wrapped = content_of(cms, recipient([3]))
      {:ok, key} = KeyWrap.unwrap(@kek, wrapped)
      key
    end

    test "the base messages verify", ctx do
      for cms <- [ctx.cms, ctx.with_attributes] do
        assert {:ok, _} = Cmsex.verify_mac(cms, kek_opts())
      end
    end

    test "E53: a byte of the MAC changed, or the MAC cut", %{cms: cms} do
      changed = flip(cms, field(4))
      cut = with_content(cms, field(4), &binary_part(&1, 0, 16))

      for changed <- [changed, cut] do
        assert error(Cmsex.verify_mac(changed, kek_opts())) == {:invalid_mac, nil}
      end
    end

    test "E54: a byte of the content changed", %{cms: cms} do
      changed = flip(cms, field(3) ++ [1, 0])
      assert error(Cmsex.verify_mac(changed, kek_opts())) == {:invalid_mac, nil}
    end

    test "E55: a wrong key", %{cms: cms} do
      key = :binary.copy(<<0x5A>>, 32)
      assert error(Cmsex.verify_mac(cms, kek_opts(key))) == {:invalid_mac, nil}
    end

    test "E56: a MAC key shorter than 16 bytes", %{cms: cms} do
      key = <<1::64>>
      wrapped = KeyWrap.wrap_with_padding(@kek, key)

      changed =
        cms
        |> put(recipient([2]), {:seq, [{:oid, :aes256_wrap_pad}]})
        |> put(recipient([3]), {:octets, wrapped})
        |> put(field(4), {:octets, :crypto.mac(:hmac, :sha256, key, @content)})

      assert error(Cmsex.verify_mac(changed, kek_opts())) == {:invalid_mac, nil}
    end

    test "E57: authenticated attributes without digestAlgorithm", ctx do
      changed = drop(ctx.with_attributes, field(3))

      assert error(Cmsex.verify_mac(changed, kek_opts())) == {:malformed, :digest_algorithm}
    end

    test "E58: a message-digest that is not the content's, under a good MAC", ctx do
      cms = ctx.with_attributes
      key = mac_key(cms)

      attributes =
        Cmsex.Compose.attribute_set([
          Cmsex.Attribute.content_type(:signed_data),
          Cmsex.Compose.message_digest(:binary.copy(<<0>>, 32))
        ])

      changed =
        cms
        |> put(field(5), {:raw, DER.retag(attributes, 0xA2)})
        |> put(field(6), {:octets, :crypto.mac(:hmac, :sha256, key, attributes)})

      assert reason(Cmsex.verify_mac(changed, kek_opts())) == :digest_mismatch
    end

    test "E59: content other than id-data without authenticated attributes", %{cms: cms} do
      changed = put(cms, field(3) ++ [0], {:oid, :signed_data})

      assert error(Cmsex.verify_mac(changed, kek_opts())) ==
               {:missing_attribute, :content_type}
    end

    test "E60: an unknown MAC algorithm", %{cms: cms} do
      changed = put(cms, field(2), {:seq, [{:oid, @unknown}]})
      assert reason(Cmsex.verify_mac(changed, kek_opts())) == :unsupported_algorithm
    end

    test "E61: a SHA-1 digest algorithm without :allow_sha1", ctx do
      changed = put(ctx.with_attributes, field(3), {:implicit, 1, {:seq, [{:oid, :sha1}]}})
      assert reason(Cmsex.verify_mac(changed, kek_opts())) == :weak_algorithm
    end

    test "E62: verify_mac/2 on an EnvelopedData" do
      cms = Cmsex.encrypt!(@content, kek())
      assert reason(Cmsex.verify_mac(cms, kek_opts())) == :unsupported_content_type
    end
  end

  ## DigestedData

  describe "DigestedData" do
    setup do
      %{cms: Cmsex.digest!(@content)}
    end

    # DigestedData: version, digestAlgorithm, encapContentInfo, digest.

    test "E63: a byte of the content changed, or of the digest", %{cms: cms} do
      for changed <- [flip(cms, field(2) ++ [1, 0]), flip(cms, field(3))] do
        assert reason(Cmsex.verify_digest(changed)) == :digest_mismatch
      end
    end

    test "E64: a digest of another size", %{cms: cms} do
      changed = with_content(cms, field(3), &binary_part(&1, 0, 20))
      assert reason(Cmsex.verify_digest(changed)) == :digest_mismatch
    end

    test "E65: MD5, and SHA-1 without :allow_sha1", %{cms: cms} do
      for hash <- [:md5, :sha1] do
        changed = put(cms, field(1), {:seq, [{:oid, hash}]})
        assert reason(Cmsex.verify_digest(changed)) == :weak_algorithm
      end
    end

    test "E66: an unknown digest algorithm", %{cms: cms} do
      changed = put(cms, field(1), {:seq, [{:oid, @unknown}]})
      assert reason(Cmsex.verify_digest(changed)) == :unsupported_algorithm
    end

    test "E67: detached, without :content" do
      cms = Cmsex.digest!(@content, detached: true)
      assert reason(Cmsex.verify_digest(cms)) == :content_required
    end

    test "E68: verify_digest/2 on an AuthenticatedData" do
      assert reason(Cmsex.verify_digest(Cmsex.mac!(@content, kek()))) ==
               :unsupported_content_type
    end
  end
end
