defmodule Cmsex.CipherTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Cmsex.{Algorithm, Cipher, DER, KDF, LegacyWrap, PasswordWrap}

  defp hex(string), do: Base.decode16!(String.replace(string, ~r/\s/, ""), case: :mixed)

  defp read(term) do
    {:ok, element} = term |> DER.encode() |> DER.decode()
    {:ok, alg} = Algorithm.read(element)
    Cipher.read(alg)
  end

  defp flip(bin, at) do
    <<head::binary-size(^at), byte, tail::binary>> = bin
    <<head::binary, bxor(byte, 1), tail::binary>>
  end

  describe "Cipher" do
    property "what encrypt/4 writes, decrypt/5 reads, and the identifier reads back" do
      check all name <- member_of(Cipher.names()),
                plaintext <- binary(max_length: 100),
                aad <- binary(max_length: 20) do
        cipher = Cipher.new(name)
        key = Cipher.random_key(cipher)
        {ciphertext, tag} = Cipher.encrypt(cipher, key, plaintext, aad)

        assert Cipher.decrypt(cipher, key, ciphertext, aad, tag) == {:ok, plaintext}
        assert read(Cipher.identifier(cipher)) == {:ok, cipher}
        assert Cipher.aead?(cipher) == (tag != nil)
      end
    end

    test "CBC pads to whole blocks, always adding some (RFC 5652, 6.3)" do
      cipher = Cipher.new(:aes128_cbc)
      key = Cipher.random_key(cipher)

      for {size, expected} <- [{0, 16}, {1, 16}, {15, 16}, {16, 32}, {17, 32}] do
        {ciphertext, nil} = Cipher.encrypt(cipher, key, :binary.copy(<<7>>, size))
        assert byte_size(ciphertext) == expected
      end

      triple = Cipher.new(:des_ede3_cbc)
      {ciphertext, nil} = Cipher.encrypt(triple, Cipher.random_key(triple), "1234567")
      assert byte_size(ciphertext) == 8
    end

    test "CBC refuses bad padding, partial blocks and a key of the wrong size" do
      cipher = Cipher.new(:aes128_cbc)
      key = Cipher.random_key(cipher)
      raw = &:crypto.crypto_one_time(:aes_128_cbc, key, cipher.iv, &1, true)

      for last <- [<<0>>, <<17>>, <<255>>, <<2, 3>>, <<3, 3, 2>>] do
        block = :binary.copy(<<0xAA>>, 16 - byte_size(last)) <> last
        assert Cipher.decrypt(cipher, key, raw.(block)) == :error
      end

      assert Cipher.decrypt(cipher, key, raw.(:binary.copy(<<16>>, 16))) == {:ok, ""}

      assert Cipher.decrypt(cipher, key, raw.(:binary.copy(<<1>>, 16))) ==
               {:ok, :binary.copy(<<1>>, 15)}

      assert Cipher.decrypt(cipher, key, <<>>) == :error
      assert Cipher.decrypt(cipher, key, :binary.copy(<<0>>, 15)) == :error
      assert Cipher.decrypt(cipher, key, :binary.copy(<<0>>, 33)) == :error
      assert Cipher.decrypt(cipher, <<0::64>>, raw.(:binary.copy(<<16>>, 16))) == :error
    end

    test "the authenticated ciphers check the tag, its size, the AAD and the ciphertext" do
      for name <- [:aes128_gcm, :aes256_ccm, :chacha20_poly1305] do
        cipher = Cipher.new(name)
        key = Cipher.random_key(cipher)
        {ciphertext, tag} = Cipher.encrypt(cipher, key, "attack at dawn", "header")

        assert Cipher.decrypt(cipher, key, ciphertext, "header", tag) == {:ok, "attack at dawn"}
        assert Cipher.decrypt(cipher, key, ciphertext, "header", flip(tag, 0)) == :error
        assert Cipher.decrypt(cipher, key, flip(ciphertext, 3), "header", tag) == :error
        assert Cipher.decrypt(cipher, key, ciphertext, "Header", tag) == :error

        assert Cipher.decrypt(cipher, Cipher.random_key(cipher), ciphertext, "header", tag) ==
                 :error

        assert Cipher.decrypt(cipher, key, ciphertext, "header", nil) == :error
        assert Cipher.decrypt(cipher, key, ciphertext, "header", tag <> <<0>>) == :error

        # `:crypto` takes a truncated GCM tag; the parameters say 16 bytes.
        assert Cipher.decrypt(cipher, key, ciphertext, "header", binary_part(tag, 0, 1)) == :error
      end
    end

    test "tag sizes" do
      assert Cipher.new(:aes128_gcm, 12).tag_size == 12
      assert Cipher.new(:aes128_ccm, 4).tag_size == 4
      assert Cipher.new(:aes128_cbc, 12).tag_size == nil

      for {name, size} <- [aes128_gcm: 11, aes128_gcm: 17, aes128_ccm: 5, chacha20_poly1305: 12] do
        assert_raise ArgumentError, fn -> Cipher.new(name, size) end
      end

      assert_raise ArgumentError, fn -> Cipher.new(:rc2_cbc) end
      assert_raise ArgumentError, fn -> Cipher.new(:aes128_wrap) end
    end

    test "nonces: 12 bytes for GCM and ChaCha20-Poly1305, 7 for CCM" do
      assert byte_size(Cipher.new(:aes256_gcm).iv) == 12
      assert byte_size(Cipher.new(:aes256_ccm).iv) == 7
      assert byte_size(Cipher.new(:chacha20_poly1305).iv) == 12
      assert byte_size(Cipher.new(:aes256_cbc).iv) == 16
      assert byte_size(Cipher.new(:des_ede3_cbc).iv) == 8
      assert Cipher.new(:aes256_gcm).iv != Cipher.new(:aes256_gcm).iv
    end

    test "the GCM and CCM tag size is left out when it is 12, the default (RFC 5084)" do
      cipher = %{Cipher.new(:aes128_gcm, 12) | iv: <<1::96>>}

      assert DER.encode(Cipher.identifier(cipher)) ==
               DER.encode({:seq, [{:oid, :aes128_gcm}, {:seq, [{:octets, <<1::96>>}]}]})

      cipher = %{Cipher.new(:aes128_ccm, 16) | iv: <<1::56>>}

      assert DER.encode(Cipher.identifier(cipher)) ==
               DER.encode(
                 {:seq, [{:oid, :aes128_ccm}, {:seq, [{:octets, <<1::56>>}, {:int, 16}]}]}
               )

      assert {:ok, %{tag_size: 12}} =
               read({:seq, [{:oid, :aes256_gcm}, {:seq, [{:octets, <<1::96>>}]}]})

      assert {:ok, %{tag_size: 12, iv: <<1::64>>}} =
               read({:seq, [{:oid, :aes256_gcm}, {:seq, [{:octets, <<1::64>>}, {:int, 12}]}]})
    end

    test "parameters that do not fit are malformed" do
      malformed = [
        {:seq, [{:oid, :aes128_cbc}]},
        {:seq, [{:oid, :aes128_cbc}, :null]},
        {:seq, [{:oid, :aes128_cbc}, {:octets, <<0::64>>}]},
        {:seq, [{:oid, :des_ede3_cbc}, {:octets, <<0::128>>}]},
        {:seq, [{:oid, :aes128_gcm}, {:octets, <<0::96>>}]},
        {:seq, [{:oid, :aes128_gcm}, {:seq, [{:octets, <<>>}]}]},
        {:seq, [{:oid, :aes128_gcm}, {:seq, [{:octets, <<0::96>>}, {:int, 11}]}]},
        {:seq, [{:oid, :aes128_gcm}, {:seq, [{:octets, <<0::96>>}, {:int, 17}]}]},
        {:seq, [{:oid, :aes128_gcm}, {:seq, [{:octets, <<0::96>>}, {:int, 16}, {:int, 16}]}]},
        {:seq, [{:oid, :aes128_ccm}, {:seq, [{:octets, <<0::48>>}]}]},
        {:seq, [{:oid, :aes128_ccm}, {:seq, [{:octets, <<0::112>>}]}]},
        {:seq, [{:oid, :aes128_ccm}, {:seq, [{:octets, <<0::56>>}, {:int, 5}]}]},
        {:seq, [{:oid, :chacha20_poly1305}, {:octets, <<0::64>>}]},
        {:seq, [{:oid, :chacha20_poly1305}]},
        {:seq, [{:oid, :rc2_cbc}, {:octets, <<0::64>>}]},
        {:seq, [{:oid, :rc2_cbc}, {:seq, [{:int, 58}, {:octets, <<0::32>>}]}]}
      ]

      for term <- malformed do
        assert {:error, :malformed, _} = read(term), inspect(term)
      end
    end

    test "RC2: 40, 64 and 128 effective key bits (RFC 3370, 5.2)" do
      for {version, size} <- [{160, 5}, {120, 8}, {58, 16}] do
        result =
          read({:seq, [{:oid, :rc2_cbc}, {:seq, [{:int, version}, {:octets, <<0::64>>}]}]})

        # Without RC2 in :crypto, the parameters are read all the same, and
        # only then refused.
        if :rc2_cbc in :crypto.supports(:ciphers),
          do: assert({:ok, %{name: :rc2_cbc, key_size: ^size}} = result),
          else: assert({:error, :not_available, :rc2_cbc} = result)
      end

      # The others, including the 32 bits of a bare IV in RFC 2268, are not read.
      assert {:error, :unsupported_algorithm, _} =
               read({:seq, [{:oid, :rc2_cbc}, {:seq, [{:int, 52}, {:octets, <<0::64>>}]}]})
    end

    test "RC2 encrypts and decrypts, when this system has it" do
      cipher = %{name: :rc2_cbc, crypto: :rc2_cbc, key_size: 16, iv: <<1::64>>, tag_size: nil}

      if :rc2_cbc in :crypto.supports(:ciphers) do
        key = Cipher.random_key(cipher)
        {ciphertext, nil} = Cipher.encrypt(cipher, key, "old content")
        assert Cipher.decrypt(cipher, key, ciphertext) == {:ok, "old content"}
        assert read(Cipher.identifier(cipher)) == {:ok, cipher}
      end
    end

    test "algorithms it does not decrypt" do
      for term <- [
            {:seq, [{:oid, :des_cbc}, {:octets, <<0::64>>}]},
            {:seq, [{:oid, :aes128_wrap}]},
            {:seq, [{:oid, {1, 2, 3, 4}}, :null]}
          ] do
        assert {:error, :unsupported_algorithm, _} = read(term)
      end
    end

    test "RFC 4134, 7.1 and 7.2: EncryptedData with Triple-DES" do
      key = hex("73 7c 79 1f 25 ea d0 e0 46 29 25 43 52 f7 dc 62 91 e5 cb 26 91 7a da 32")

      for name <- ["7.1.bin", "7.2.bin"] do
        {:ok, root} = DER.decode(File.read!("test/fixtures/rfc4134/" <> name))
        [_oid, explicit] = DER.children(root)
        [encrypted_data] = DER.children(explicit)
        [_version, info | _] = DER.children(encrypted_data)
        [_type, alg, {0x80, ciphertext, _}] = DER.children(info)
        {:ok, alg} = Algorithm.read(alg)
        {:ok, cipher} = Cipher.read(alg)

        assert cipher.name == :des_ede3_cbc
        assert Cipher.decrypt(cipher, key, ciphertext) == {:ok, "This is some sample content."}
      end
    end
  end

  describe "KDF" do
    # RFC 5869, A.1, A.2 and A.3.
    test "HKDF" do
      ikm = :binary.copy(<<0x0B>>, 22)

      assert KDF.hkdf(
               :sha256,
               hex("000102030405060708090a0b0c"),
               ikm,
               hex("f0f1f2f3f4f5f6f7f8f9"),
               42
             ) ==
               hex(
                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
               )

      assert KDF.hkdf(:sha256, <<>>, ikm, <<>>, 42) ==
               hex(
                 "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
               )

      salt = :binary.list_to_bin(Enum.to_list(0x60..0xAF))
      info = :binary.list_to_bin(Enum.to_list(0xB0..0xFF))
      ikm = :binary.list_to_bin(Enum.to_list(0x00..0x4F))

      assert KDF.hkdf(:sha256, salt, ikm, info, 82) ==
               hex("""
               b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
               59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
               cc30c58179ec3e87c14c01d5c1f3434f1d87
               """)

      assert_raise ArgumentError, fn -> KDF.hkdf(:sha256, <<>>, ikm, <<>>, 255 * 32 + 1) end
    end

    # RFC 6070, 2, without the one of 16777216 iterations.
    test "PBKDF2" do
      vectors = [
        {"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
        {"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
        {"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
        {"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
         "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
        {"pass\0word", "sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"}
      ]

      for {password, salt, iterations, length, expected} <- vectors do
        assert KDF.pbkdf2(:sha1, password, salt, iterations, length) == hex(expected)
      end
    end

    test "X9.63: blocks of the hash of the secret, a counter and the shared info" do
      secret = :crypto.strong_rand_bytes(32)
      info = "shared info"
      first = :crypto.hash(:sha256, [secret, <<1::32>>, info])
      second = :crypto.hash(:sha256, [secret, <<2::32>>, info])

      assert KDF.x963(:sha256, secret, info, 16) == binary_part(first, 0, 16)
      assert KDF.x963(:sha256, secret, info, 32) == first
      assert KDF.x963(:sha256, secret, info, 40) == first <> binary_part(second, 0, 8)
      assert byte_size(KDF.x963(:sha512, secret, info, 32)) == 32
      assert KDF.x963(:sha1, secret, info, 20) == :crypto.hash(:sha, [secret, <<1::32>>, info])
    end
  end

  describe "LegacyWrap" do
    # RFC 3217, 3.4.
    @des3_cek "2923 bf85 e06d d6ae 5291 49f1 f1ba e9ea b3a7 da3d 860d 3e98"
    @des3_kek "255e 0d1c 07b6 46df b313 4cc8 43ba 8aa7 1f02 5b7c 0838 251f"
    @des3_wrapped """
    6901 0761 8ef0 92b3 b48c a179 6b23 4ae9 fa33 ebb4 1596 0403
    7db5 d6a8 4eb3 aac2 768c 6327 75a4 67d4
    """

    test "Triple-DES key wrap, the example of RFC 3217" do
      kek = hex(@des3_kek)
      wrapped = hex(@des3_wrapped)

      assert LegacyWrap.des3_wrap(kek, hex(@des3_cek), hex("5dd4 cbfc 96f5 453b")) == wrapped
      assert LegacyWrap.des3_unwrap(kek, wrapped) == {:ok, hex(@des3_cek)}
    end

    test "Triple-DES key unwrap refuses a changed byte, a wrong key, a wrong size, bad parity" do
      kek = hex(@des3_kek)
      wrapped = hex(@des3_wrapped)

      for at <- 0..39, do: assert(LegacyWrap.des3_unwrap(kek, flip(wrapped, at)) == :error)

      # DES ignores the low bit of each key byte, so the wrong key changes more.
      assert LegacyWrap.des3_unwrap(:crypto.exor(kek, :binary.copy(<<0x80>>, 24)), wrapped) ==
               :error

      assert LegacyWrap.des3_unwrap(kek, binary_part(wrapped, 0, 32)) == :error
      assert LegacyWrap.des3_unwrap(binary_part(kek, 0, 16), wrapped) == :error

      # A key without odd parity, with a checksum that matches it.
      cek = :binary.copy(<<0>>, 24)
      icv = binary_part(:crypto.hash(:sha, cek), 0, 8)
      iv = <<1::64>>
      temp1 = :crypto.crypto_one_time(:des_ede3_cbc, kek, iv, cek <> icv, true)
      temp3 = (iv <> temp1) |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

      bad =
        :crypto.crypto_one_time(:des_ede3_cbc, kek, <<0x4ADDA22C79E82105::64>>, temp3, true)

      assert LegacyWrap.des3_unwrap(kek, bad) == :error
    end

    test "Triple-DES key wrap sets odd parity" do
      kek = hex(@des3_kek)
      wrapped = LegacyWrap.des3_wrap(kek, :binary.copy(<<0>>, 24), <<1::64>>)
      assert LegacyWrap.des3_unwrap(kek, wrapped) == {:ok, :binary.copy(<<1>>, 24)}
    end

    # RFC 3217, 4.4, as erratum 639 gives it with 128 effective key bits:
    # the example in the RFC itself uses 40, which `:crypto` does not do
    # with a 16-byte key.
    @rc2_kek "fd04 fd08 0607 07fb 0003 feff fd02 fe05"
    @rc2_cek "b70a 25fb c9d8 6a86 050c e0d7 11ea d4d9"
    @rc2_wrapped """
    f4d8 021c 1ea4 63d2 17a9 eb69 29ff a577 36d3 e203 86c9 0993
    835b 4be4 ad8d 8a1b c63b 25de 2bf7 7993
    """

    test "RC2 key wrap, the example of RFC 3217 with 128 bits, when this system has RC2" do
      if :rc2_cbc in :crypto.supports(:ciphers) do
        kek = hex(@rc2_kek)
        wrapped = hex(@rc2_wrapped)
        iv = hex("c7d9 0059 b29e 97f7")

        assert LegacyWrap.rc2_wrap(kek, hex(@rc2_cek), iv, hex("4845 cce7 fd12 50")) == wrapped
        assert LegacyWrap.rc2_unwrap(kek, wrapped) == {:ok, hex(@rc2_cek)}

        for at <- 0..39, do: assert(LegacyWrap.rc2_unwrap(kek, flip(wrapped, at)) == :error)
        assert LegacyWrap.rc2_unwrap(kek, binary_part(wrapped, 0, 36)) == :error
        assert LegacyWrap.rc2_unwrap(kek, binary_part(wrapped, 0, 16)) == :error

        # Keys of 5 and 8 bytes, the most and the least padding.
        for cek <- [<<1::40>>, <<1::56>>, <<1::64>>] do
          pad = :binary.copy(<<0xEE>>, rem(8 - rem(1 + byte_size(cek), 8), 8))
          wrapped = LegacyWrap.rc2_wrap(kek, cek, iv, pad)
          assert LegacyWrap.rc2_unwrap(kek, wrapped) == {:ok, cek}
        end
      end
    end
  end

  describe "PasswordWrap" do
    # RFC 3211, 3: the first vector, DES-CBC with a key from "password".
    test "the DES vector of RFC 3211" do
      kek = KDF.pbkdf2(:sha1, "password", hex("12 34 56 78 78 56 34 12"), 5, 8)
      assert kek == hex("D1 DA A7 86 15 F2 87 E6")

      if :des_cbc in :crypto.supports(:ciphers) do
        assert :crypto.crypto_one_time(:des_cbc, kek, <<0::64>>, <<0::64>>, true) ==
                 hex("9B BD 78 FC 11 A3 A9 08")

        cek = hex("8C 62 7C 89 73 23 A2 F8")
        iv = hex("EF E5 98 EF 21 B3 3D 6D")
        wrapped = hex("B8 1B 25 65 EE 37 3C A6 DE DC A2 6A 17 8B 0C 10")

        assert PasswordWrap.wrap(:des_cbc, kek, iv, 8, cek, hex("C4 36 F5 41")) == wrapped
        assert PasswordWrap.unwrap(:des_cbc, kek, iv, 8, wrapped) == {:ok, cek}
      end
    end

    # RFC 3211, 3: the second vector, a 256-bit key wrapped with Triple-DES.
    test "the Triple-DES vector of RFC 3211" do
      password = "All n-entities must communicate with other n-entities via n-1 entiteeheehees"
      kek = KDF.pbkdf2(:sha1, password, hex("12 34 56 78 78 56 34 12"), 500, 24)

      assert kek ==
               hex("6A 89 70 BF 68 C9 2C AE A8 4A 8D F2 85 10 85 86 07 12 63 80 CC 47 AB 2D")

      cek =
        hex("""
        8C 63 7D 88 72 23 A2 F9 65 B5 66 EB 01 4B 0F A5
        D5 23 00 A3 F7 EA 40 FF FC 57 72 03 C7 1B AF 3B
        """)

      iv = hex("BA F1 CA 79 31 21 3C 4E")

      wrapped =
        hex("""
        C0 3C 51 4A BD B9 E2 C5 AA C0 38 57 2B 5E 24 55
        38 76 B3 77 AA FB 82 EC A5 A9 D7 3F 8A B1 43 D9
        EC 74 E6 CA D7 DB 26 0C
        """)

      assert PasswordWrap.wrap(:des_ede3_cbc, kek, iv, 8, cek, hex("FA 06 0A 45")) == wrapped
      assert PasswordWrap.unwrap(:des_ede3_cbc, kek, iv, 8, wrapped) == {:ok, cek}
    end

    property "round trip with AES, and a wrong key fails" do
      check all size <- member_of([16, 24, 32]),
                cek_size <- integer(3..64) do
        kek = :crypto.strong_rand_bytes(size)
        crypto = %{16 => :aes_128_cbc, 24 => :aes_192_cbc, 32 => :aes_256_cbc}[size]
        iv = :crypto.strong_rand_bytes(16)
        cek = :crypto.strong_rand_bytes(cek_size)
        wrapped = PasswordWrap.wrap(crypto, kek, iv, 16, cek)

        assert byte_size(wrapped) == max(32, div(4 + cek_size + 15, 16) * 16)
        assert PasswordWrap.unwrap(crypto, kek, iv, 16, wrapped) == {:ok, cek}
      end
    end

    test "unwrap refuses a wrong key, a changed byte, and sizes that are not whole blocks" do
      kek = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(16)
      cek = :crypto.strong_rand_bytes(32)
      wrapped = PasswordWrap.wrap(:aes_256_cbc, kek, iv, 16, cek)

      # One time in about 2^24 a wrong key passes the check value; RFC 3211
      # leaves the rest to the content.
      wrong = :crypto.strong_rand_bytes(32)
      assert PasswordWrap.unwrap(:aes_256_cbc, wrong, iv, 16, wrapped) == :error

      for at <- 0..(byte_size(wrapped) - 1) do
        assert PasswordWrap.unwrap(:aes_256_cbc, kek, iv, 16, flip(wrapped, at)) != {:ok, cek}
      end

      assert PasswordWrap.unwrap(:aes_256_cbc, kek, iv, 16, binary_part(wrapped, 0, 16)) == :error
      assert PasswordWrap.unwrap(:aes_256_cbc, kek, iv, 16, binary_part(wrapped, 0, 47)) == :error
      assert PasswordWrap.unwrap(:aes_256_cbc, kek, iv, 16, <<>>) == :error
    end
  end
end
