defmodule Cmsex.EncryptedTest do
  use ExUnit.Case, async: true

  # The messages of test/fixtures/encrypted, written by OpenSSL 3, LibreSSL
  # and Python cryptography for the recipients there (see gen_encrypted.sh
  # and INFO.txt there), and by Cmsex itself (gen_written.exs).

  import Cmsex.EncryptedFixtures

  alias Cmsex.{
    Authenticated,
    Decrypted,
    DigestedData,
    EncryptedData,
    EnvelopedData,
    Error,
    RecipientInfo
  }

  # {message, credentials, cipher, recipient}, the credentials as a
  # recipient of the material, :kek or :password, and the recipient as the
  # key-encryption algorithm of the RecipientInfo that decrypts, with the
  # key wrap for key agreement.
  @enveloped [
    {"o3_rsa_v15", "rsa2048", :aes256_cbc, :rsa_encryption},
    {"o3_rsa_v15_aes128", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"o3_rsa_v15_aes192", "rsa2048", :aes192_cbc, :rsa_encryption},
    {"o3_rsa_v15_des3", "rsa2048", :des_ede3_cbc, :rsa_encryption},
    {"o3_rsa_v15_rc2_40", "rsa2048", :rc2_cbc, :rsa_encryption},
    {"o3_rsa_v15_rc2_128", "rsa2048", :rc2_cbc, :rsa_encryption},
    {"o3_rsa_keyid", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"o3_rsa_oaep", "rsa2048", :aes128_cbc, :rsaes_oaep},
    {"o3_rsa_oaep_sha256", "rsa2048", :aes128_cbc, :rsaes_oaep},
    {"o3_rsa_oaep_sha512", "rsa2048", :aes256_cbc, :rsaes_oaep},
    {"o3_rsa_oaep_mixed", "rsa2048", :aes128_cbc, :rsaes_oaep},
    {"o3_rsa_oaep_label", "rsa2048", :aes128_cbc, :rsaes_oaep},
    {"o3_rsa_oaep_keyid", "rsa2048", :aes128_cbc, :rsaes_oaep},
    {"o3_rsa_gcm128", "rsa2048", :aes128_gcm, :rsa_encryption},
    {"o3_rsa_gcm192", "rsa2048", :aes192_gcm, :rsa_encryption},
    {"o3_rsa_gcm256", "rsa2048", :aes256_gcm, :rsa_encryption},
    {"o3_rsa_stream", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"o3_rsa_stream_gcm", "rsa2048", :aes256_gcm, :rsa_encryption},
    {"o3_p256", "p256", :aes128_cbc, {:std_dh_sha1kdf, :aes128_wrap}},
    {"o3_p256_keyid", "p256", :aes128_cbc, {:std_dh_sha1kdf, :aes128_wrap}},
    {"o3_p256_sha224kdf", "p256", :aes128_cbc, {:std_dh_sha224kdf, :aes128_wrap}},
    {"o3_p256_sha256kdf", "p256", :aes128_cbc, {:std_dh_sha256kdf, :aes128_wrap}},
    {"o3_p256_cofactor", "p256", :aes128_cbc, {:cofactor_dh_sha1kdf, :aes128_wrap}},
    {"o3_p256_wrap256", "p256", :aes128_cbc, {:std_dh_sha1kdf, :aes256_wrap}},
    {"o3_p256_gcm", "p256", :aes256_gcm, {:std_dh_sha1kdf, :aes256_wrap}},
    {"o3_p256_des3_wrap", "p256", :des_ede3_cbc, {:std_dh_sha1kdf, :cms3des_wrap}},
    {"o3_p384_sha384kdf", "p384", :aes256_cbc, {:std_dh_sha384kdf, :aes256_wrap}},
    {"o3_p521_sha512kdf", "p521", :aes256_cbc, {:std_dh_sha512kdf, :aes256_wrap}},
    {"o3_bp256", "bp256", :aes128_cbc, {:std_dh_sha1kdf, :aes128_wrap}},
    {"o3_bp384_sha384kdf", "bp384", :aes256_cbc, {:std_dh_sha384kdf, :aes256_wrap}},
    {"o3_kek128", :kek, :aes128_cbc, :aes128_wrap},
    {"o3_kek192", :kek, :aes128_cbc, :aes192_wrap},
    {"o3_kek256", :kek, :aes256_cbc, :aes256_wrap},
    {"o3_kek_gcm", :kek, :aes128_gcm, :aes128_wrap},
    {"o3_pwri", :password, :aes256_cbc, :pwri_kek},
    {"o3_pwri_kek_aes128", :password, :aes256_cbc, :pwri_kek},
    {"o3_pwri_kek_des3", :password, :aes256_cbc, :pwri_kek},
    {"o3_pwri_gcm", :password, :aes256_gcm, :pwri_kek},
    {"o3_mixed", "rsa2048", :aes256_cbc, :rsa_encryption},
    {"o3_mixed", "p256", :aes256_cbc, {:std_dh_sha1kdf, :aes256_wrap}},
    {"o3_mixed", "p384", :aes256_cbc, {:std_dh_sha1kdf, :aes256_wrap}},
    {"o3_mixed", :kek, :aes256_cbc, :aes128_wrap},
    {"o3_mixed", :password, :aes256_cbc, :pwri_kek},
    {"o3_pkcs7", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"lre_rsa_v15", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"lre_rsa_v15_des3", "rsa2048", :des_ede3_cbc, :rsa_encryption},
    {"lre_rsa_oaep", "rsa2048", :aes256_cbc, :rsaes_oaep},
    {"lre_rsa_stream", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"lre_kek", :kek, :aes128_cbc, :aes128_wrap},
    {"lre_pwri", :password, :aes256_cbc, :pwri_kek},
    {"py_aes128", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"py_aes256", "rsa2048", :aes256_cbc, :rsa_encryption},
    {"py_two", "rsa2048", :aes128_cbc, :rsa_encryption},
    {"py_two", "rsa3072", :aes128_cbc, :rsa_encryption}
  ]

  # {message, size of the content key, cipher}
  @encrypted [
    {"o3_encrypted128", 16, :aes128_cbc},
    {"o3_encrypted256", 32, :aes256_cbc},
    {"o3_encrypted_des3", 24, :des_ede3_cbc},
    {"lre_encrypted", 16, :aes128_cbc}
  ]

  # {message, digest}
  @digested [
    {"o3_digest_sha256", :sha256},
    {"o3_digest_sha512", :sha512},
    {"o3_digest_sha1", :sha1},
    {"o3_digest_stream", :sha384},
    {"lre_digest", :sha256}
  ]

  # {message, credentials, reason, detail}
  @invalid [
    # GCM in an EnvelopedData, with an IV of zeros in place of
    # GCMParameters and no ciphertext.
    {"lre_rsa_gcm", "rsa2048", :malformed, Cmsex.OID.oid(:aes256_gcm)},
    # RFC 3217 wraps only a Triple-DES key with Triple-DES; OpenSSL wraps
    # an AES-128 key with it, which does not unwrap here.
    {"o3_p256_des3_wrap_aes", "p256", :decryption_failed, nil}
  ]

  # The messages of Cmsex: {message, function, the credentials of each
  # recipient}. Some have content of another type, an OID of the arc of
  # RFC 5612 for documentation.
  @written [
    {"cmsex_enveloped", :decrypt, ["rsa2048", "p256", "bp256", "x25519", :kek, :password]},
    {"cmsex_enveloped_ski", :decrypt, ["rsa3072", "p384"]},
    {"cmsex_enveloped_hkdf", :decrypt, ["p256", "p521", "x448"]},
    {"cmsex_auth_enveloped_gcm", :decrypt, ["rsa2048", :kek]},
    {"cmsex_auth_enveloped_ccm", :decrypt, [:kek, "bp384"]},
    {"cmsex_auth_enveloped_chacha", :decrypt, ["x448", :password]},
    {"cmsex_encrypted", :decrypt, [:content_key]},
    {"cmsex_auth_data", :verify_mac, ["rsa2048", "p256", "x25519", :kek, :password]},
    {"cmsex_auth_data_attributes", :verify_mac, [:kek, "p384"]},
    {"cmsex_digested", :verify_digest, [:none]},
    {"cmsex_digested_other_type", :verify_digest, [:none]}
  ]

  @other_type {1, 3, 6, 1, 4, 1, 32_473, 3}

  # The options of decrypt/2 for the credentials of a message: the KEK has
  # the size of its key wrap.
  defp options(message, :kek), do: [kek: {kek_id(), secret(kek_size(message))}]
  defp options(_message, :password), do: [password: password()]
  defp options(_message, :content_key), do: [content_key: secret(24)]
  defp options(_message, :none), do: []
  defp options(_message, name), do: credentials(name)

  defp kek_size(message) do
    {:ok, %{recipient_infos: infos}} = Cmsex.decode(read!(message <> ".p7m"))
    %RecipientInfo{key_encryption_algorithm: wrap} = Enum.find(infos, &(&1.type == :kek))
    Cmsex.Recipient.wrap_size(wrap)
  end

  defp decrypt(message, credentials),
    do: Cmsex.decrypt(read!(message <> ".p7m"), options(message, credentials))

  defp rc2_available?, do: :rc2_cbc in :crypto.supports(:ciphers)

  test "every message is here" do
    listed =
      Enum.map(
        @enveloped ++ @encrypted ++ @digested ++ @invalid ++ @written,
        &(elem(&1, 0) <> ".p7m")
      )

    assert Enum.sort(Enum.uniq(listed)) == Enum.sort(messages())
  end

  describe "messages of other tools" do
    test "EnvelopedData and AuthEnvelopedData decrypt for each of their recipients" do
      for {message, credentials, cipher, recipient} <- @enveloped,
          cipher != :rc2_cbc or rc2_available?() do
        assert {:ok, %Decrypted{} = decrypted} = decrypt(message, credentials),
               "#{message} with #{inspect(credentials)}"

        assert decrypted.content == content(), message
        assert decrypted.content_type == :data
        assert decrypted.message.content_encryption_algorithm == cipher, message

        type = if Cmsex.Cipher.aead?(cipher), do: :auth_enveloped_data, else: :enveloped_data
        assert decrypted.message.type == type, message
        assert recipient(decrypted.recipient) == recipient, message
      end
    end

    test "RC2, where the :crypto of the system has it" do
      for {"o3_rsa_v15_rc2" <> _ = message, credentials, _cipher, _recipient} <- @enveloped do
        if rc2_available?(),
          do: assert({:ok, %Decrypted{}} = decrypt(message, credentials)),
          else:
            assert(
              {:error, %Error{reason: :not_available, detail: :rc2_cbc}} =
                decrypt(message, credentials)
            )
      end
    end

    # The job of CI on an OpenSSL without the legacy provider sets
    # CMSEX_EXPECT_NO_LEGACY, so that the tests of RC2 surely take the path
    # of the error there.
    if System.get_env("CMSEX_EXPECT_NO_LEGACY") in [nil, ""],
      do: @tag(skip: "CMSEX_EXPECT_NO_LEGACY is not set")

    test "RC2 is missing, as CMSEX_EXPECT_NO_LEGACY says" do
      refute rc2_available?(), "RC2 is in :crypto: the legacy provider was loaded"
    end

    test "EncryptedData decrypts with its content key" do
      for {message, size, cipher} <- @encrypted do
        assert {:ok, %Decrypted{recipient: nil} = decrypted} =
                 Cmsex.decrypt(read!(message <> ".p7m"), content_key: secret(size))

        assert decrypted.content == content(), message
        assert %EncryptedData{content_encryption_algorithm: ^cipher} = decrypted.message
      end
    end

    test "DigestedData verifies, SHA-1 only when allowed" do
      for {message, digest} <- @digested do
        der = read!(message <> ".p7m")
        assert {:ok, %DigestedData{} = digested} = Cmsex.verify_digest(der, allow_sha1: true)
        assert digested.content == content(), message
        assert digested.digest_algorithm == digest

        if digest == :sha1,
          do: assert({:error, %Error{reason: :weak_algorithm}} = Cmsex.verify_digest(der)),
          else: assert({:ok, %DigestedData{}} = Cmsex.verify_digest(der))
      end
    end

    test "what is refused, and why" do
      for {message, credentials, reason, detail} <- @invalid do
        assert {:error, %Error{reason: ^reason, detail: ^detail}} =
                 decrypt(message, credentials),
               message
      end
    end
  end

  describe "messages of Cmsex" do
    test "each reads with the credentials of each of its recipients" do
      for {message, function, all} <- @written, credentials <- all do
        der = read!(message <> ".p7m")

        assert {:ok, result} = apply(Cmsex, function, [der, options(message, credentials)]),
               "#{message} with #{inspect(credentials)}"

        assert result.content == content(), message
        assert result.content_type in [:data, @other_type], message

        case result do
          %Decrypted{recipient: nil} -> assert credentials == :content_key
          %Decrypted{recipient: %RecipientInfo{}} -> :ok
          %Authenticated{recipient: %RecipientInfo{}} -> :ok
          %DigestedData{} -> assert credentials == :none
        end
      end
    end

    test "what they carry besides the content" do
      {:ok, decrypted} = Cmsex.decrypt(read!("cmsex_enveloped_hkdf.p7m"), credentials("x448"))
      assert decrypted.message.certificates == [cert("ca")]
      assert decrypted.recipient.key_encryption_algorithm == :std_dh_hkdf_sha512

      {:ok, decrypted} =
        Cmsex.decrypt(read!("cmsex_auth_enveloped_ccm.p7m"), credentials("bp384"))

      assert decrypted.content_type == @other_type
      assert byte_size(decrypted.message.mac) == 8

      {:ok, authenticated} =
        Cmsex.verify_mac(read!("cmsex_auth_data_attributes.p7m"), credentials("p384"))

      assert authenticated.message.mac_algorithm == :hmac_sha384
      assert authenticated.message.digest_algorithm == :sha512
      assert authenticated.content_type == @other_type
    end
  end

  describe "details" do
    test "a wrong KEK or password gives the one error of decryption" do
      for {message, credentials, _cipher, _recipient} <- @enveloped,
          credentials in [:kek, :password] do
        der = read!(message <> ".p7m")

        wrong =
          if credentials == :kek,
            do: [kek: {kek_id(), :binary.copy(<<0x5A>>, kek_size(message))}],
            else: [password: "not " <> password()]

        assert {:error, %Error{reason: :decryption_failed, detail: nil}} =
                 Cmsex.decrypt(der, wrong),
               message
      end
    end

    test "a recipient the message is not for is not found" do
      for {message, credentials} <- [
            {"o3_rsa_v15", "rsa3072"},
            {"o3_p256", "p384"},
            {"py_aes128", "rsa3072"}
          ] do
        assert {:error, %Error{reason: :recipient_not_found}} =
                 Cmsex.decrypt(read!(message <> ".p7m"), credentials(credentials))
      end

      assert {:error, %Error{reason: :recipient_not_found}} =
               Cmsex.decrypt(read!("o3_kek128.p7m"), kek: {"other", secret(16)})
    end

    test "indefinite lengths come in the streamed messages" do
      for message <- ~w(o3_rsa_stream o3_rsa_stream_gcm o3_digest_stream lre_rsa_stream) do
        assert <<0x30, 0x80, _::binary>> = read!(message <> ".p7m")
      end
    end

    test "PBKDF2 of OpenSSL has HMAC-SHA1 and 2048 iterations, within the limit" do
      der = read!("o3_pwri.p7m")
      {:ok, %EnvelopedData{recipient_infos: [info]}} = Cmsex.decode(der)
      assert info.key_derivation_algorithm == :pbkdf2

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_iterations}} =
               Cmsex.decrypt(der, password: password(), max_iterations: 2047)

      assert {:ok, _decrypted} = Cmsex.decrypt(der, password: password(), max_iterations: 2048)
    end

    test "the content of an AuthEnvelopedData is authenticated" do
      der = read!("o3_rsa_gcm256.p7m")
      {:ok, %EnvelopedData{encrypted_content: ciphertext}} = Cmsex.decode(der)
      [before, rest] = :binary.split(der, ciphertext)
      <<first, others::binary>> = ciphertext
      changed = before <> <<Bitwise.bxor(first, 1), others::binary>> <> rest

      assert {:error, %Error{reason: :decryption_failed}} =
               Cmsex.decrypt(changed, credentials("rsa2048"))
    end

    test "a message of OpenSSL encrypted again by Cmsex for the same recipients" do
      {:ok, decrypted} = decrypt("o3_mixed", "p384")

      recipients = [
        cert("rsa2048"),
        cert("p256"),
        cert("bp384"),
        Cmsex.Recipient.kek(secret(16), kek_id()),
        Cmsex.Recipient.password(password(), iterations: 2048)
      ]

      der = Cmsex.encrypt!(decrypted.content, recipients)

      for credentials <- ["rsa2048", "p256", "bp384", :password] do
        assert {:ok, %Decrypted{content: content}} =
                 Cmsex.decrypt(der, options(nil, credentials))

        assert content == content()
      end

      assert {:ok, %Decrypted{}} = Cmsex.decrypt(der, kek: {kek_id(), secret(16)})
    end
  end

  defp recipient(%RecipientInfo{type: :key_agreement} = info),
    do: {info.key_encryption_algorithm, info.key_wrap_algorithm}

  defp recipient(%RecipientInfo{key_encryption_algorithm: algorithm}), do: algorithm
end
