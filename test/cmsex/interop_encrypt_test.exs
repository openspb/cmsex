defmodule Cmsex.InteropEncryptTest do
  # Other implementations decrypt what Cmsex.encrypt/3,
  # Cmsex.encrypt_with_key/3 and Cmsex.digest/2 write, and encrypt what
  # Cmsex.decrypt/2 reads, with the recipients of test/fixtures/encrypted;
  # OpenSSL computes the same key derivations and key wraps. The tools are
  # those found on this system; see test/support/interop.ex.
  #
  # Python cryptography decrypts only PKCS #1 v1.5, which Cmsex does not
  # write (RFC 3218), so it only encrypts here. X25519 and X448 (RFC 8418)
  # are not here: OpenSSL 3 fails on them both ways, and the others do not
  # have them. No tool here has AuthenticatedData; see digest_mac_test.exs.
  use ExUnit.Case, async: true

  import Cmsex.EncryptedFixtures

  alias Cmsex.{Decrypted, DigestedData, Interop, KDF, KeyWrap, LegacyWrap, Recipient}

  @moduletag :interop
  @moduletag :tmp_dir
  @moduletag timeout: 300_000

  @kek_id_hex Base.encode16(kek_id())

  ## They decrypt

  # {name, recipient, options of Cmsex, features}. The recipient: a
  # certificate of the material with the options of Recipient.certificate/2,
  # {:kek, size, options}, {:password, options}, :all of them, or, for
  # EncryptedData and DigestedData, {:content_key, size} and :digest.
  @they_decrypt [
    {"RSA-OAEP with SHA-256", {"rsa2048", []}, [], []},
    {"RSA-OAEP with SHA-1", {"rsa2048", oaep_digest: :sha1}, [], []},
    {"RSA-OAEP with SHA-224", {"rsa2048", oaep_digest: :sha224}, [], []},
    {"RSA-OAEP with SHA-384", {"rsa2048", oaep_digest: :sha384}, [], []},
    {"RSA-OAEP with SHA-512", {"rsa2048", oaep_digest: :sha512}, [], []},
    {"RSA-OAEP, by subject key identifier", {"rsa2048", identifier: :subject_key_identifier}, [],
     []},
    {"RSA-OAEP, AES-128-CBC", {"rsa2048", []}, [cipher: :aes128_cbc], []},
    {"RSA-OAEP, AES-192-CBC", {"rsa2048", []}, [cipher: :aes192_cbc], []},
    {"RSA-OAEP, AES-128-GCM", {"rsa2048", []}, [cipher: :aes128_gcm], [:aead]},
    {"RSA-OAEP, AES-256-GCM", {"rsa2048", []}, [cipher: :aes256_gcm], [:aead]},
    {"RSA-OAEP, AES-256-GCM with a tag of 12 bytes", {"rsa2048", []},
     [cipher: :aes256_gcm, tag_size: 12], [:aead, :gcm_default_tag]},
    {"RSA-OAEP, AES-128-CCM", {"rsa2048", []}, [cipher: :aes128_ccm], [:aead, :ccm]},
    {"RSA-OAEP, ChaCha20-Poly1305", {"rsa2048", []}, [cipher: :chacha20_poly1305],
     [:aead, :chacha20_poly1305]},
    {"RSA-OAEP, another content type", {"rsa2048", []}, [content_type: {1, 2, 3, 4}], []},
    {"RSA-OAEP, unprotected attributes", {"rsa2048", []},
     [unprotected_attributes: [%Cmsex.Attribute{type: {1, 2, 3, 4}, values: [<<5, 0>>]}]], []},
    {"RSA-OAEP, with OriginatorInfo", {"rsa2048", []}, [certificates: ["ca", "rsa3072"]], []},
    {"P-256", {"p256", []}, [], [:ecdh]},
    {"P-256, X9.63 with SHA-512", {"p256", key_agreement: :std_dh_sha512kdf}, [], [:ecdh]},
    {"P-256, HKDF with SHA-256", {"p256", key_agreement: :std_dh_hkdf_sha256}, [],
     [:ecdh, :hkdf]},
    {"P-256, with user keying material", {"p256", ukm: "cmsex ukm 0123456789"}, [], [:ecdh]},
    {"P-256, AES-128 key wrap", {"p256", key_wrap: :aes128_wrap}, [], [:ecdh]},
    {"P-256, AES-256 key wrap with padding", {"p256", key_wrap: :aes256_wrap_pad}, [], [:ecdh]},
    {"P-256, by subject key identifier", {"p256", identifier: :subject_key_identifier}, [],
     [:ecdh]},
    {"P-256, AES-256-GCM", {"p256", []}, [cipher: :aes256_gcm], [:ecdh, :aead]},
    {"P-384", {"p384", []}, [], [:ecdh]},
    {"P-521", {"p521", []}, [], [:ecdh]},
    {"brainpoolP256r1", {"bp256", []}, [], [:ecdh]},
    {"brainpoolP384r1", {"bp384", []}, [], [:ecdh]},
    {"KEK of 16 bytes", {:kek, 16, []}, [], []},
    {"KEK of 24 bytes", {:kek, 24, []}, [], []},
    {"KEK of 32 bytes", {:kek, 32, []}, [], []},
    {"KEK with a date", {:kek, 16, date: ~U[2026-10-24 12:00:00Z]}, [], []},
    {"KEK, AES key wrap with padding", {:kek, 16, key_wrap: :aes128_wrap_pad}, [],
     [:kek_wrap_pad]},
    {"KEK, AES-128-GCM", {:kek, 16, []}, [cipher: :aes128_gcm], [:aead]},
    {"password", {:password, iterations: 2048}, [], []},
    {"password, HMAC-SHA512 and AES-128",
     {:password, iterations: 2048, prf: :hmac_sha512, kek_cipher: :aes128_cbc}, [], []},
    {"password, AES-256-GCM", {:password, iterations: 2048}, [cipher: :aes256_gcm], [:aead]},
    {"every kind of recipient", :all, [], [:ecdh]},
    {"EncryptedData, AES-128-CBC", {:content_key, 16}, [cipher: :aes128_cbc], []},
    {"EncryptedData, AES-256-CBC", {:content_key, 32}, [], []},
    {"DigestedData, SHA-224", :digest, [digest: :sha224], []},
    {"DigestedData, SHA-256", :digest, [], []},
    {"DigestedData, SHA-384", :digest, [digest: :sha384], []},
    {"DigestedData, SHA-512", :digest, [digest: :sha512], []}
  ]

  # What a tool is known not to decrypt.
  @unsupported %{
    # OpenSSL 3 has neither the HKDF of RFC 8418, nor AES key wrap with
    # padding for a KEK (it has it for key agreement), nor CCM and
    # ChaCha20-Poly1305 in CMS. It needs the aes-ICVlen of GCMParameters,
    # which DER leaves out when it is the default of 12 (RFC 5084, 3.2).
    openssl: [:hkdf, :kek_wrap_pad, :ccm, :chacha20_poly1305, :gcm_default_tag],
    # LibreSSL 3.3, that of macOS, has no ECDH and no AuthEnvelopedData.
    libressl: [:ecdh, :aead, :hkdf, :kek_wrap_pad]
  }

  for tool <- [:openssl, :libressl] do
    found = Interop.find(tool)

    describe "#{tool} decrypts" do
      cond do
        found ->
          for {name, recipient, opts, features} <- @they_decrypt do
            if Enum.any?(features, &(&1 in @unsupported[tool])),
              do: @tag(skip: "#{tool} does not take it")

            test name, %{tmp_dir: dir} do
              they_decrypt(
                unquote(Macro.escape(found)),
                unquote(Macro.escape(recipient)),
                unquote(Macro.escape(opts)),
                dir
              )
            end
          end

        Interop.required?(tool) ->
          test "is found" do
            flunk("#{unquote(tool)} was not found; see test/support/interop.ex")
          end

        true ->
          @tag skip: "#{tool} was not found"
          test "is found", do: :ok
      end
    end
  end

  defp they_decrypt({bin, version}, recipient, opts, dir) do
    file = Path.join(dir, "message.p7m")
    File.write!(file, write(recipient, opts))

    failures =
      for credentials <- credentials_of(recipient),
          {:error, output} <- [tool_decrypts(bin, file, credentials, dir)],
          do: {credentials, output}

    assert failures == [], "#{version} refused:\n#{inspect(failures, pretty: true)}"
  end

  defp write(:digest, opts), do: Cmsex.digest!(content(), opts)

  defp write({:content_key, size}, opts),
    do: Cmsex.encrypt_with_key!(content(), secret(size), opts)

  defp write(recipient, opts) do
    opts = Keyword.update(opts, :certificates, [], fn names -> Enum.map(names, &cert/1) end)
    Cmsex.encrypt!(content(), recipients(recipient), opts)
  end

  defp recipients(:all) do
    [
      cert("rsa2048"),
      cert("p256"),
      Recipient.kek(secret(16), kek_id()),
      Recipient.password(password(), iterations: 2048)
    ]
  end

  defp recipients({:kek, size, opts}), do: Recipient.kek(secret(size), kek_id(), opts)
  defp recipients({:password, opts}), do: Recipient.password(password(), opts)
  defp recipients({name, opts}), do: Recipient.certificate(cert(name), opts)

  # The credentials a tool decrypts with: each recipient of the message.
  defp credentials_of(:all), do: ["rsa2048", "p256", {:kek, 16}, :password]
  defp credentials_of({:kek, size, _opts}), do: [{:kek, size}]
  defp credentials_of({:password, _opts}), do: [:password]
  defp credentials_of({name, _opts}) when is_binary(name), do: [name]
  defp credentials_of(other), do: [other]

  defp tool_decrypts(bin, file, credentials, dir) do
    out = Path.join(dir, "content.out")
    File.rm(out)
    args = ~w(-binary -inform DER -in) ++ [file, "-out", out] ++ decrypt_args(credentials)

    case Interop.run(bin, ["cms" | args]) do
      {output, 0} -> if File.read(out) == {:ok, content()}, do: :ok, else: {:error, output}
      {output, _} -> {:error, output}
    end
  end

  defp decrypt_args(:digest), do: ["-digest_verify"]
  defp decrypt_args(:password), do: ["-decrypt", "-pwri_password", password()]

  defp decrypt_args({:content_key, size}),
    do: ["-EncryptedData_decrypt", "-secretkey", Base.encode16(secret(size))]

  defp decrypt_args({:kek, size}),
    do: ["-decrypt", "-secretkey", Base.encode16(secret(size)), "-secretkeyid", @kek_id_hex]

  defp decrypt_args(name),
    do: ["-decrypt", "-recip", path(name <> ".crt"), "-inkey", path(name <> ".key")]

  ## They encrypt

  # {name, operation, arguments, credentials}: OpenSSL or LibreSSL writes
  # a message of content.txt with `cms operation -binary` and the
  # arguments, in the directory of the material, and Cmsex decrypts it
  # with each of the credentials.
  @k16 Base.encode16(secret(16))
  @k32 Base.encode16(secret(32))
  @kek ["-secretkey", @k16, "-secretkeyid", @kek_id_hex]
  @password ["-pwri_password", password()]
  @oaep ~w(-keyopt rsa_padding_mode:oaep)

  @openssl_encrypts [
    {"RSA PKCS #1 v1.5", "-encrypt", ~w(-aes256 rsa2048.crt), ["rsa2048"]},
    {"RSA PKCS #1 v1.5, Triple-DES", "-encrypt", ~w(-des3 rsa2048.crt), ["rsa2048"]},
    {"RSA PKCS #1 v1.5, by subject key identifier", "-encrypt", ~w(-aes128 -keyid rsa2048.crt),
     ["rsa2048"]},
    {"RSA-OAEP", "-encrypt", ~w(-aes128 -recip rsa2048.crt) ++ @oaep, ["rsa2048"]},
    {"RSA-OAEP with SHA-256", "-encrypt",
     ~w(-aes128 -recip rsa2048.crt) ++
       @oaep ++ ~w(-keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256), ["rsa2048"]},
    {"RSA-OAEP with a label", "-encrypt",
     ~w(-aes128 -recip rsa2048.crt) ++ @oaep ++ ~w(-keyopt rsa_oaep_label:636d736578),
     ["rsa2048"]},
    {"RSA, AES-256-GCM", "-encrypt", ~w(-aes-256-gcm rsa2048.crt), ["rsa2048"]},
    {"RSA, streamed", "-encrypt", ~w(-aes128 -stream rsa2048.crt), ["rsa2048"]},
    {"RSA, streamed AES-256-GCM", "-encrypt", ~w(-aes-256-gcm -stream rsa2048.crt), ["rsa2048"]},
    {"two RSA recipients", "-encrypt", ~w(-aes128 rsa2048.crt rsa3072.crt),
     ["rsa2048", "rsa3072"]},
    {"P-256", "-encrypt", ~w(-aes128 p256.crt), ["p256"]},
    {"P-256, X9.63 with SHA-256", "-encrypt",
     ~w(-aes128 -recip p256.crt -keyopt ecdh_kdf_md:sha256), ["p256"]},
    {"P-256, cofactor ECDH", "-encrypt", ~w(-aes128 -recip p256.crt -keyopt ecdh_cofactor_mode:1),
     ["p256"]},
    {"P-256, Triple-DES and its key wrap", "-encrypt", ~w(-des3 -des3-wrap p256.crt), ["p256"]},
    {"P-256, AES-256-GCM", "-encrypt", ~w(-aes-256-gcm p256.crt), ["p256"]},
    {"P-384, X9.63 with SHA-384", "-encrypt",
     ~w(-aes256 -recip p384.crt -keyopt ecdh_kdf_md:sha384), ["p384"]},
    {"P-521", "-encrypt", ~w(-aes256 p521.crt), ["p521"]},
    {"brainpoolP256r1", "-encrypt", ~w(-aes128 bp256.crt), ["bp256"]},
    {"KEK", "-encrypt", ["-aes128" | @kek], [{:kek, 16}]},
    {"KEK, AES-128-GCM", "-encrypt", ["-aes-128-gcm" | @kek], [{:kek, 16}]},
    {"password", "-encrypt", ["-aes256" | @password], [:password]},
    {"password, AES-128 key wrap", "-encrypt",
     ["-aes256" | @password] ++ ~w(-kekcipher aes-128-cbc), [:password]},
    {"password, AES-256-GCM", "-encrypt",
     ["-aes-256-gcm" | @password] ++ ~w(-kekcipher aes-256-cbc), [:password]},
    {"every kind of recipient", "-encrypt",
     ["-aes256" | @kek] ++ @password ++ ~w(rsa2048.crt p256.crt),
     ["rsa2048", "p256", {:kek, 16}, :password]},
    {"EncryptedData, AES-128-CBC", "-EncryptedData_encrypt", ["-aes128", "-secretkey", @k16],
     [{:content_key, 16}]},
    {"EncryptedData, AES-256-CBC", "-EncryptedData_encrypt", ["-aes256", "-secretkey", @k32],
     [{:content_key, 32}]},
    {"DigestedData, SHA-256", "-digest_create", ~w(-md sha256), [:digest]},
    {"DigestedData, SHA-512, streamed", "-digest_create", ~w(-md sha512 -stream), [:digest]}
  ]

  @libressl_encrypts [
    {"RSA PKCS #1 v1.5", "-encrypt", ~w(-aes128 rsa2048.crt), ["rsa2048"]},
    {"RSA PKCS #1 v1.5, Triple-DES", "-encrypt", ~w(-des3 rsa2048.crt), ["rsa2048"]},
    {"RSA-OAEP", "-encrypt", ~w(-aes256 -recip rsa2048.crt) ++ @oaep, ["rsa2048"]},
    {"RSA, streamed", "-encrypt", ~w(-aes128 -stream rsa2048.crt), ["rsa2048"]},
    {"KEK", "-encrypt", ["-aes128" | @kek], [{:kek, 16}]},
    {"password", "-encrypt", ["-aes256" | @password], [:password]},
    {"EncryptedData", "-EncryptedData_encrypt", ["-aes128", "-secretkey", @k16],
     [{:content_key, 16}]},
    {"DigestedData", "-digest_create", ~w(-md sha256), [:digest]}
  ]

  # Options that only recent versions have; a case with one is skipped by
  # a version that does not list it in `cms -help`.
  @recent_options ["-kekcipher"]

  for {tool, cases} <- [openssl: @openssl_encrypts, libressl: @libressl_encrypts] do
    found = Interop.find(tool)

    describe "#{tool} encrypts" do
      cond do
        found ->
          {help, _status} = Interop.run(elem(found, 0), ["cms", "-help"])

          for {name, operation, args, credentials} <- cases do
            missing = Enum.find(@recent_options, &(&1 in args and not (help =~ ~r/^\s*#{&1}\s/m)))
            if missing, do: @tag(skip: "#{tool} has no #{missing}")

            test name, %{tmp_dir: dir} do
              {bin, version} = unquote(Macro.escape(found))
              out = Path.join(dir, "message.p7m")

              args =
                ["cms", unquote(operation), "-binary", "-in", "content.txt", "-outform", "DER"] ++
                  ["-out", out | unquote(args)]

              assert {_output, 0} = Interop.run(bin, args, cd: path("."))
              they_wrote(File.read!(out), unquote(Macro.escape(credentials)), version)
            end
          end

        Interop.required?(tool) ->
          test "is found" do
            flunk("#{unquote(tool)} was not found; see test/support/interop.ex")
          end

        true ->
          @tag skip: "#{tool} was not found"
          test "is found", do: :ok
      end
    end
  end

  python = Interop.find(:python)

  describe "python encrypts" do
    cond do
      python ->
        # Python: a certificate or two, AES-128 or AES-256, PKCS #1 v1.5.
        @python_encrypt """
        import sys
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.ciphers import algorithms
        from cryptography.hazmat.primitives.serialization import pkcs7

        content_file, cipher, out, *certificates = sys.argv[1:]
        builder = pkcs7.PKCS7EnvelopeBuilder().set_data(open(content_file, "rb").read())
        for name in certificates:
            builder = builder.add_recipient(x509.load_pem_x509_certificate(open(name, "rb").read()))
        builder = builder.set_content_encryption_algorithm(getattr(algorithms, cipher))
        der = builder.encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        open(out, "wb").write(der)
        """

        @python_encrypts [
          {"AES-128", "AES128", ["rsa2048"]},
          {"AES-256", "AES256", ["rsa2048"]},
          {"two recipients", "AES128", ["rsa2048", "rsa3072"]}
        ]

        for {name, cipher, recipients} <- @python_encrypts do
          test name, %{tmp_dir: dir} do
            {bin, version} = unquote(Macro.escape(python))
            out = Path.join(dir, "message.p7m")
            certificates = Enum.map(unquote(recipients), &path(&1 <> ".crt"))
            args = [path("content.txt"), unquote(cipher), out | certificates]

            assert {_output, 0} = Interop.python(bin, @python_encrypt, args)
            they_wrote(File.read!(out), unquote(recipients), version)
          end
        end

      Interop.required?(:python) ->
        test "is found" do
          flunk("python was not found; see test/support/interop.ex")
        end

      true ->
        @tag skip: "python was not found"
        test "is found", do: :ok
    end
  end

  # The message decrypts here with each of the credentials.
  defp they_wrote(der, credentials, version) do
    for credentials <- credentials do
      result =
        case credentials do
          :digest -> Cmsex.verify_digest(der)
          :password -> Cmsex.decrypt(der, password: password())
          {:kek, size} -> Cmsex.decrypt(der, kek: {kek_id(), secret(size)})
          {:content_key, size} -> Cmsex.decrypt(der, content_key: secret(size))
          name -> Cmsex.decrypt(der, credentials(name))
        end

      assert {:ok, %struct{content: content}} = result,
             "with #{inspect(credentials)}, of #{version}: #{inspect(result)}"

      assert struct in [Decrypted, DigestedData]
      assert content == content()
    end
  end

  ## Key derivation and key wrap

  openssl = Interop.find(:openssl)

  describe "openssl computes the same" do
    if openssl do
      @openssl openssl

      # `openssl enc` takes the key wraps since some version of OpenSSL 3.
      @enc_wraps match?(
                   {_output, 0},
                   Interop.run(elem(openssl, 0), [
                     "enc",
                     "-id-aes128-wrap-pad",
                     "-K",
                     String.duplicate("00", 16),
                     "-in",
                     path("content.txt"),
                     "-out",
                     "/dev/null"
                   ])
                 )

      test "ANSI X9.63 KDF" do
        for hash <- [:sha1, :sha224, :sha256, :sha384, :sha512], length <- [16, 24, 32, 65] do
          secret = :crypto.strong_rand_bytes(32)
          info = :crypto.strong_rand_bytes(Enum.random(1..60))
          args = kdf_args(hash, length, hexsecret: secret, hexinfo: info) ++ ["X963KDF"]
          assert openssl_kdf(args) == KDF.x963(hash, secret, info, length)
        end
      end

      test "HKDF, with and without a salt" do
        for hash <- [:sha256, :sha384, :sha512], salt <- [<<>>, :crypto.strong_rand_bytes(16)] do
          secret = :crypto.strong_rand_bytes(32)
          info = :crypto.strong_rand_bytes(24)
          salt_opts = if salt == <<>>, do: [], else: [hexsalt: salt]
          args = kdf_args(hash, 32, [hexkey: secret, hexinfo: info] ++ salt_opts) ++ ["HKDF"]
          assert openssl_kdf(args) == KDF.hkdf(hash, salt, secret, info, 32)
        end
      end

      test "PBKDF2" do
        for hash <- [:sha1, :sha256, :sha512], iterations <- [1, 2048] do
          salt = :crypto.strong_rand_bytes(16)
          password = "pass " <> Base.encode16(:crypto.strong_rand_bytes(4))

          args =
            kdf_args(hash, 32, hexsalt: salt) ++
              ["-kdfopt", "pass:" <> password, "-kdfopt", "iter:#{iterations}", "PBKDF2"]

          assert openssl_kdf(args) == KDF.pbkdf2(hash, password, salt, iterations, 32)
        end
      end

      unless @enc_wraps, do: @tag(skip: "openssl enc has no key wrap")

      test "AES key wrap, with and without padding", %{tmp_dir: dir} do
        for size <- [16, 24, 32], key_size <- [5, 16, 24, 32, 40] do
          kek = :crypto.strong_rand_bytes(size)
          key = :crypto.strong_rand_bytes(key_size)
          bits = size * 8

          padded = openssl_enc(["-id-aes#{bits}-wrap-pad"], kek, key, dir)
          assert padded == KeyWrap.wrap_with_padding(kek, key)
          assert {:ok, ^key} = KeyWrap.unwrap_with_padding(kek, padded)

          if rem(key_size, 8) == 0 and key_size >= 16 do
            wrapped = openssl_enc(["-id-aes#{bits}-wrap"], kek, key, dir)
            assert wrapped == KeyWrap.wrap(kek, key)
            assert openssl_enc(["-d", "-id-aes#{bits}-wrap"], kek, wrapped, dir) == key
          end
        end
      end

      unless @enc_wraps, do: @tag(skip: "openssl enc has no key wrap")

      test "Triple-DES key wrap, each way", %{tmp_dir: dir} do
        if :des_ede3_cbc in :crypto.supports(:ciphers) do
          kek = :crypto.strong_rand_bytes(24)
          key = odd_parity(:crypto.strong_rand_bytes(24))

          wrapped = openssl_enc(["-des3-wrap"], kek, key, dir)
          assert LegacyWrap.des3_unwrap(kek, wrapped) == {:ok, key}

          ours = LegacyWrap.des3_wrap(kek, key, :crypto.strong_rand_bytes(8))
          assert openssl_enc(["-d", "-des3-wrap"], kek, ours, dir) == key
        end
      end
    else
      @tag skip: "openssl was not found"
      test "is found", do: :ok
    end
  end

  defp kdf_args(hash, length, hex) do
    digest = hash |> Atom.to_string() |> String.upcase()

    ["kdf", "-keylen", "#{length}", "-kdfopt", "digest:" <> digest] ++
      Enum.flat_map(hex, fn {name, value} ->
        ["-kdfopt", "#{name}:" <> Base.encode16(value)]
      end)
  end

  # `openssl kdf` prints the key in hex, with colons.
  defp openssl_kdf(args) do
    {bin, _version} = @openssl
    assert {output, 0} = Interop.run(bin, args)
    output |> String.trim() |> String.replace(":", "") |> Base.decode16!()
  end

  defp openssl_enc(cipher, kek, input, dir) do
    {bin, _version} = @openssl
    name = "#{System.unique_integer([:positive])}"
    file = Path.join(dir, name <> ".in")
    out = Path.join(dir, name <> ".out")
    File.write!(file, input)

    args = ["enc" | cipher] ++ ["-K", Base.encode16(kek), "-in", file, "-out", out]
    assert {_output, 0} = Interop.run(bin, args)
    File.read!(out)
  end

  # A Triple-DES key with odd parity, which the key wrap of RFC 3217 keeps.
  defp odd_parity(key) do
    for <<high::7, _low::1 <- key>>, into: <<>> do
      ones = for(<<(bit::1 <- <<high::7>>)>>, do: bit) |> Enum.sum()
      <<high::7, 1 - rem(ones, 2)::1>>
    end
  end
end
