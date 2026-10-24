defmodule Cmsex.GeneratedTest do
  use ExUnit.Case, async: true

  # The messages of test/fixtures/generated, written by OpenSSL 3, LibreSSL,
  # GnuTLS, Python cryptography and jarsigner with the keys of the material
  # (see gen_fixtures.sh and INFO.txt there).

  import Cmsex.TestFixtures

  alias Cmsex.{Error, Signer}

  # {message, [{signer, digest, signature algorithm}] in the order of the
  # message, options}. Options: `detached` (the content is content.txt, or
  # the .sf file of the same name), `attributes` (true), `ski` (false),
  # `deviations` ([]).
  @valid [
    {"o3_rsa", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"o3_rsa_detached", [{"rsa2048", :sha256, :rsa_encryption}], detached: true},
    {"o3_rsa_noattr", [{"rsa2048", :sha256, :rsa_encryption}], attributes: false},
    {"o3_rsa_nosmimecap", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"o3_rsa_keyid", [{"rsa2048", :sha256, :rsa_encryption}], ski: true},
    {"o3_rsa_sha384", [{"rsa2048", :sha384, :rsa_encryption}], []},
    {"o3_rsa_chain", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"o3_rsa3072_sha512", [{"rsa3072", :sha512, :rsa_encryption}], []},
    {"o3_pss", [{"rsa2048", :sha256, :rsassa_pss}], []},
    {"o3_pss_sha384_saltmax", [{"rsa2048", :sha384, :rsassa_pss}], []},
    {"o3_rsapss_key", [{"rsapss", :sha256, :rsassa_pss}], []},
    {"o3_p256", [{"p256", :sha256, :ecdsa_with_sha256}], []},
    {"o3_p384", [{"p384", :sha384, :ecdsa_with_sha384}], []},
    {"o3_p521", [{"p521", :sha512, :ecdsa_with_sha512}], []},
    {"o3_ed25519", [{"ed25519", :sha512, :ed25519}], []},
    {"o3_ed25519_sha256", [{"ed25519", :sha256, :ed25519}], deviations: [:ed25519_digest]},
    {"o3_noski", [{"noski", :sha256, :ecdsa_with_sha256}], []},
    {"o3_serial20", [{"serial20", :sha256, :ecdsa_with_sha256}], []},
    {"o3_utf8", [{"utf8", :sha256, :ecdsa_with_sha256}], []},
    {"o3_printable", [{"printable", :sha256, :ecdsa_with_sha256}], []},
    {"o3_stream", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"o3_pkcs7", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"o3_two_signers",
     [{"p256", :sha256, :ecdsa_with_sha256}, {"rsa2048", :sha256, :rsa_encryption}], []},
    {"o3_resign", [{"p256", :sha256, :ecdsa_with_sha256}, {"rsa2048", :sha256, :rsa_encryption}],
     []},
    {"lre_rsa", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"lre_rsa_detached", [{"rsa2048", :sha256, :rsa_encryption}], detached: true},
    {"lre_rsa_noattr", [{"rsa2048", :sha256, :rsa_encryption}], attributes: false},
    {"lre_rsa_keyid", [{"rsa2048", :sha256, :rsa_encryption}], ski: true},
    {"lre_rsa_sha512", [{"rsa2048", :sha512, :rsa_encryption}], []},
    {"lre_p256_sha256", [{"p256", :sha256, :ecdsa_with_sha256}], []},
    {"lre_stream", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"lre_pkcs7", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"gt_rsa", [{"rsa2048", :sha256, :rsa_encryption}], attributes: false},
    {"gt_rsa_detached", [{"rsa2048", :sha256, :rsa_encryption}],
     detached: true, attributes: false},
    {"gt_rsa_time", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"gt_rsa_sha384", [{"rsa2048", :sha384, :rsa_encryption}], []},
    {"gt_rsapss_key", [{"rsapss", :sha256, :rsassa_pss}], []},
    {"gt_p256", [{"p256", :sha256, :ecdsa_with_sha256}], attributes: false},
    {"gt_p384_time", [{"p384", :sha384, :ecdsa_with_sha384}], []},
    {"gt_ed25519", [{"ed25519", :sha512, :ed25519}], attributes: false},
    {"gt_ed25519_time", [{"ed25519", :sha512, :ed25519}], []},
    {"gt_ed448", [{"ed448", :shake256, :ed448}], attributes: false},
    {"py_rsa", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"py_rsa_nocap", [{"rsa2048", :sha256, :rsa_encryption}], []},
    {"py_rsa_noattr", [{"rsa2048", :sha256, :rsa_encryption}], attributes: false},
    {"py_rsa_detached", [{"rsa2048", :sha256, :rsa_encryption}], detached: true},
    {"py_pss", [{"rsa2048", :sha256, :rsassa_pss}], []},
    {"py_p256", [{"p256", :sha256, :ecdsa_with_sha256}], []},
    {"py_p384", [{"p384", :sha384, :ecdsa_with_sha384}], []},
    {"py_two_signers",
     [{"p256", :sha512, :ecdsa_with_sha512}, {"rsa2048", :sha256, :rsa_encryption}], []},
    {"java_rsa", [{"rsa2048", :sha384, :sha384_with_rsa_encryption}], detached: true},
    {"java_pss", [{"rsa2048", :sha384, :rsassa_pss}], detached: true},
    {"java_ec", [{"p256", :sha384, :ecdsa_with_sha384}], detached: true},
    {"java_ed25519", [{"ed25519", :sha512, :ed25519}], detached: true},
    {"java_ed448", [{"ed448", :shake256_len, :ed448}], detached: true}
  ]

  # {message, reason, options that make it verify, or nil}
  @invalid [
    {"o3_rsa_sha1", :weak_algorithm, allow_sha1: true},
    {"lre_p256", :weak_algorithm, allow_sha1: true},
    {"o3_rsa1024", :weak_key, min_rsa_bits: 1024},
    {"o3_rsa_nocerts", :signer_not_found, certificates: ["rsa2048"]},
    {"py_rsa_nocerts", :signer_not_found, certificates: ["rsa2048"]},
    # Out of RFC 8419: Ed448 takes SHAKE256 with a length of 512 bits.
    {"o3_ed448_sha512", :algorithm_mismatch, nil},
    {"o3_ed448_shake256", :algorithm_mismatch, nil},
    # An RSASSA-PSS key named rsaEncryption (RFC 4055, 1.2).
    {"o3_rsapss_key_pkcs1", :key_mismatch, nil}
  ]

  @certs_only ["o3_certs_only", "o3_certs_crl"]

  test "every generated message is here" do
    listed =
      Enum.map(@valid, &elem(&1, 0)) ++ Enum.map(@invalid, &elem(&1, 0)) ++ @certs_only

    files = Enum.map(messages(), &Path.rootname/1)
    assert Enum.sort(listed) == Enum.sort(files)
  end

  describe "messages of other tools" do
    for {name, signers, opts} <- @valid do
      @name name
      @signers signers
      @opts opts

      test name do
        check_valid(@name, @signers, @opts)
      end
    end

    for {name, reason, fix} <- @invalid do
      @name name
      @reason reason
      @fix fix

      test name do
        check_invalid(@name, @reason, @fix)
      end
    end
  end

  defp check_valid(name, signers, opts) do
    detached = Keyword.get(opts, :detached, false)
    attributes = Keyword.get(opts, :attributes, true)
    deviations = Keyword.get(opts, :deviations, [])
    der = message(name)
    content = detached_content(name)

    verify_opts = [trust: roots()] ++ if(detached, do: [content: content], else: [])
    assert {:ok, verified} = Cmsex.verify(der, verify_opts)

    assert verified.content == if(detached, do: nil, else: content)
    assert verified.content_type == :data
    assert length(verified.signers) == length(signers)

    for {signer, {cert_name, digest, signature}} <- Enum.zip(verified.signers, signers) do
      assert signer.certificate == cert(cert_name)
      assert List.last(signer.path) == cert(cert_name)
      assert hd(signer.path) in roots()
      assert signer.signer_info.digest_algorithm == digest
      assert signer.signer_info.signature_algorithm == signature
      assert signer.deviations == deviations
      assert signer.signing_time != nil == attributes
      assert signer.signer_info.signed_attributes != nil == attributes

      sid = if opts[:ski], do: :subject_key_identifier, else: :issuer_and_serial
      assert elem(signer.signer_info.sid, 0) == sid
    end

    if detached do
      assert {:error, %Error{reason: :content_required}} = Cmsex.verify(der, trust: roots())
    end
  end

  defp check_invalid(name, reason, fix) do
    der = message(name)
    assert {:error, %Error{reason: ^reason, signer: 0}} = Cmsex.verify(der, trust: roots())

    if fix do
      fix = Enum.map(fix, &certificates/1)
      assert {:ok, %{signers: [_]}} = Cmsex.verify(der, [trust: roots()] ++ fix)
    end
  end

  defp certificates({:certificates, names}), do: {:certificates, Enum.map(names, &cert/1)}
  defp certificates(option), do: option

  defp message(name) do
    case File.read(path(name <> ".p7s")) do
      {:ok, der} -> der
      {:error, :enoent} -> read!(name <> ".p7c")
    end
  end

  # A JAR signature covers its .sf file; the others, content.txt.
  defp detached_content(name) do
    case File.read(path(name <> ".sf")) do
      {:ok, sf} -> sf
      {:error, :enoent} -> content()
    end
  end

  describe "details" do
    test "a detached message verifies with its content as a stream or a digest" do
      # Without signed attributes, a changed content breaks the signature;
      # with them, the message digest.
      for {name, reason} <- [
            {"o3_rsa_detached", :digest_mismatch},
            {"py_rsa_detached", :digest_mismatch},
            {"gt_rsa_detached", :invalid_signature}
          ] do
        der = message(name)

        chunks =
          content()
          |> :binary.bin_to_list()
          |> Enum.chunk_every(7)
          |> Enum.map(&:binary.list_to_bin/1)

        assert {:ok, _} = Cmsex.verify(der, trust: roots(), content: {:stream, chunks})

        digest = :crypto.hash(:sha256, content())
        assert {:ok, _} = Cmsex.verify(der, trust: roots(), content: {:digest, :sha256, digest})

        assert {:error, %Error{reason: ^reason}} =
                 Cmsex.verify(der, trust: roots(), content: content() <> "x")
      end
    end

    test "the signatures of a JAR also carry CMSAlgorithmProtection" do
      for name <- ~w(java_rsa java_pss java_ec java_ed25519 java_ed448) do
        {:ok, sd} = Cmsex.decode(message(name))
        [signer_info] = sd.signer_infos
        assert :cms_algorithm_protection in Enum.map(signer_info.signed_attributes, & &1.type)
      end
    end

    test "the signing times are those of the generation" do
      {:ok, verified} = Cmsex.verify(message("o3_rsa"), trust: roots())
      [%{signing_time: time}] = verified.signers
      assert time.year >= 2026 and DateTime.compare(time, DateTime.utc_now()) == :lt
    end

    test "a serial of 20 bytes with the high bit set" do
      {:ok, sd} = Cmsex.decode(message("o3_serial20"))
      [%{sid: {:issuer_and_serial, _issuer, serial}}] = sd.signer_infos
      assert serial == 0xF1E2D3C4B5A6978869504132231405F6E7D8C9BA
    end

    test "indefinite lengths come in the streamed messages" do
      for name <- ["o3_stream", "lre_stream"] do
        assert <<0x30, 0x80, _::binary>> = message(name)
      end
    end

    test "Ed25519 with SHA-256 is refused under ed25519_digest: :strict" do
      assert {:error, %Error{reason: :algorithm_mismatch}} =
               Cmsex.verify(message("o3_ed25519_sha256"),
                 trust: roots(),
                 ed25519_digest: :strict
               )
    end

    test "a certificate of another CA is not trusted" do
      assert {:error, %Error{reason: :untrusted}} =
               Cmsex.verify(message("o3_utf8"), trust: [cert("ca")])
    end

    test "certs-only messages" do
      assert {:ok, certificates} = Cmsex.certificates(message("o3_certs_only"))
      assert Enum.sort(certificates) == Enum.sort([cert("rsa2048"), cert("ca")])

      assert {:ok, sd} = Cmsex.decode(message("o3_certs_crl"))
      assert sd.certificates == [cert("ca")]
      assert sd.crls == [read!("ca.crl")]
      assert sd.signer_infos == []

      for name <- @certs_only do
        assert {:error, %Error{reason: :no_signers}} = Cmsex.verify(message(name))
      end
    end
  end

  describe "signing with the keys of OpenSSL" do
    @keys ~w(rsa2048 rsa3072 rsapss p256 p384 p521 ed25519 ed448 serial20 utf8 printable)

    test "each key signs, with and without signed attributes" do
      for name <- @keys, no_attributes <- [false, true] do
        signer = %Signer{certificate: cert(name), key: key(name)}
        der = Cmsex.sign!(content(), signer, no_attributes: no_attributes)

        assert {:ok, %{signers: [%{certificate: certificate}]}} =
                 Cmsex.verify(der, trust: roots())

        assert certificate == cert(name)
      end
    end

    test "a subject key identifier needs the extension" do
      signer = %Signer{certificate: cert("noski"), key: key("noski")}

      assert {:error, %Error{reason: :invalid_certificate, detail: :subject_key_identifier}} =
               Cmsex.sign(content(), signer, identifier: :subject_key_identifier)

      assert {:ok, _} = Cmsex.sign(content(), signer)
    end

    test "an RSA key of 1024 bits is weak" do
      signer = %Signer{certificate: cert("rsa1024"), key: key("rsa1024")}
      assert {:error, %Error{reason: :weak_key}} = Cmsex.sign(content(), signer)
    end
  end
end
