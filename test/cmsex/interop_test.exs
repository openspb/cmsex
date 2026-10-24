defmodule Cmsex.InteropTest do
  # Other implementations verify what Cmsex.sign/3 writes, and sign what
  # Cmsex.verify/2 checks, with the keys and certificates of
  # test/fixtures/generated. The tools are those found on this system; see
  # test/support/interop.ex.
  use ExUnit.Case, async: true

  import Cmsex.TestFixtures

  alias Cmsex.{Interop, Signer, TestJar}

  @moduletag :interop
  @moduletag :tmp_dir
  @moduletag timeout: 300_000

  # {name, key of the material, signer options}
  @algorithms [
    {"RSA", "rsa2048", []},
    {"RSA with SHA-512", "rsa3072", digest: :sha512},
    {"RSASSA-PSS", "rsa2048", rsa_padding: :pss},
    {"RSASSA-PSS key", "rsapss", []},
    {"P-256", "p256", []},
    {"P-384", "p384", digest: :sha384},
    {"P-521", "p521", digest: :sha512},
    {"Ed25519", "ed25519", []},
    {"Ed448", "ed448", []}
  ]

  # Each algorithm in each of these. With two signers, the second is P-256,
  # or RSA when the first is P-256.
  @variants for placement <- [:attached, :detached],
                identifier <- [:issuer_and_serial, :subject_key_identifier],
                attributes <- [:protection, :plain, :none],
                signers <- [1, 2],
                do: %{
                  placement: placement,
                  identifier: identifier,
                  attributes: attributes,
                  signers: signers
                }

  ## They verify

  # What a tool is known not to verify, as {tool, key, attributes,
  # identifier}, with :all for any.
  @unsupported [
    # LibreSSL 3.3, that of macOS, has no EdDSA.
    {:libressl, "ed25519", :all, :all},
    {:libressl, "ed448", :all, :all},
    # OpenSSL verifies Ed25519 only with signed attributes, and Ed448 not at
    # all: it knows neither id-shake256-len (RFC 8419) nor Ed448 over the
    # content itself. OpenSSL 3.0 has no Ed25519 in CMS: see
    # Interop.openssl_ed25519?/1.
    {:openssl, "ed25519", :none, :all},
    {:openssl, "ed448", :all, :all},
    # GnuTLS verifies Ed448 only without signed attributes.
    {:certtool, "ed448", :protection, :all},
    {:certtool, "ed448", :plain, :all},
    # jarsigner reads only signers identified by issuer and serial number.
    {:jarsigner, :all, :all, :subject_key_identifier}
  ]

  for tool <- [:openssl, :libressl, :certtool, :jarsigner] do
    found = Interop.find(tool)
    no_ed25519? = tool == :openssl and found != nil and not Interop.openssl_ed25519?(found)

    describe "#{tool} verifies" do
      cond do
        found ->
          for {name, key, opts} <- @algorithms do
            if {tool, key, :all, :all} in @unsupported, do: @tag(skip: "#{tool} does not take it")

            if key == "ed25519" and no_ed25519?,
              do: @tag(skip: "this OpenSSL has no Ed25519 in CMS")

            test name, %{tmp_dir: dir} do
              they_verify(
                unquote(tool),
                unquote(Macro.escape(found)),
                unquote(key),
                unquote(opts),
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

  defp they_verify(tool, {bin, version}, key, opts, dir) do
    failures =
      @variants
      |> Enum.filter(&(tool != :jarsigner or &1.placement == :detached))
      |> Enum.reject(&unsupported?(tool, key, &1))
      |> Enum.with_index()
      |> Task.async_stream(
        fn {variant, i} ->
          dir = Path.join(dir, "#{i}")
          File.mkdir_p!(dir)
          {variant, verify_with(tool, bin, key, signers(tool, key, opts, variant), variant, dir)}
        end,
        timeout: 60_000
      )
      |> Enum.flat_map(fn
        {:ok, {_variant, :ok}} -> []
        {:ok, {variant, {:error, output}}} -> [{variant, output}]
      end)

    assert failures == [], "#{tool} (#{version}) refused:\n#{inspect(failures, pretty: true)}"
  end

  # jarsigner builds the path only from the certificates of the message.
  defp signers(tool, key, opts, variant) do
    second = if key == "p256", do: "rsa2048", else: "p256"
    names = Enum.take([key, second], variant.signers)
    chain = if tool == :jarsigner, do: [cert("ca")], else: []

    for name <- names do
      extra = if name == key, do: opts, else: []

      struct!(
        Signer,
        [certificate: cert(name), key: key(name), identifier: variant.identifier, chain: chain] ++
          extra
      )
    end
  end

  defp sign_options(variant) do
    [
      detached: variant.placement == :detached,
      no_attributes: variant.attributes == :none,
      algorithm_protection: variant.attributes == :protection
    ]
  end

  defp verify_with(:jarsigner, bin, key, signers, variant, dir) do
    extension = block_extension(key)

    jar =
      TestJar.signed([{"content.txt", content()}], fn signature_file ->
        {extension, Cmsex.sign!(signature_file, signers, sign_options(variant))}
      end)

    file = Path.join(dir, "signed.jar")
    File.write!(file, jar)

    args = ["-verify", "-strict", "-keystore", path("truststore.p12"), "-storepass", "keystore"]

    case Interop.run(bin, args ++ [file]) do
      {output, 0} -> if output =~ "jar verified.", do: :ok, else: {:error, output}
      {output, _} -> {:error, output}
    end
  end

  defp verify_with(tool, bin, _key, signers, variant, dir) do
    message = write_message(signers, variant, dir)
    tool_verifies(tool, bin, message, variant.placement == :detached, dir)
  end

  # Whether OpenSSL, LibreSSL or GnuTLS verifies a message in a file, with
  # content.txt as the content when it is detached.
  defp tool_verifies(:certtool, bin, message, detached?, _dir) do
    args = [
      "--p7-verify",
      "--inder",
      "--infile",
      message,
      "--load-ca-certificate",
      path("ca.crt")
    ]

    args = if detached?, do: args ++ ["--load-data", path("content.txt")], else: args

    case Interop.run(bin, args) do
      {_output, 0} -> :ok
      {output, _} -> {:error, output}
    end
  end

  defp tool_verifies(_openssl, bin, message, detached?, dir) do
    out = Path.join(dir, "content.out")

    args =
      ~w(cms -verify -binary -inform DER -in) ++ [message, "-CAfile", path("ca.crt"), "-out", out]

    args = if detached?, do: args ++ ["-content", path("content.txt")], else: args

    case Interop.run(bin, args) do
      {output, 0} -> if File.read!(out) == content(), do: :ok, else: {:error, output}
      {output, _} -> {:error, output}
    end
  end

  defp write_message(signers, variant, dir) do
    message = Path.join(dir, "message.p7s")
    File.write!(message, Cmsex.sign!(content(), signers, sign_options(variant)))
    message
  end

  # The block file of a JAR is named after the key of the signer.
  defp block_extension("rsa" <> _), do: "RSA"
  defp block_extension(_key), do: "EC"

  defp unsupported?(tool, key, variant) do
    Enum.any?(@unsupported, fn {t, k, attributes, identifier} ->
      t == tool and k in [key, :all] and attributes in [variant.attributes, :all] and
        identifier in [variant.identifier, :all]
    end)
  end

  ## They verify messages that Cmsex changed

  @token Cmsex.Attribute.new(:time_stamp_token, [<<0x30, 3, 0x02, 1, 7>>])

  defp changed_messages do
    signer = fn name, extra ->
      struct!(Signer, [certificate: cert(name), key: key(name)] ++ extra)
    end

    ours = Cmsex.sign!(content(), signer.("rsa2048", []))

    [
      {"a signer added to a message of OpenSSL",
       Cmsex.add_signer!(read!("o3_rsa.p7s"), signer.("p256", [])), false},
      {"a signer added to a detached message of OpenSSL",
       Cmsex.add_signer!(read!("o3_rsa_detached.p7s"), signer.("p384", digest: :sha384),
         content: content()
       ), true},
      {"a signer by key identifier added to a message of GnuTLS",
       Cmsex.add_signer!(
         read!("gt_rsa.p7s"),
         signer.("rsa3072", identifier: :subject_key_identifier)
       ), false},
      {"a countersignature", Cmsex.countersign!(ours, 0, signer.("p256", [])), false},
      {"a countersignature of a countersignature",
       ours
       |> Cmsex.countersign!(0, signer.("p256", []))
       |> Cmsex.countersign!([0, 0], signer.("rsa2048", [])), false},
      {"a countersignature of a message of OpenSSL",
       Cmsex.countersign!(read!("o3_p256.p7s"), 0, signer.("rsa2048", [])), false},
      {"an unsigned attribute added to a message of OpenSSL",
       Cmsex.add_unsigned_attribute!(read!("o3_two_signers.p7s"), 1, @token), false}
    ]
  end

  for tool <- [:openssl, :libressl, :certtool] do
    found = Interop.find(tool)

    describe "#{tool} verifies messages changed by Cmsex" do
      cond do
        found ->
          test "added signers, countersignatures, unsigned attributes", %{tmp_dir: dir} do
            {bin, version} = unquote(Macro.escape(found))

            failures =
              for {{name, der, detached?}, i} <- Enum.with_index(changed_messages()),
                  file = Path.join(dir, "changed_#{i}.p7s"),
                  File.write!(file, der) == :ok,
                  {:error, output} <- [tool_verifies(unquote(tool), bin, file, detached?, dir)],
                  do: {name, output}

            assert failures == [],
                   "#{unquote(tool)} (#{version}) refused:\n#{inspect(failures, pretty: true)}"
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

  ## They sign

  # A Python script that signs with cryptography: certificate, key,
  # content, hash, padding ("pkcs1", "pss" or "-"), flags ("detached",
  # "noattr"), output.
  @python_sign """
  import sys
  from cryptography import x509
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import padding
  from cryptography.hazmat.primitives.serialization import pkcs7

  cert_file, key_file, content_file, hash_name, padding_name, flags, out = sys.argv[1:]
  cert = x509.load_pem_x509_certificate(open(cert_file, "rb").read())
  key = serialization.load_pem_private_key(open(key_file, "rb").read(), None)
  hash_algorithm = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}[hash_name]()
  rsa_padding = None
  if padding_name == "pss":
      rsa_padding = padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.DIGEST_LENGTH)
  options = [pkcs7.PKCS7Options.Binary]
  if "detached" in flags:
      options.append(pkcs7.PKCS7Options.DetachedSignature)
  if "noattr" in flags:
      options.append(pkcs7.PKCS7Options.NoAttributes)
  builder = pkcs7.PKCS7SignatureBuilder().set_data(open(content_file, "rb").read())
  builder = builder.add_signer(cert, key, hash_algorithm, rsa_padding=rsa_padding)
  open(out, "wb").write(builder.sign(serialization.Encoding.DER, options))
  """

  # {name, key of the material, options of the tool}, each signed with and
  # without the content inside, with and without signed attributes, and,
  # where the tool has it, with a subject key identifier.
  @openssl_signs [
    {"RSA", "rsa2048", []},
    {"RSASSA-PSS", "rsa2048", ~w(-keyopt rsa_padding_mode:pss)},
    {"RSASSA-PSS key", "rsapss", ~w(-keyopt rsa_padding_mode:pss)},
    {"P-256", "p256", []},
    {"P-384", "p384", ~w(-md sha384)},
    {"P-521", "p521", ~w(-md sha512)},
    {"Ed25519", "ed25519", ~w(-md sha512)}
  ]

  @libressl_signs [
    {"RSA", "rsa2048", []},
    {"RSA with SHA-512", "rsa2048", ~w(-md sha512)},
    {"P-256", "p256", ~w(-md sha256)}
  ]

  @certtool_signs [
    {"RSA", "rsa2048", []},
    {"RSA with SHA-384", "rsa2048", ~w(--hash SHA384)},
    {"RSASSA-PSS key", "rsapss", []},
    {"P-256", "p256", []},
    {"P-384", "p384", ~w(--hash SHA384)},
    {"Ed25519", "ed25519", []},
    {"Ed448", "ed448", []}
  ]

  @python_signs [
    {"RSA", "rsa2048", "sha256 pkcs1"},
    {"RSASSA-PSS", "rsa2048", "sha256 pss"},
    {"RSA with SHA-512", "rsa2048", "sha512 pkcs1"},
    {"P-256", "p256", "sha256 -"},
    {"P-384", "p384", "sha384 -"},
    {"P-521", "p521", "sha512 -"}
  ]

  @jarsigner_signs [
    {"RSA", "rsa2048", []},
    {"RSASSA-PSS", "rsa2048", ~w(-sigalg RSASSA-PSS)},
    {"P-256", "p256", []},
    {"Ed25519", "ed25519", []},
    {"Ed448", "ed448", []}
  ]

  for {tool, cases} <- [
        openssl: @openssl_signs,
        libressl: @libressl_signs,
        certtool: @certtool_signs,
        python: @python_signs,
        jarsigner: @jarsigner_signs
      ] do
    found = Interop.find(tool)
    no_ed25519? = tool == :openssl and found != nil and not Interop.openssl_ed25519?(found)

    describe "#{tool} signs" do
      cond do
        found ->
          for {name, key, opts} <- cases do
            if key == "ed25519" and no_ed25519?,
              do: @tag(skip: "this OpenSSL has no Ed25519 in CMS")

            test name, %{tmp_dir: dir} do
              they_sign(
                unquote(tool),
                unquote(Macro.escape(found)),
                unquote(key),
                unquote(opts),
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

  defp they_sign(tool, {bin, version}, key, opts, dir) do
    failures =
      for(
        detached <- [false, true],
        attributes <- [true, false],
        ski <- [false, true],
        do: %{detached: detached, attributes: attributes, ski: ski}
      )
      |> Enum.reject(&cannot_sign?(tool, key, &1))
      |> Enum.with_index()
      |> Task.async_stream(
        fn {variant, i} ->
          dir = Path.join(dir, "#{i}")
          File.mkdir_p!(dir)
          {variant, signed_by(tool, bin, key, opts, variant, dir)}
        end,
        timeout: 60_000
      )
      |> Enum.flat_map(fn
        {:ok, {_variant, :ok}} -> []
        {:ok, {variant, error}} -> [{variant, error}]
      end)

    assert failures == [],
           "messages of #{tool} (#{version}) refused:\n#{inspect(failures, pretty: true)}"
  end

  # Which variants a tool signs: the subject key identifier only with
  # OpenSSL and LibreSSL, and a JAR is always detached and with attributes.
  # OpenSSL signs Ed25519 only with signed attributes, and GnuTLS Ed448
  # only without them.
  defp cannot_sign?(tool, _key, %{ski: true}) when tool not in [:openssl, :libressl], do: true
  defp cannot_sign?(:jarsigner, _key, variant), do: not variant.detached or not variant.attributes
  defp cannot_sign?(:openssl, "ed25519", variant), do: not variant.attributes
  defp cannot_sign?(:certtool, "ed448", variant), do: variant.attributes
  defp cannot_sign?(_tool, _key, _variant), do: false

  defp signed_by(:jarsigner, bin, key, opts, _variant, dir) do
    unsigned = Path.join(dir, "unsigned.jar")
    signed = Path.join(dir, "signed.jar")
    File.write!(unsigned, TestJar.unsigned([{"content.txt", content()}]))

    args =
      ["-keystore", path("keystore_#{key}.p12"), "-storetype", "PKCS12", "-storepass", "keystore"] ++
        ["-signedjar", signed] ++ opts ++ [unsigned, "signer"]

    with {:ok, _output} <- ok(Interop.run(bin, args)) do
      entries = TestJar.entries(File.read!(signed))
      block = Map.fetch!(entries, "META-INF/SIGNER." <> block_extension(key))
      check_ours(block, entries["META-INF/SIGNER.SF"], key)
    end
  end

  defp signed_by(:python, bin, key, opts, variant, dir) do
    out = Path.join(dir, "message.p7s")
    [hash, padding] = String.split(opts)

    flags =
      [variant.detached && "detached", not variant.attributes && "noattr"]
      |> Enum.filter(&is_binary/1)
      |> Enum.join(",")

    args = [
      path("#{key}.crt"),
      path("#{key}.key"),
      path("content.txt"),
      hash,
      padding,
      flags,
      out
    ]

    with {:ok, _output} <- ok(Interop.python(bin, @python_sign, args)) do
      check_ours(File.read!(out), if(variant.detached, do: content()), key)
    end
  end

  defp signed_by(:certtool, bin, key, opts, variant, dir) do
    out = Path.join(dir, "message.p7s")
    command = if variant.detached, do: "--p7-detached-sign", else: "--p7-sign"

    args =
      [command, "--load-privkey", path("#{key}.key"), "--load-certificate", path("#{key}.crt")] ++
        ["--infile", path("content.txt"), "--outder", "--outfile", out] ++
        if(variant.attributes, do: ["--p7-time"], else: []) ++ opts

    with {:ok, _output} <- ok(Interop.run(bin, args)) do
      check_ours(File.read!(out), if(variant.detached, do: content()), key)
    end
  end

  defp signed_by(_openssl, bin, key, opts, variant, dir) do
    out = Path.join(dir, "message.p7s")

    args =
      ~w(cms -sign -binary -in) ++
        [path("content.txt"), "-signer", path("#{key}.crt"), "-inkey", path("#{key}.key")] ++
        ["-outform", "DER", "-out", out] ++
        if(variant.detached, do: [], else: ["-nodetach"]) ++
        if(variant.attributes, do: [], else: ["-noattr"]) ++
        if(variant.ski, do: ["-keyid"], else: []) ++ opts

    with {:ok, _output} <- ok(Interop.run(bin, args)) do
      check_ours(File.read!(out), if(variant.detached, do: content()), key)
    end
  end

  defp ok({output, 0}), do: {:ok, output}
  defp ok({output, status}), do: {:error, {:tool_failed, status, output}}

  # The message verifies here, with the content, and was signed by `key`.
  defp check_ours(der, detached_content, key) do
    opts = [trust: roots()] ++ if(detached_content, do: [content: detached_content], else: [])

    case Cmsex.verify(der, opts) do
      {:ok, %{signers: [%{certificate: certificate}], content: inside}} ->
        cond do
          certificate != cert(key) -> {:error, :other_signer}
          detached_content == nil and inside != content() -> {:error, :other_content}
          true -> :ok
        end

      other ->
        {:error, other}
    end
  end

  ## Python reads the certificates

  python = Interop.find(:python)

  describe "python reads" do
    if python do
      @python python

      @python_reads """
      import sys
      from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
      for certificate in pkcs7.load_der_pkcs7_certificates(open(sys.argv[1], "rb").read()):
          print(certificate.public_bytes(Encoding.DER).hex())
      """

      test "the certificates of signed and certs-only messages", %{tmp_dir: dir} do
        {bin, _version} = @python
        signer = %Signer{certificate: cert("rsa2048"), key: key("rsa2048"), chain: [cert("ca")]}

        bundle = [cert("rsa2048"), cert("ca"), cert("p256")]

        messages = [
          {"signed", Cmsex.sign!(content(), signer), [cert("rsa2048"), cert("ca")]},
          {"detached", Cmsex.sign!(content(), signer, detached: true),
           [cert("rsa2048"), cert("ca")]},
          {"certs_only", Cmsex.certs_only!(bundle), bundle}
        ]

        for {name, der, certificates} <- messages do
          file = Path.join(dir, name <> ".p7s")
          File.write!(file, der)
          assert {output, 0} = Interop.python(bin, @python_reads, [file])

          read = output |> String.split() |> Enum.map(&Base.decode16!(&1, case: :lower))
          assert Enum.sort(read) == Enum.sort(certificates)
        end
      end
    else
      @tag skip: "python was not found"
      test "is found", do: :ok
    end
  end
end
