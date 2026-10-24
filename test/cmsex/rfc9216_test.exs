defmodule Cmsex.RFC9216Test do
  use ExUnit.Case, async: true

  # The example keys and certificates of RFC 9216: Alice and Bob under an
  # RSA CA, Carlos and Dana under an Ed25519 CA, each with one certificate
  # to sign and one to encrypt, and the two CAs certified by each other.
  # Keys anyone can use, made by another hand than the rest of the
  # material.

  alias Cmsex.{Error, Verified}

  @dir Path.expand("../fixtures/rfc9216", __DIR__)

  defp read(name), do: File.read!(Path.join(@dir, name <> ".crt"))
  defp key(name), do: File.read!(Path.join(@dir, name <> ".key"))

  @people %{
    "alice" => {"ca_rsa", "ca_ed25519", "ca_rsa_cross"},
    "bob" => {"ca_rsa", "ca_ed25519", "ca_rsa_cross"},
    "carlos" => {"ca_ed25519", "ca_rsa", "ca_ed25519_cross"},
    "dana" => {"ca_ed25519", "ca_rsa", "ca_ed25519_cross"}
  }

  @content "Example content of RFC 9216 keys"

  defp reason({:error, %Error{reason: reason, detail: detail}}), do: {reason, detail}

  for {who, {root, other_root, cross}} <- @people do
    describe who do
      setup do
        signer = %{certificate: read(unquote(who) <> "_sign"), key: key(unquote(who) <> "_sign")}

        %{
          signer: signer,
          root: read(unquote(root)),
          other_root: read(unquote(other_root)),
          cross: read(unquote(cross))
        }
      end

      test "signs, and the signature is trusted under the CA", ctx do
        {:ok, cms} = Cmsex.sign(@content, ctx.signer)

        assert {:ok, %Verified{content: @content, signers: [signer]}} =
                 Cmsex.verify(cms, trust: [ctx.root])

        assert signer.certificate == ctx.signer.certificate
        assert signer.path == [ctx.root, ctx.signer.certificate]
      end

      test "is trusted under the other CA through its cross certificate", ctx do
        {:ok, cms} = Cmsex.sign(@content, ctx.signer)
        assert reason(Cmsex.verify(cms, trust: [ctx.other_root])) == {:untrusted, :no_path}

        assert {:ok, %Verified{signers: [signer]}} =
                 Cmsex.verify(cms, trust: [ctx.other_root], certificates: [ctx.cross])

        assert signer.path == [ctx.other_root, ctx.cross, ctx.signer.certificate]

        # The same with the cross certificate in the message.
        {:ok, cms} = Cmsex.sign(@content, Map.put(ctx.signer, :chain, [ctx.cross]))
        assert {:ok, %Verified{}} = Cmsex.verify(cms, trust: [ctx.other_root])
      end

      test "decrypts what is encrypted to it" do
        recipient = read(unquote(who) <> "_encrypt")
        credentials = [key: key(unquote(who) <> "_encrypt"), certificate: recipient]

        for cipher <- [:aes256_cbc, :aes256_gcm] do
          {:ok, cms} = Cmsex.encrypt(@content, recipient, cipher: cipher)
          assert {:ok, %{content: @content}} = Cmsex.decrypt(cms, credentials)
        end

        {:ok, cms} = Cmsex.mac(@content, recipient)
        assert {:ok, %{content: @content}} = Cmsex.verify_mac(cms, credentials)
      end
    end
  end

  test "each certificate is for its use only" do
    # A certificate to sign is not a recipient: the RSA ones by their key
    # usage, the Ed25519 ones by their key.
    for who <- ["alice", "bob"],
        do:
          assert(
            reason(Cmsex.encrypt(@content, read(who <> "_sign"))) ==
              {:invalid_recipient, :key_usage}
          )

    for who <- ["carlos", "dana"],
        do:
          assert(
            reason(Cmsex.encrypt(@content, read(who <> "_sign"))) ==
              {:invalid_recipient, :key_type}
          )

    # A certificate to encrypt does not sign: an RSA key can, but no path
    # trusts it for that; an X25519 key cannot.
    for who <- ["alice", "bob"] do
      signer = %{certificate: read(who <> "_encrypt"), key: key(who <> "_encrypt")}
      {:ok, cms} = Cmsex.sign(@content, signer)
      assert reason(Cmsex.verify(cms, trust: [read("ca_rsa")])) == {:untrusted, :key_usage}
    end

    for who <- ["carlos", "dana"] do
      signer = %{certificate: read(who <> "_encrypt"), key: key(who <> "_encrypt")}
      assert reason(Cmsex.sign(@content, signer)) == {:key_mismatch, nil}
    end
  end

  test "a message to all four, and signed by all four" do
    recipients = for who <- Map.keys(@people), do: read(who <> "_encrypt")
    {:ok, cms} = Cmsex.encrypt(@content, recipients, cipher: :aes128_gcm)

    for who <- Map.keys(@people) do
      credentials = [key: key(who <> "_encrypt"), certificate: read(who <> "_encrypt")]
      assert {:ok, %{content: @content}} = Cmsex.decrypt(cms, credentials)
    end

    signers =
      for who <- Map.keys(@people),
          do: %{certificate: read(who <> "_sign"), key: key(who <> "_sign")}

    {:ok, cms} = Cmsex.sign(@content, signers, detached: true)

    assert {:ok, %Verified{content: nil, signers: verified}} =
             Cmsex.verify(cms, content: @content, trust: [read("ca_rsa"), read("ca_ed25519")])

    # The SignerInfos are a SET, in the order of their encoding.
    assert Enum.sort(Enum.map(verified, & &1.certificate)) ==
             Enum.sort(Enum.map(signers, & &1.certificate))
  end
end
