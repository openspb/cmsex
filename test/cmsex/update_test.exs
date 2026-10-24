defmodule Cmsex.UpdateTest do
  use ExUnit.Case, async: true

  alias Cmsex.{Attribute, DER, Error, Signer, SignerInfo, TestCMS, TestFixtures, TestPKI}

  @content "the content of the update tests"

  setup_all do
    root = TestPKI.cert({:p384, :update_root}, ca: true, subject: "Update Root")
    issuer = {root, {:p384, :update_root}}

    certs =
      Map.new([:rsa2048, :p256, :p384, :ed25519, :ed448], &{&1, TestPKI.cert(&1, issuer: issuer)})

    %{root: root, certs: certs}
  end

  defp signer(ctx, key, fields \\ []),
    do: struct!(%Signer{certificate: ctx.certs[key], key: TestPKI.key(key)}, fields)

  defp signer_infos(der) do
    {:ok, signed_data} = Cmsex.decode(der)
    signed_data.signer_infos
  end

  defp raws(der), do: Enum.map(signer_infos(der), & &1.raw.signer_info)
  defp signed_part(signer_info), do: signer_info.raw.signed_part

  defp verify!(der, ctx, opts \\ []) do
    assert {:ok, verified} = Cmsex.verify(der, [trust: [ctx.root]] ++ opts)
    verified
  end

  defp reason({:error, %Error{reason: reason}}), do: reason

  describe "add_signer/3" do
    test "adds a SignerInfo after the others, which keep their bytes", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))
      added = Cmsex.add_signer!(der, signer(ctx, :rsa2048))

      assert [first, second] = raws(added)
      assert [first] == raws(der)

      verified = verify!(added, ctx)
      assert verified.content == @content

      assert Enum.map(verified.signers, & &1.certificate) == [
               ctx.certs[:p256],
               ctx.certs[:rsa2048]
             ]

      assert DER.der?(added)
      assert DER.der?(second)
    end

    test "several at once, and again", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))
      der = Cmsex.add_signer!(der, [signer(ctx, :ed25519), signer(ctx, :ed448)])
      der = Cmsex.add_signer!(der, signer(ctx, :p384, digest: :sha384))

      verified = verify!(der, ctx)

      assert Enum.map(verified.signers, & &1.certificate) ==
               Enum.map([:p256, :ed25519, :ed448, :p384], &ctx.certs[&1])

      assert {:ok, signed_data} = Cmsex.decode(der)
      assert signed_data.digest_algorithms == [:sha256, :sha512, :shake256_len, :sha384]
    end

    test "the certificates of the new signers join the message", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))
      added = Cmsex.add_signer!(der, signer(ctx, :rsa2048, chain: [ctx.root]))
      assert Cmsex.certificates!(added) == [ctx.certs[:p256], ctx.certs[:rsa2048], ctx.root]

      # Those already there are not repeated, and none can be asked for.
      again = Cmsex.add_signer!(added, signer(ctx, :p256))
      assert Cmsex.certificates!(again) == Cmsex.certificates!(added)

      none = Cmsex.add_signer!(der, signer(ctx, :rsa2048), certificates: :none)
      assert Cmsex.certificates!(none) == [ctx.certs[:p256]]
      assert reason(Cmsex.verify(none)) == :signer_not_found
      assert {:ok, _} = Cmsex.verify(none, certificates: [ctx.certs[:rsa2048]])
    end

    test "to a message without certificates", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256), certificates: :none)
      added = Cmsex.add_signer!(der, signer(ctx, :rsa2048))
      assert Cmsex.certificates!(added) == [ctx.certs[:rsa2048]]
      assert {:ok, _} = Cmsex.verify(added, certificates: [ctx.certs[:p256]])
    end

    test "with a subject key identifier makes the message version 3", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))
      assert {:ok, %{version: 1}} = Cmsex.decode(der)

      added = Cmsex.add_signer!(der, signer(ctx, :rsa2048), identifier: :subject_key_identifier)
      assert {:ok, %{version: 3, deviations: []}} = Cmsex.decode(added)
      verify!(added, ctx)
    end

    test "a detached message needs its content, and the same one", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256), detached: true)

      assert reason(Cmsex.add_signer(der, signer(ctx, :rsa2048))) == :content_required

      added = Cmsex.add_signer!(der, signer(ctx, :rsa2048), content: @content)
      assert {:ok, %{content: nil}} = Cmsex.decode(added)
      assert length(verify!(added, ctx, content: @content).signers) == 2

      stream = Cmsex.add_signer!(der, signer(ctx, :p384), content: {:stream, [@content]})
      assert length(verify!(stream, ctx, content: @content).signers) == 2

      digest = {:digest, :sha256, :crypto.hash(:sha256, @content)}
      ready = Cmsex.add_signer!(der, signer(ctx, :rsa2048), content: digest)
      assert length(verify!(ready, ctx, content: @content).signers) == 2

      assert {:error, %Error{reason: :digest_mismatch, signer: 0}} =
               Cmsex.add_signer(der, signer(ctx, :rsa2048), content: "another content")

      assert reason(
               Cmsex.add_signer(Cmsex.sign!(@content, signer(ctx, :p256)), signer(ctx, :rsa2048),
                 content: @content
               )
             ) ==
               :unexpected_content
    end

    test "a key function is not called when the content does not match", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256), detached: true)
      fun = fn _request -> raise "called" end
      external = %Signer{certificate: ctx.certs[:rsa2048], key: fun}

      assert reason(Cmsex.add_signer(der, external, content: "another content")) ==
               :digest_mismatch
    end

    test "to a certs-only message, which becomes a detached signature", ctx do
      bundle = Cmsex.certs_only!([ctx.root])
      added = Cmsex.add_signer!(bundle, signer(ctx, :p256), content: @content)
      verified = verify!(added, ctx, content: @content)
      assert [%{certificate: cert}] = verified.signers
      assert cert == ctx.certs[:p256]
    end

    test "to another content type", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256), content_type: :tst_info)
      added = Cmsex.add_signer!(der, signer(ctx, :rsa2048))
      verified = verify!(added, ctx)
      assert verified.content_type == :tst_info
      assert length(verified.signers) == 2

      assert_raise ArgumentError, fn ->
        Cmsex.add_signer(der, signer(ctx, :rsa2048), no_attributes: true)
      end
    end

    test "without signed attributes", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))
      added = Cmsex.add_signer!(der, signer(ctx, :ed25519), no_attributes: true)
      assert [_, %{signed_attributes: nil}] = signer_infos(added)
      verify!(added, ctx)
    end

    test "to a message in BER, whose content comes out in DER", ctx do
      ber = TestCMS.to_ber(Cmsex.sign!(@content, signer(ctx, :p256)))
      refute DER.der?(ber)

      added = Cmsex.add_signer!(ber, signer(ctx, :rsa2048))
      assert [first, _] = raws(added)
      assert [first] == raws(ber)
      assert length(verify!(added, ctx).signers) == 2

      # The SignerInfo in BER stays as it was; the rest is DER.
      {:ok, %{signer_infos: [old, new]}} = Cmsex.decode(added)
      refute DER.der?(old.raw.signer_info)
      assert DER.der?(new.raw.signer_info)
    end

    test "in PEM", ctx do
      pem = Cmsex.PEM.encode(Cmsex.sign!(@content, signer(ctx, :p256)))
      added = Cmsex.add_signer!(pem, signer(ctx, :rsa2048))
      assert <<0x30, _::binary>> = added
      verify!(added, ctx)
    end

    test "errors", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))

      assert {:error, %Error{reason: :key_certificate_mismatch, signer: 1}} =
               Cmsex.add_signer(der, [
                 signer(ctx, :rsa2048),
                 %Signer{certificate: ctx.certs[:p384], key: TestPKI.key(:p256)}
               ])

      assert reason(Cmsex.add_signer("garbage", signer(ctx, :rsa2048))) == :malformed

      assert_raise ArgumentError, fn ->
        Cmsex.add_signer(der, signer(ctx, :rsa2048), detached: true)
      end

      assert_raise ArgumentError, fn ->
        Cmsex.add_signer(der, signer(ctx, :rsa2048), digest: :md5)
      end

      assert_raise Cmsex.Error, fn -> Cmsex.add_signer!("garbage", signer(ctx, :rsa2048)) end
    end
  end

  describe "the fixtures of other tools" do
    test "keep verifying", ctx do
      for name <- ~w(o3_rsa o3_p256 o3_stream o3_two_signers lre_rsa gt_rsa py_rsa java_ec) do
        der = TestFixtures.read!(name <> ".p7s")
        opts = if name == "java_ec", do: [content: TestFixtures.read!("java_ec.sf")], else: []
        added = Cmsex.add_signer!(der, signer(ctx, :p256), opts)

        old = raws(der)
        assert Enum.take(raws(added), length(old)) == old

        roots = [ctx.root | TestFixtures.roots()]
        assert {:ok, verified} = Cmsex.verify(added, [trust: roots] ++ opts), name
        assert length(verified.signers) == length(old) + 1
      end
    end
  end

  describe "countersign/4" do
    test "a signer, verified with countersignatures: true", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      countersigned = Cmsex.countersign!(der, 0, signer(ctx, :p256))

      [before] = signer_infos(der)
      assert [after_] = signer_infos(countersigned)
      assert signed_part(after_) == signed_part(before)
      assert after_.signature == before.signature

      assert [%Attribute{type: :countersignature, values: [value]}] = after_.unsigned_attributes

      # Without the option, the countersignature is only read.
      assert [%{countersignatures: []}] = verify!(countersigned, ctx).signers

      assert [%{countersignatures: [counter]}] =
               verify!(countersigned, ctx, countersignatures: true).signers

      assert counter.certificate == ctx.certs[:p256]
      assert counter.index == 0
      assert %DateTime{} = counter.signing_time
      assert counter.path == [ctx.root, ctx.certs[:p256]]
      assert counter.signer_info.raw.signer_info == value

      # RFC 5652, 11.4: no content type, the digest of the signature value.
      refute SignerInfo.attribute(counter.signer_info, :content_type)

      assert SignerInfo.read_attribute(counter.signer_info, :message_digest) ==
               {:ok, :crypto.hash(:sha256, before.signature)}

      # The certificate of the countersigner joins the message.
      assert Cmsex.certificates!(countersigned) == [ctx.certs[:rsa2048], ctx.certs[:p256]]
    end

    test "each key type, with and without signed attributes", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))

      for key <- [:rsa2048, :p256, :p384, :ed25519, :ed448], no_attributes <- [false, true] do
        countersigned = Cmsex.countersign!(der, 0, signer(ctx, key), no_attributes: no_attributes)

        [%{countersignatures: [counter]}] =
          verify!(countersigned, ctx, countersignatures: true).signers

        assert counter.certificate == ctx.certs[key]
        assert counter.signer_info.signed_attributes == nil == no_attributes
      end
    end

    test "more countersignatures go after the others", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      der = Cmsex.countersign!(der, 0, signer(ctx, :p256))
      [%{unsigned_attributes: [%{values: [first]}]}] = signer_infos(der)

      der = Cmsex.countersign!(der, 0, [signer(ctx, :p384), signer(ctx, :ed25519)])

      assert [%{unsigned_attributes: [%Attribute{type: :countersignature, values: values}]}] =
               signer_infos(der)

      assert [^first, _, _] = values

      [%{countersignatures: counters}] = verify!(der, ctx, countersignatures: true).signers

      assert Enum.map(counters, & &1.certificate) ==
               Enum.map([:p256, :p384, :ed25519], &ctx.certs[&1])

      assert Enum.map(counters, & &1.index) == [0, 1, 2]
    end

    test "a countersignature, at a list of positions", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      der = Cmsex.countersign!(der, 0, [signer(ctx, :p256), signer(ctx, :p384)])
      der = Cmsex.countersign!(der, [0, 1], signer(ctx, :ed25519))
      der = Cmsex.countersign!(der, [0, 1, 0], signer(ctx, :ed448))

      [%{countersignatures: [first, second]}] = verify!(der, ctx, countersignatures: true).signers
      assert first.countersignatures == []
      assert [nested] = second.countersignatures
      assert nested.certificate == ctx.certs[:ed25519]
      assert [deeper] = nested.countersignatures
      assert deeper.certificate == ctx.certs[:ed448]

      # Each level covers the signature value of the one above.
      assert SignerInfo.read_attribute(nested.signer_info, :message_digest) ==
               {:ok, :crypto.hash(:sha512, second.signer_info.signature)}

      # An error deep down says where.
      {offset, size} = :binary.match(der, deeper.signer_info.signature)
      <<head::binary-size(^offset + ^size - 1), last, tail::binary>> = der
      tampered = <<head::binary, Bitwise.bxor(last, 1), tail::binary>>

      assert {:error, %Error{reason: :invalid_signature, signer: [0, 1, 0, 0]}} =
               Cmsex.verify(tampered, countersignatures: true)

      assert {:ok, _} = Cmsex.verify(tampered)
    end

    test "the signers of the message stay where they are", ctx do
      der = Cmsex.sign!(@content, [signer(ctx, :p256), signer(ctx, :rsa2048), signer(ctx, :p384)])
      before = raws(der)

      countersigned = Cmsex.countersign!(der, 1, signer(ctx, :ed25519))
      [a, b, c] = raws(countersigned)
      assert a == Enum.at(before, 0)
      assert c == Enum.at(before, 2)
      assert b != Enum.at(before, 1)

      signers = verify!(countersigned, ctx, countersignatures: true).signers
      assert Enum.map(signers, &length(&1.countersignatures)) == [0, 1, 0]
    end

    test "a tampered countersignature fails only with countersignatures: true", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      countersigned = Cmsex.countersign!(der, 0, signer(ctx, :p256))
      [%{unsigned_attributes: [%{values: [value]}]}] = signer_infos(countersigned)
      {offset, _} = :binary.match(countersigned, value)
      size = byte_size(value)
      <<head::binary-size(^offset + ^size - 1), last, tail::binary>> = countersigned
      tampered = <<head::binary, Bitwise.bxor(last, 1), tail::binary>>

      assert {:ok, _} = Cmsex.verify(tampered, trust: [ctx.root])

      assert {:error, %Error{reason: :invalid_signature, signer: [0, 0]}} =
               Cmsex.verify(tampered, trust: [ctx.root], countersignatures: true)
    end

    test "attributes of the countersigner, but never content-type", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      v2 = Attribute.signing_certificate_v2(ctx.certs[:p256])
      countersigned = Cmsex.countersign!(der, 0, signer(ctx, :p256, signed_attributes: [v2]))

      [%{countersignatures: [counter]}] =
        verify!(countersigned, ctx, countersignatures: true).signers

      assert SignerInfo.attribute(counter.signer_info, :signing_certificate_v2) == v2

      assert_raise ArgumentError, ~r/countersignature has no content-type/, fn ->
        Cmsex.countersign(
          der,
          0,
          signer(ctx, :p256, signed_attributes: [Attribute.content_type(:data)])
        )
      end
    end

    test "verify_countersignature/3 checks one without the signer above", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      der = Cmsex.countersign!(der, 0, [signer(ctx, :p256), signer(ctx, :p384)])
      der = Cmsex.countersign!(der, [0, 1], signer(ctx, :ed25519))

      assert {:ok, counter} = Cmsex.verify_countersignature(der, [0, 1], trust: [ctx.root])
      assert counter.certificate == ctx.certs[:p384]
      assert counter.index == 1
      assert counter.path == [ctx.root, ctx.certs[:p384]]
      assert counter.countersignatures == []

      assert {:ok, %{countersignatures: [nested]}} =
               Cmsex.verify_countersignature(der, [0, 1], countersignatures: true)

      assert nested.certificate == ctx.certs[:ed25519]

      assert {:ok, %{certificate: cert}} = Cmsex.verify_countersignature(der, [0, 1, 0])
      assert cert == ctx.certs[:ed25519]

      # The main signature broken: the countersignature is still good.
      [%{signature: signature}] = signer_infos(der)
      {offset, _} = :binary.match(der, signature)
      <<head::binary-size(^offset), byte, tail::binary>> = der
      broken = <<head::binary, Bitwise.bxor(byte, 1), tail::binary>>

      assert {:error, %Error{reason: :invalid_signature, signer: 0}} = Cmsex.verify(broken)

      assert {:error, %Error{reason: :digest_mismatch, signer: [0, 0]}} =
               Cmsex.verify_countersignature(broken, [0, 0])

      for position <- [0, [0], [1, 0], [0, 2], [0, 1, 1], [0, -1], "0"] do
        assert_raise ArgumentError, fn -> Cmsex.verify_countersignature(der, position) end
      end

      assert_raise ArgumentError, fn ->
        Cmsex.verify_countersignature(der, [0, 0], content: @content)
      end
    end

    test "a message in BER", ctx do
      ber = TestCMS.to_ber(Cmsex.sign!(@content, signer(ctx, :rsa2048)))
      countersigned = Cmsex.countersign!(ber, 0, signer(ctx, :p256))
      [before] = signer_infos(ber)
      [after_] = signer_infos(countersigned)
      assert signed_part(after_) == signed_part(before)
      [%{countersignatures: [_]}] = verify!(countersigned, ctx, countersignatures: true).signers
    end

    test "a position the message does not have", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))

      for position <- [1, [1], [0, 0], -1, [], [0, -1], :first, "0"] do
        assert_raise ArgumentError, fn -> Cmsex.countersign(der, position, signer(ctx, :p256)) end
      end

      countersigned = Cmsex.countersign!(der, 0, signer(ctx, :p256))

      assert_raise ArgumentError, ~r/\[0, 1\]/, fn ->
        Cmsex.countersign(countersigned, [0, 1], signer(ctx, :p256))
      end

      assert_raise ArgumentError, ~r/\[0, 0, 0\]/, fn ->
        Cmsex.countersign(countersigned, [0, 0, 0], signer(ctx, :p256))
      end
    end

    test "errors of the countersigner", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      bad = %Signer{certificate: ctx.certs[:p384], key: TestPKI.key(:p256)}
      assert reason(Cmsex.countersign(der, 0, bad)) == :key_certificate_mismatch
      assert_raise Cmsex.Error, fn -> Cmsex.countersign!(der, 0, bad) end

      assert_raise ArgumentError, fn ->
        Cmsex.countersign(der, 0, signer(ctx, :p256), content: "x")
      end
    end
  end

  describe "add_unsigned_attribute/4" do
    defp token(n), do: Attribute.new(:time_stamp_token, [DER.encode({:seq, [{:int, n}]})])

    test "keeps the signed part and the attributes already there", ctx do
      first = Attribute.new({1, 2, 3, 4}, [DER.encode({:utf8, "first"})])
      der = Cmsex.sign!(@content, signer(ctx, :p256, unsigned_attributes: [first]))
      [before] = signer_infos(der)

      added = Cmsex.add_unsigned_attribute!(der, 0, token(1))
      [after_] = signer_infos(added)
      assert signed_part(after_) == signed_part(before)
      assert after_.unsigned_attributes == [first, token(1)]
      assert SignerInfo.unsigned_attribute(after_, :time_stamp_token) == token(1)

      [signer] = verify!(added, ctx).signers
      assert signer.signer_info.unsigned_attributes == [first, token(1)]
    end

    test "several, one after the other, at the same position", ctx do
      der = Cmsex.sign!(@content, [signer(ctx, :p256), signer(ctx, :rsa2048)])

      der =
        Enum.reduce(0..1, der, fn index, der ->
          Cmsex.add_unsigned_attribute!(der, index, [token(index), token(index + 10)])
        end)

      assert [%{unsigned_attributes: [a, b]}, %{unsigned_attributes: [c, d]}] = signer_infos(der)
      assert [a, b, c, d] == [token(0), token(10), token(1), token(11)]
      assert length(verify!(der, ctx).signers) == 2
    end

    test "the signature value is what a time-stamp covers", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))
      [signer_info] = signer_infos(der)
      assert SignerInfo.signature(signer_info) == signer_info.signature

      {:ok, verified} = Cmsex.verify(der)
      [%{signer_info: verified_info}] = verified.signers
      assert SignerInfo.signature(verified_info) == signer_info.signature
    end

    test "to a countersignature", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :rsa2048))
      der = Cmsex.countersign!(der, 0, signer(ctx, :p256))
      der = Cmsex.add_unsigned_attribute!(der, [0, 0], token(7))

      [%{countersignatures: [counter]}] = verify!(der, ctx, countersignatures: true).signers
      assert counter.signer_info.unsigned_attributes == [token(7)]
    end

    test "to a fixture of OpenSSL", ctx do
      der = TestFixtures.read!("o3_two_signers.p7s")
      added = Cmsex.add_unsigned_attribute!(der, 1, token(1))
      [a, b] = signer_infos(der)
      [c, d] = signer_infos(added)
      assert c.raw.signer_info == a.raw.signer_info
      assert signed_part(d) == signed_part(b)
      assert {:ok, _} = Cmsex.verify(added, trust: TestFixtures.roots())
      _ = ctx
    end

    test "arguments", ctx do
      der = Cmsex.sign!(@content, signer(ctx, :p256))
      assert_raise ArgumentError, fn -> Cmsex.add_unsigned_attribute(der, 0, []) end
      assert_raise ArgumentError, fn -> Cmsex.add_unsigned_attribute(der, 0, [:token]) end
      assert_raise ArgumentError, fn -> Cmsex.add_unsigned_attribute(der, 1, token(1)) end

      assert_raise ArgumentError, fn ->
        Cmsex.add_unsigned_attribute(der, 0, token(1), digest: :sha256)
      end

      assert reason(Cmsex.add_unsigned_attribute("garbage", 0, token(1))) == :malformed

      assert {:error, %Error{reason: :limit_exceeded}} =
               Cmsex.add_unsigned_attribute(der, 0, token(1), max_depth: 2)

      assert_raise Cmsex.Error, fn -> Cmsex.add_unsigned_attribute!("garbage", 0, token(1)) end
    end
  end
end
