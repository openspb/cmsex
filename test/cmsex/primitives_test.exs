defmodule Cmsex.PrimitivesTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Cmsex.{Algorithm, Certificate, DER, Digest, Key, OID, TestPKI}

  describe "Digest" do
    test "sizes and known values" do
      for hash <- Digest.hashes() do
        assert byte_size(Digest.hash(hash, "abc")) == Digest.size(hash)
      end

      assert Base.encode16(Digest.hash(:sha256, "abc"), case: :lower) ==
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

      # FIPS 202: SHAKE256("") with 512 bits of output.
      assert Base.encode16(Digest.hash(:shake256, ""), case: :lower) ==
               "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" <>
                 "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    end

    test "a ready digest answers only for its hash" do
      assert Digest.many({:digest, :sha256, "x"}, [:sha256, :sha512]) == %{sha256: "x"}
    end

    property "a stream gives the digests of the binary, for any split" do
      check all data <- binary(max_length: 2000),
                cuts <- list_of(integer(0..2000), max_length: 8) do
        cuts = cuts |> Enum.map(&min(&1, byte_size(data))) |> Enum.sort()
        chunks = split(data, cuts)
        hashes = [:sha256, :sha512, :shake256]
        assert Digest.many({:stream, chunks}, hashes) == Digest.many(data, hashes)
      end
    end
  end

  defp split(data, cuts) do
    {chunks, last} =
      Enum.reduce(cuts, {[], 0}, fn cut, {acc, from} ->
        {[binary_part(data, from, cut - from) | acc], cut}
      end)

    Enum.reverse([binary_part(data, last, byte_size(data) - last) | chunks])
  end

  describe "Algorithm" do
    defp alg(term) do
      {:ok, el} = DER.decode(DER.encode(term))
      {:ok, alg} = Algorithm.read(el)
      alg
    end

    test "digests take absent or NULL parameters" do
      assert Algorithm.digest(alg({:seq, [{:oid, :sha256}]})) == {:ok, :sha256}
      assert Algorithm.digest(alg({:seq, [{:oid, :sha256}, :null]})) == {:ok, :sha256}
      assert {:error, :malformed, _} = Algorithm.digest(alg({:seq, [{:oid, :sha256}, {:int, 1}]}))

      assert Algorithm.digest(alg({:seq, [{:oid, :shake256_len}, {:int, 512}]})) ==
               {:ok, :shake256_len}

      assert {:error, :unsupported_algorithm, _} =
               Algorithm.digest(alg({:seq, [{:oid, :shake256_len}, {:int, 256}]}))

      assert {:error, :unsupported_algorithm, {1, 2, 3}} =
               Algorithm.digest(alg({:seq, [{:oid, {1, 2, 3}}]}))
    end

    test "signature algorithms" do
      assert {:ok, %{scheme: :rsa_pkcs1, hash: nil}} =
               Algorithm.signature(alg({:seq, [{:oid, :rsa_encryption}, :null]}))

      assert {:ok, %{scheme: :rsa_pkcs1, hash: :sha384}} =
               Algorithm.signature(alg({:seq, [{:oid, :sha384_with_rsa_encryption}]}))

      assert {:ok, %{scheme: :ecdsa, hash: :sha256}} =
               Algorithm.signature(alg({:seq, [{:oid, :ecdsa_with_sha256}]}))

      assert {:ok, %{scheme: :ed25519}} = Algorithm.signature(alg({:seq, [{:oid, :ed25519}]}))
      assert {:error, :malformed, _} = Algorithm.signature(alg({:seq, [{:oid, :ed25519}, :null]}))

      assert {:error, :unsupported_algorithm, _} =
               Algorithm.signature(alg({:seq, [{:oid, :dsa_with_sha1}]}))

      assert {:error, :malformed, _} = Algorithm.signature(alg({:seq, [{:oid, :rsassa_pss}]}))
    end

    test "PSS parameters, written and with defaults" do
      written = alg(Algorithm.signature_identifier(:rsa_pss, :sha256))

      assert {:ok, %{scheme: :rsa_pss, hash: :sha256, pss: pss}} = Algorithm.signature(written)
      assert pss == %{hash: :sha256, mgf_hash: :sha256, salt_length: 32, trailer_field: 1}

      defaults = alg({:seq, [{:oid, :rsassa_pss}, {:seq, []}]})

      assert {:ok, %{pss: %{hash: :sha1, mgf_hash: :sha1, salt_length: 20, trailer_field: 1}}} =
               Algorithm.signature(defaults)

      # Defaults written out compare equal to defaults left out (RFC 6211).
      sha1 = {:seq, [{:oid, :sha1}]}

      explicit =
        alg(
          {:seq,
           [
             {:oid, :rsassa_pss},
             {:seq,
              [
                {:explicit, 0, sha1},
                {:explicit, 1, {:seq, [{:oid, :mgf1}, sha1]}},
                {:explicit, 2, {:int, 20}},
                {:explicit, 3, {:int, 1}}
              ]}
           ]}
        )

      assert Algorithm.canonical(explicit) == Algorithm.canonical(defaults)
      refute Algorithm.canonical(explicit) == Algorithm.canonical(written)

      bad_trailer = alg({:seq, [{:oid, :rsassa_pss}, {:seq, [{:explicit, 3, {:int, 2}}]}]})
      assert {:error, :malformed, _} = Algorithm.signature(bad_trailer)
    end

    test "NULL and absent compare equal" do
      assert Algorithm.canonical(alg({:seq, [{:oid, :sha256}]})) ==
               Algorithm.canonical(alg({:seq, [{:oid, :sha256}, :null]}))

      refute Algorithm.canonical(alg({:seq, [{:oid, :sha256}]})) ==
               Algorithm.canonical(alg({:seq, [{:oid, :sha384}]}))
    end

    test "OAEP parameters" do
      {:seq, [_oid, params]} = Algorithm.oaep_identifier(:sha256)
      {:ok, el} = DER.decode(DER.encode(params))
      assert Algorithm.oaep_params(el) == {:ok, %{hash: :sha256, mgf_hash: :sha256, label: ""}}
      assert Algorithm.oaep_params(nil) == {:ok, %{hash: :sha1, mgf_hash: :sha1, label: ""}}
    end

    test "plan: agreement between digest, signature and key" do
      rsa = Key.public(TestPKI.private(:rsa2048))
      small = Key.public(TestPKI.private(:rsa1024))
      ec = Key.public(TestPKI.private(:p256))
      ed = Key.public(TestPKI.private(:ed25519))
      pkcs1 = %{scheme: :rsa_pkcs1, hash: nil, pss: nil}

      assert {:ok, %{hash: :sha256, scheme: :rsa_pkcs1}} = Algorithm.plan(:sha256, pkcs1, rsa, [])
      assert {:error, :weak_key, 1024} = Algorithm.plan(:sha256, pkcs1, small, [])
      assert {:ok, _} = Algorithm.plan(:sha256, pkcs1, small, min_rsa_bits: 1024)
      assert {:error, :weak_algorithm, :sha1} = Algorithm.plan(:sha1, pkcs1, rsa, [])
      assert {:ok, _} = Algorithm.plan(:sha1, pkcs1, rsa, allow_sha1: true)
      assert {:error, :weak_algorithm, :md5} = Algorithm.plan(:md5, pkcs1, rsa, allow_sha1: true)
      assert {:error, :key_mismatch, _} = Algorithm.plan(:sha256, pkcs1, ec, [])

      combined = %{scheme: :rsa_pkcs1, hash: :sha256, pss: nil}
      assert {:error, :algorithm_mismatch, _} = Algorithm.plan(:sha384, combined, rsa, [])

      ecdsa = %{scheme: :ecdsa, hash: :sha384, pss: nil}
      assert {:ok, %{hash: :sha384}} = Algorithm.plan(:sha384, ecdsa, ec, [])
      assert {:error, :algorithm_mismatch, _} = Algorithm.plan(:sha256, ecdsa, ec, [])

      eddsa = %{scheme: :ed25519, hash: nil, pss: nil}
      assert {:ok, %{deviations: []}} = Algorithm.plan(:sha512, eddsa, ed, [])
      assert {:ok, %{deviations: [:ed25519_digest]}} = Algorithm.plan(:sha256, eddsa, ed, [])

      assert {:error, :algorithm_mismatch, _} =
               Algorithm.plan(:sha256, eddsa, ed, ed25519_digest: :strict)

      ed448 = Key.public(TestPKI.private(:ed448))
      eddsa448 = %{scheme: :ed448, hash: nil, pss: nil}
      assert {:ok, _} = Algorithm.plan(:shake256_len, eddsa448, ed448, [])
      assert {:ok, _} = Algorithm.plan(:shake256, eddsa448, ed448, signed_attributes?: false)
      assert {:error, :algorithm_mismatch, _} = Algorithm.plan(:shake256, eddsa448, ed448, [])
    end

    test "plan: a PSS key with parameters restricts the signature (RFC 4056)" do
      {:rsa, n, e} = Key.public(TestPKI.private(:rsa2048))

      key =
        {:rsa_pss, n, e, %{hash: :sha256, mgf_hash: :sha256, salt_length: 32, trailer_field: 1}}

      sig = fn hash, salt ->
        %{
          scheme: :rsa_pss,
          hash: hash,
          pss: %{hash: hash, mgf_hash: hash, salt_length: salt, trailer_field: 1}
        }
      end

      assert {:ok, _} = Algorithm.plan(:sha256, sig.(:sha256, 32), key, [])
      assert {:ok, _} = Algorithm.plan(:sha256, sig.(:sha256, 40), key, [])

      assert {:error, :algorithm_mismatch, _} =
               Algorithm.plan(:sha256, sig.(:sha256, 20), key, [])

      assert {:error, :algorithm_mismatch, _} =
               Algorithm.plan(:sha384, sig.(:sha384, 48), key, [])

      # The PSS hash must be the digestAlgorithm.
      assert {:error, :algorithm_mismatch, _} =
               Algorithm.plan(:sha384, sig.(:sha256, 32), key, [])

      # A PSS key never signs with PKCS #1 v1.5.
      assert {:error, :key_mismatch, _} =
               Algorithm.plan(:sha256, %{scheme: :rsa_pkcs1, hash: nil, pss: nil}, key, [])
    end

    test "rsa_size/1" do
      assert Algorithm.rsa_size(0xFF) == 8
      assert Algorithm.rsa_size(0x100) == 9
      {:rsa, n, _} = Key.public(TestPKI.private(:rsa2048))
      assert Algorithm.rsa_size(n) == 2048
    end
  end

  describe "Certificate" do
    test "reads what TestPKI writes" do
      ca = TestPKI.cert(:rsa3072, ca: true, subject: "Test CA")

      leaf =
        TestPKI.cert(:p256,
          issuer: {ca, :rsa3072},
          serial: 0x8000_0000_0000_0000_0000_0000_0000_0000_0000_0001
        )

      assert {:ok, %Certificate{} = c} = Certificate.parse(ca)
      assert {:ok, %Certificate{} = l} = Certificate.parse(leaf)
      assert c.ca?
      assert c.key_usage == [:key_cert_sign, :crl_sign]
      assert l.key_usage == [:digital_signature, :non_repudiation]
      assert l.issuer == c.subject
      assert l.serial == 0x8000_0000_0000_0000_0000_0000_0000_0000_0000_0001
      assert l.authority_key_identifier == c.subject_key_identifier
      assert {:ec, :secp256r1, <<4, _::binary-size(64)>>} = l.public_key
      assert {:rsa, _, 65_537} = c.public_key
      assert :public_key.pkix_is_issuer(leaf, ca)
      {:rsa, n, e} = c.public_key
      assert :public_key.pkix_verify(leaf, {:RSAPublicKey, n, e})
    end

    test "every key type" do
      for name <- [:rsa2048, :p384, :p521, :brainpool256, :ed25519, :ed448] do
        assert {:ok, cert} = Certificate.parse(TestPKI.cert(name))
        assert Key.matches?(TestPKI.private(name), cert.public_key), inspect(name)
        refute Key.matches?(TestPKI.private({name, :other}), cert.public_key), inspect(name)
      end

      ca = TestPKI.cert(:ed25519, ca: true)

      for name <- [:x25519, :x448] do
        assert {:ok, cert} = Certificate.parse(TestPKI.cert(name, issuer: {ca, :ed25519}))
        assert {^name, _} = cert.public_key
      end
    end

    test "PSS keys" do
      assert {:ok, %{public_key: {:rsa_pss, _, _, nil}}} =
               Certificate.parse(TestPKI.cert(:rsa2048, pss_key: true))

      assert {:ok, %{public_key: {:rsa_pss, _, _, %{hash: :sha384, salt_length: 48}}}} =
               Certificate.parse(TestPKI.cert(:rsa2048, pss_key: %{hash: :sha384}))
    end

    test "without SKI and key usage" do
      assert {:ok, %{subject_key_identifier: nil, key_usage: nil}} =
               Certificate.parse(TestPKI.cert(:p256, ski: false, key_usage: nil))
    end

    test "rejects what is not a certificate" do
      assert Certificate.parse(<<>>) == :error
      assert Certificate.parse(<<0x30, 0>>) == :error
      assert Certificate.parse(DER.encode({:seq, [{:int, 1}, {:int, 2}, {:int, 3}]})) == :error
      assert Certificate.parse(:not_binary) == :error
    end

    test "canonical names: string types, case and spaces" do
      name = fn type, cn ->
        DER.encode({:seq, [{:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {type, cn}]}]}]})
      end

      a = Certificate.canonical_name(name.(:utf8, "Test  Name"))
      assert a == Certificate.canonical_name(name.(:printable, "test name"))
      assert a == Certificate.canonical_name(name.(:utf8, " TEST NAME "))
      refute a == Certificate.canonical_name(name.(:utf8, "Test Name 2"))

      bmp =
        DER.encode(
          {:seq,
           [
             {:set,
              [
                {:seq,
                 [
                   {:oid, {2, 5, 4, 3}},
                   {:primitive, 0x1E,
                    :unicode.characters_to_binary("Test Name", :utf8, {:utf16, :big})}
                 ]}
              ]}
           ]}
        )

      assert a == Certificate.canonical_name(bmp)
      assert Certificate.canonical_name(<<0x04, 0>>) == nil
    end
  end

  describe "Key" do
    test "reads PKCS #8, PKCS #1, SEC 1 and records" do
      for name <- [:rsa2048, :p256, :p384, :p521, :ed25519, :ed448] do
        record = TestPKI.key(name)
        expected = TestPKI.private(name)
        assert Key.parse(TestPKI.pkcs8(record)) == {:ok, expected}, inspect(name)
        assert Key.parse(record) == {:ok, expected}
      end

      rsa = TestPKI.key(:rsa2048)

      assert Key.parse(:public_key.der_encode(:RSAPrivateKey, rsa)) ==
               {:ok, TestPKI.private(:rsa2048)}

      ec = TestPKI.key(:p256)
      assert Key.parse(:public_key.der_encode(:ECPrivateKey, ec)) == {:ok, TestPKI.private(:p256)}

      for type <- [:x25519, :x448] do
        assert {:ok, {^type, _, _}} = Key.parse(TestPKI.montgomery_pkcs8(type, TestPKI.key(type)))
      end
    end

    test "rejects what is not a key" do
      for bad <- [
            <<>>,
            "junk",
            <<0x30, 0>>,
            DER.encode({:seq, [{:int, 5}]}),
            :atom,
            {:ECPrivateKey}
          ] do
        assert Key.parse(bad) == :error, inspect(bad)
      end
    end

    test "signs and verifies with every scheme" do
      for {name, scheme, hash} <- [
            {:rsa2048, :rsa_pkcs1, :sha256},
            {:rsa2048, :rsa_pss, :sha384},
            {:p256, :ecdsa, :sha256},
            {:p521, :ecdsa, :sha512},
            {:brainpool256, :ecdsa, :sha256},
            {:ed25519, :ed25519, nil},
            {:ed448, :ed448, nil}
          ] do
        key = TestPKI.private(name)

        pss =
          if scheme == :rsa_pss,
            do: %{hash: hash, mgf_hash: hash, salt_length: Digest.size(hash), trailer_field: 1}

        data = if hash, do: Digest.hash(hash, "message"), else: "message"
        signature = Key.sign(key, scheme, hash, data, pss)
        assert Key.verify(Key.public(key), scheme, hash, data, signature, pss), inspect(name)
        refute Key.verify(Key.public(key), scheme, hash, data, flip(signature), pss)

        refute Key.verify(
                 Key.public(TestPKI.private({name, :other})),
                 scheme,
                 hash,
                 data,
                 signature,
                 pss
               )

        refute Key.verify(Key.public(key), scheme, hash, data, "", pss)
      end
    end

    test "verification never raises" do
      refute Key.verify({:rsa, 5, 3}, :rsa_pkcs1, :sha256, "short", "x", nil)

      refute Key.verify(
               {:ec, :secp256r1, "bad point"},
               :ecdsa,
               :sha256,
               :crypto.hash(:sha256, ""),
               "x",
               nil
             )

      refute Key.verify({:ed25519, "short"}, :ed25519, nil, "m", "x", nil)
      refute Key.verify({:unknown, {1, 2}}, :ecdsa, :sha256, "", "", nil)
    end
  end

  defp flip(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>

  test "the curves of Key are named in OID" do
    for curve <- Key.curves(), do: assert(is_tuple(OID.oid(curve)))
  end
end
