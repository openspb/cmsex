defmodule Cmsex.OptionsTest do
  use ExUnit.Case, async: true

  alias Cmsex.{Attribute, Recipient, Signer, TestPKI}

  # An option given twice is refused, wherever options are taken: which
  # of the values was meant cannot be told, and taking one in silence
  # could weaken a check, as with `[trust: roots, trust: nil]`.
  test "an option given twice raises" do
    cert = TestPKI.cert(:p256)
    key = TestPKI.key(:p256)
    signer = %{certificate: cert, key: key}
    signed = Cmsex.sign!("content", signer)
    kek = :crypto.strong_rand_bytes(32)
    recipient = Recipient.kek(kek, "id")
    enveloped = Cmsex.encrypt!("content", recipient)

    for call <- [
          fn -> Cmsex.decode(signed, max_depth: 8, max_depth: 64) end,
          fn -> Cmsex.certificates(signed, max_certificates: 1, max_certificates: 2) end,
          fn -> Cmsex.verify(signed, trust: [cert], trust: nil) end,
          fn -> Cmsex.verify_each(signed, allow_sha1: false, allow_sha1: true) end,
          fn -> Cmsex.sign("content", signer, detached: true, detached: false) end,
          fn -> Cmsex.certs_only([cert], crls: [], crls: []) end,
          fn -> Cmsex.add_signer(signed, signer, max_depth: 8, max_depth: 64) end,
          fn -> Cmsex.add_signer(signed, signer, digest: :sha256, digest: :sha512) end,
          fn -> Cmsex.encrypt("content", recipient, cipher: :aes256_gcm, cipher: :aes128_cbc) end,
          fn -> Cmsex.encrypt_with_key("content", kek, detached: true, detached: false) end,
          fn -> Cmsex.decrypt(enveloped, kek: {"id", kek}, kek: {"other", kek}) end,
          fn -> Cmsex.digest("content", digest: :sha256, digest: :sha512) end,
          fn -> Cmsex.verify_digest(Cmsex.digest!("x"), allow_sha1: true, allow_sha1: false) end,
          fn -> Cmsex.mac("content", recipient, mac: :hmac_sha256, mac: :hmac_sha512) end,
          fn -> Cmsex.verify_mac(enveloped, kek: {"id", kek}, kek: {"id", kek}) end,
          fn -> Recipient.certificate(cert, oaep_digest: :sha256, oaep_digest: :sha512) end,
          fn -> Recipient.kek(kek, "id", key_wrap: :aes256_wrap, key_wrap: :aes256_wrap_pad) end,
          fn -> Recipient.password("password", iterations: 1, iterations: 600_000) end,
          fn -> Signer.new!(certificate: cert, key: key, key: TestPKI.key({:p256, :other})) end,
          fn -> Attribute.signing_certificate_v2(cert, hash: :sha256, hash: :sha512) end
        ] do
      assert_raise ArgumentError, ~r/given more than once/, call
    end
  end

  test "the same options, once each, are taken" do
    cert = TestPKI.cert(:p256)
    signer = Signer.new!(certificate: cert, key: TestPKI.key(:p256), digest: :sha384)

    assert {:ok, _} = Cmsex.sign("content", signer, detached: true, signing_time: false)
    assert %Attribute{} = Attribute.signing_certificate_v2(cert, hash: :sha512)
  end
end
