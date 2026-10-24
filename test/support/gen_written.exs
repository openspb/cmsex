# Writes the messages of Cmsex itself into test/fixtures/encrypted, as
# cmsex_*.p7m, for the recipients that gen_encrypted.sh made, which runs
# this at its end:
#
#     MIX_ENV=test mix run test/support/gen_written.exs
#
# They have what the other tools do not write, or do not read: X25519 and
# X448, HKDF, AES-CCM, ChaCha20-Poly1305, AES key wrap with padding,
# AuthenticatedData, an OriginatorInfo, attributes. With the messages of
# those tools, they are the corpus of the fuzz tests, and what a later
# version of Cmsex must still read.

alias Cmsex.{Attribute, EncryptedFixtures, Recipient}

content = EncryptedFixtures.content()
cert = &EncryptedFixtures.cert/1
secret = &EncryptedFixtures.secret/1
kek = fn size, opts -> Recipient.kek(secret.(size), EncryptedFixtures.kek_id(), opts) end
# Few iterations, so that the fuzz tests go through many of them.
password = Recipient.password(EncryptedFixtures.password(), iterations: 1000)
# An OID of the arc of RFC 5612, for documentation.
attribute = Attribute.new({1, 3, 6, 1, 4, 1, 32_473, 2}, [Cmsex.DER.encode({:utf8, "cmsex"})])
other_type = {1, 3, 6, 1, 4, 1, 32_473, 3}

messages = [
  cmsex_enveloped:
    Cmsex.encrypt!(content, [
      cert.("rsa2048"),
      cert.("p256"),
      cert.("bp256"),
      cert.("x25519"),
      kek.(16, []),
      password
    ]),
  cmsex_enveloped_ski:
    Cmsex.encrypt!(
      content,
      [
        Recipient.certificate(cert.("rsa3072"),
          identifier: :subject_key_identifier,
          oaep_digest: :sha512
        ),
        Recipient.certificate(cert.("p384"), identifier: :subject_key_identifier)
      ],
      cipher: :aes192_cbc,
      unprotected_attributes: [attribute]
    ),
  cmsex_enveloped_hkdf:
    Cmsex.encrypt!(
      content,
      [
        Recipient.certificate(cert.("p256"),
          key_agreement: :std_dh_hkdf_sha256,
          key_wrap: :aes256_wrap,
          ukm: "cmsex ukm"
        ),
        Recipient.certificate(cert.("p521"), key_agreement: :std_dh_hkdf_sha512),
        cert.("x448")
      ],
      certificates: [cert.("ca")]
    ),
  cmsex_auth_enveloped_gcm:
    Cmsex.encrypt!(content, [cert.("rsa2048"), kek.(32, key_wrap: :aes256_wrap_pad)],
      cipher: :aes256_gcm,
      authenticated_attributes: [attribute]
    ),
  cmsex_auth_enveloped_ccm:
    Cmsex.encrypt!(content, [kek.(24, []), cert.("bp384")],
      cipher: :aes128_ccm,
      tag_size: 8,
      content_type: other_type
    ),
  cmsex_auth_enveloped_chacha:
    Cmsex.encrypt!(content, [cert.("x448"), password], cipher: :chacha20_poly1305),
  cmsex_encrypted:
    Cmsex.encrypt_with_key!(content, secret.(24),
      cipher: :aes192_cbc,
      unprotected_attributes: [attribute]
    ),
  cmsex_auth_data:
    Cmsex.mac!(content, [cert.("rsa2048"), cert.("p256"), cert.("x25519"), kek.(16, []), password]),
  cmsex_auth_data_attributes:
    Cmsex.mac!(content, [kek.(32, []), cert.("p384")],
      mac: :hmac_sha384,
      digest: :sha512,
      content_type: other_type,
      authenticated_attributes: [attribute],
      unauthenticated_attributes: [attribute]
    ),
  cmsex_digested: Cmsex.digest!(content),
  cmsex_digested_other_type: Cmsex.digest!(content, digest: :sha384, content_type: other_type)
]

for {name, der} <- messages do
  File.write!(EncryptedFixtures.path("#{name}.p7m"), der)
end

IO.puts("#{length(messages)} messages of Cmsex written")
