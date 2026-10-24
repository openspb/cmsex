# Time of Cmsex.encrypt/3 and Cmsex.decrypt/2, and of Cmsex.mac/3 and
# Cmsex.verify_mac/2.
#
#     mix run bench/encrypt.exs
#
# Each case runs for about a second; the median and the 99th percentile of
# the calls are shown, in milliseconds.

Code.require_file("helper.exs", __DIR__)
alias CmsexBench, as: B
alias Cmsex.Recipient

B.header("Cmsex.encrypt/3 and Cmsex.decrypt/2")
content = :crypto.strong_rand_bytes(1024)
kek = :crypto.strong_rand_bytes(32)

for {label, name} <- [
      {"RSA-2048, OAEP", "rsa2048"},
      {"RSA-3072, OAEP", "rsa3072"},
      {"P-256, ECDH", "p256"},
      {"P-384, ECDH", "p384"},
      {"X25519", "x25519"},
      {"X448", "x448"}
    ] do
  credentials = B.credentials(name)
  recipient = credentials[:certificate]
  {:ok, cms} = Cmsex.encrypt(content, recipient)
  B.measure("1 KiB, #{label}: encrypt", fn -> {:ok, _} = Cmsex.encrypt(content, recipient) end)
  B.measure("1 KiB, #{label}: decrypt", fn -> {:ok, _} = Cmsex.decrypt(cms, credentials) end)
end

recipient = Recipient.kek(kek, "bench")
{:ok, cms} = Cmsex.encrypt(content, recipient)
B.measure("1 KiB, KEK: encrypt", fn -> {:ok, _} = Cmsex.encrypt(content, recipient) end)
B.measure("1 KiB, KEK: decrypt", fn -> {:ok, _} = Cmsex.decrypt(cms, kek: {"bench", kek}) end)

for iterations <- [600_000, 10_000] do
  recipient = Recipient.password("correct horse battery staple", iterations: iterations)
  {:ok, cms} = Cmsex.encrypt(content, recipient)
  label = "1 KiB, password, #{iterations} iterations"
  B.measure(label <> ": encrypt", fn -> {:ok, _} = Cmsex.encrypt(content, recipient) end)

  B.measure(label <> ": decrypt", fn ->
    {:ok, _} = Cmsex.decrypt(cms, password: "correct horse battery staple")
  end)
end

IO.puts("")
big = :crypto.strong_rand_bytes(100 * 1_048_576)
recipient = Recipient.kek(kek, "bench")

for cipher <- [:aes256_cbc, :aes256_gcm, :aes256_ccm, :chacha20_poly1305] do
  {:ok, cms} = Cmsex.encrypt(big, recipient, cipher: cipher)

  B.measure(
    "100 MiB, #{cipher}: encrypt",
    fn -> {:ok, _} = Cmsex.encrypt(big, recipient, cipher: cipher) end,
    3
  )

  B.measure(
    "100 MiB, #{cipher}: decrypt",
    fn -> {:ok, _} = Cmsex.decrypt(cms, kek: {"bench", kek}) end,
    3
  )
end

IO.puts("")
{:ok, cms} = Cmsex.mac(content, recipient)
B.measure("1 KiB, HMAC-SHA-256, KEK: mac", fn -> {:ok, _} = Cmsex.mac(content, recipient) end)

B.measure("1 KiB, HMAC-SHA-256, KEK: verify_mac", fn ->
  {:ok, _} = Cmsex.verify_mac(cms, kek: {"bench", kek})
end)

stream = B.stream(100 * 1_048_576, 1_048_576)
{:ok, cms} = Cmsex.mac({:stream, stream}, recipient)

B.measure(
  "100 MiB stream, HMAC-SHA-256: mac",
  fn -> {:ok, _} = Cmsex.mac({:stream, stream}, recipient) end,
  3
)

B.measure(
  "100 MiB stream, HMAC-SHA-256: verify_mac",
  fn -> {:ok, _} = Cmsex.verify_mac(cms, kek: {"bench", kek}, content: {:stream, stream}) end,
  3
)
