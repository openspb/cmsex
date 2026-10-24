# Time of Cmsex.sign/3.
#
#     mix run bench/sign.exs
#
# Each case runs for about a second; the median and the 99th percentile of
# the calls are shown, in milliseconds.

Code.require_file("helper.exs", __DIR__)
alias CmsexBench, as: B

B.header("Cmsex.sign/3")
content = :crypto.strong_rand_bytes(1024)

for {label, name, opts} <- [
      {"1 KiB, RSA-2048", "rsa2048", []},
      {"1 KiB, RSA-2048 PSS", "rsa2048", [rsa_padding: :pss]},
      {"1 KiB, RSA-3072", "rsa3072", []},
      {"1 KiB, P-256", "p256", []},
      {"1 KiB, P-384", "p384", []},
      {"1 KiB, Ed25519", "ed25519", []},
      {"1 KiB, Ed448", "ed448", []}
    ] do
  signer = Map.merge(B.signer(name), Map.new(opts))
  B.measure(label, fn -> {:ok, _} = Cmsex.sign(content, signer) end)
end

three = Enum.map(~w(rsa2048 p256 ed25519), &B.signer/1)
B.measure("1 KiB, RSA-2048 + P-256 + Ed25519", fn -> {:ok, _} = Cmsex.sign(content, three) end)

signer = B.signer("p256")

for {label, chunk} <- [
      {"100 MiB stream, 64 KiB chunks, P-256", 65_536},
      {"100 MiB stream, 1 MiB chunks, P-256", 1_048_576}
    ] do
  stream = B.stream(100 * 1_048_576, chunk)
  B.measure(label, fn -> {:ok, _} = Cmsex.sign({:stream, stream}, signer) end, 3)
end
