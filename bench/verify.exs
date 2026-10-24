# Time of Cmsex.verify/2, and of Cmsex.decode/2 on the same messages.
#
#     mix run bench/verify.exs
#
# Each case runs for about a second; the median and the 99th percentile of
# the calls are shown, in milliseconds.

Code.require_file("helper.exs", __DIR__)
alias CmsexBench, as: B

B.header("Cmsex.verify/2")
content = :crypto.strong_rand_bytes(1024)
root = B.cert("ca")

for {label, name} <- [
      {"1 KiB, RSA-2048", "rsa2048"},
      {"1 KiB, RSA-3072", "rsa3072"},
      {"1 KiB, P-256", "p256"},
      {"1 KiB, P-384", "p384"},
      {"1 KiB, Ed25519", "ed25519"},
      {"1 KiB, Ed448", "ed448"}
    ] do
  {:ok, cms} = Cmsex.sign(content, B.signer(name))
  B.measure(label, fn -> {:ok, _} = Cmsex.verify(cms) end)
  B.measure(label <> ", trust", fn -> {:ok, _} = Cmsex.verify(cms, trust: [root]) end)
end

# How much the reader and the checks add to the RSA operation, which is
# over the signed attributes, about 200 bytes, with SHA-256, as the
# library calls it.
{:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
  private_key = :public_key.der_decode(:PrivateKeyInfo, B.key("rsa2048"))

digest = :crypto.hash(:sha256, :crypto.strong_rand_bytes(200))
signature = :public_key.sign({:digest, digest}, :sha256, private_key)
public_key = [:binary.encode_unsigned(e), :binary.encode_unsigned(n)]
{:ok, cms} = Cmsex.sign(content, B.signer("rsa2048"))

IO.puts("")

rsa =
  B.measure("RSA-2048: :crypto.verify/5 alone", fn ->
    true = :crypto.verify(:rsa, :sha256, {:digest, digest}, signature, public_key)
  end)

decode = B.measure("RSA-2048: Cmsex.decode/2", fn -> {:ok, _} = Cmsex.decode(cms) end)
verify = B.measure("RSA-2048: Cmsex.verify/2", fn -> {:ok, _} = Cmsex.verify(cms) end)

IO.puts(
  "decode/2 is #{round(decode / rsa * 100)}% of the RSA operation; " <>
    "verify/2 adds #{round((verify - rsa) / rsa * 100)}% to it\n"
)

others = ~w(rsa3072 rsapss p384 p521 ed448 noski serial20) |> Enum.map(&B.cert/1)
signers = Enum.map(~w(rsa2048 p256 ed25519), &B.signer/1)

{:ok, cms} =
  Cmsex.sign(content, signers, certificates: Enum.map(signers, & &1.certificate) ++ others)

B.measure("10 certificates, 3 signers", fn -> {:ok, _} = Cmsex.verify(cms) end)

B.measure("10 certificates, 3 signers, trust", fn ->
  {:ok, _} = Cmsex.verify(cms, trust: [root])
end)

B.measure("10 certificates, 3 signers: decode/2", fn -> {:ok, _} = Cmsex.decode(cms) end)

signer = B.signer("p256")

for {label, chunk} <- [
      {"100 MiB stream, 64 KiB chunks, P-256", 65_536},
      {"100 MiB stream, 1 MiB chunks, P-256", 1_048_576}
    ] do
  stream = B.stream(100 * 1_048_576, chunk)
  {:ok, p7s} = Cmsex.sign({:stream, stream}, signer)
  B.measure(label, fn -> {:ok, _} = Cmsex.verify(p7s, content: {:stream, stream}) end, 3)
end
