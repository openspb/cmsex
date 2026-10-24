# Extracts the certificates and keys of RFC 9216 into test/fixtures/rfc9216,
# in DER.
#
#     curl -sO https://www.rfc-editor.org/rfc/rfc9216.txt
#     elixir test/support/extract_rfc9216.exs rfc9216.txt
#
# Each section holds one PEM block, sometimes across a page break; only the
# lines made of base64 characters are kept. The PKCS #12 objects are left
# out.

[rfc] = System.argv()
out = Path.expand("../fixtures/rfc9216", __DIR__)
File.mkdir_p!(out)
text = File.read!(rfc)

names = %{
  "3.1" => "ca_rsa.crt",
  "3.2" => "ca_rsa.key",
  "3.3" => "ca_rsa_cross.crt",
  "4.1" => "alice_sign.crt",
  "4.2" => "alice_sign.key",
  "4.3" => "alice_encrypt.crt",
  "4.4" => "alice_encrypt.key",
  "5.1" => "bob_sign.crt",
  "5.2" => "bob_sign.key",
  "5.3" => "bob_encrypt.crt",
  "5.4" => "bob_encrypt.key",
  "6.1" => "ca_ed25519.crt",
  "6.2" => "ca_ed25519.key",
  "6.3" => "ca_ed25519_cross.crt",
  "7.1" => "carlos_sign.crt",
  "7.2" => "carlos_sign.key",
  "7.3" => "carlos_encrypt.crt",
  "7.4" => "carlos_encrypt.key",
  "8.1" => "dana_sign.crt",
  "8.2" => "dana_sign.key",
  "8.3" => "dana_encrypt.crt",
  "8.4" => "dana_encrypt.key"
}

sections =
  for chunk <- Regex.split(~r/^(?=\d\.\d\.  )/m, text),
      [_, section, body] <-
        [Regex.run(~r/\A(\d\.\d)\.  .*?-----BEGIN [A-Z ]+-----\n(.*?)-----END /s, chunk)],
      do: {section, body}

for {section, body} <- sections, name = names[section] do
  base64 =
    body
    |> String.split("\n")
    |> Enum.filter(&Regex.match?(~r|^\s+[A-Za-z0-9+/=]+$|, &1))
    |> Enum.map_join(&String.trim/1)

  path = Path.join(out, name)
  File.write!(path, Base.decode64!(base64))
  IO.puts("#{path}: #{File.stat!(path).size} bytes")
end

22 = out |> File.ls!() |> length()
