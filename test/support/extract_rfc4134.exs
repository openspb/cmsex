# Extracts the examples of RFC 4134, appendix B, into test/fixtures/rfc4134.
#
#     curl -sO https://www.rfc-editor.org/rfc/rfc4134.txt
#     elixir test/support/extract_rfc4134.exs rfc4134.txt
#
# Each file sits between a "|>name" line and a "|<name" line, in base64
# lines that start with "|". Page breaks fall in between; the lines that do
# not start with "|" are skipped.

[rfc] = System.argv()
out = Path.expand("../fixtures/rfc4134", __DIR__)
File.mkdir_p!(out)

files =
  Regex.scan(~r/^\|>(\S+)\n(.*?)^\|<\1$/ms, File.read!(rfc))
  |> Enum.map(fn [_, name, body] ->
    base64 =
      body
      |> String.split("\n")
      |> Enum.filter(&String.starts_with?(&1, "|"))
      |> Enum.reject(&String.starts_with?(&1, "|*"))
      |> Enum.map_join(&String.trim_leading(&1, "|"))

    {name, Base.decode64!(base64)}
  end)

40 = length(files)

for {name, bytes} <- files do
  path = Path.join(out, name)
  File.write!(path, bytes)
  IO.puts("#{path}: #{byte_size(bytes)} bytes")
end
