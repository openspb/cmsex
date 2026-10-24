defmodule Cmsex.TestJar do
  @moduledoc false
  # Signed JAR files, as the JAR File Specification of the JDK describes
  # them: a manifest with the digest of each entry, a signature file (.SF)
  # with the digests of the manifest and of its sections, and a SignedData
  # detached over the signature file, in a block file whose extension is
  # RSA or EC.

  import Bitwise

  @main [{"Manifest-Version", "1.0"}, {"Created-By", "cmsex tests"}]

  @doc """
  A JAR with `files` (`{name, bytes}`), signed by `sign`, a function that
  takes the bytes of the signature file and returns `{extension,
  signed_data}`.
  """
  def signed(files, sign) do
    main = section(@main)
    sections = Enum.map(files, fn {name, bytes} -> entry_section(name, bytes) end)
    manifest = IO.iodata_to_binary([main | sections])

    signature_file =
      IO.iodata_to_binary([
        section([
          {"Signature-Version", "1.0"},
          {"SHA-256-Digest-Manifest-Main-Attributes", digest(main)},
          {"SHA-256-Digest-Manifest", digest(manifest)},
          {"Created-By", "cmsex tests"}
        ])
        | for {{name, _bytes}, entry} <- Enum.zip(files, sections) do
            section([{"Name", name}, {"SHA-256-Digest", digest(entry)}])
          end
      ])

    {extension, block} = sign.(signature_file)

    zip([
      {"META-INF/MANIFEST.MF", manifest},
      {"META-INF/SIGNER.SF", signature_file},
      {"META-INF/SIGNER." <> extension, block}
      | files
    ])
  end

  @doc "A JAR with `files` and no manifest."
  def unsigned(files), do: zip(files)

  @doc "The entries of a JAR, by name."
  def entries(jar) do
    {:ok, files} = :zip.unzip(jar, [:memory])
    Map.new(files, fn {name, bytes} -> {List.to_string(name), bytes} end)
  end

  defp entry_section(name, bytes),
    do: section([{"Name", name}, {"SHA-256-Digest", digest(bytes)}])

  defp section(headers), do: IO.iodata_to_binary([Enum.map(headers, &header/1), "\r\n"])

  # A line has at most 72 bytes; a longer one goes on in lines that start
  # with a space.
  defp header({name, value}) do
    <<first::binary-size(min(72, byte_size(name) + 2 + byte_size(value))), rest::binary>> =
      "#{name}: #{value}"

    [first, "\r\n" | continuation(rest)]
  end

  defp continuation(""), do: []

  defp continuation(rest) when byte_size(rest) <= 71, do: [" ", rest, "\r\n"]

  defp continuation(<<line::binary-size(71), rest::binary>>),
    do: [" ", line, "\r\n" | continuation(rest)]

  defp digest(bytes), do: Base.encode64(:crypto.hash(:sha256, bytes))

  # A ZIP file with the entries stored, made here: :zip writes Unix
  # permissions, which jarsigner -strict refuses as not covered by the
  # signature. The time of every entry is 2026-01-01 00:00.
  @dos_date (2026 - 1980) <<< 9 ||| 1 <<< 5 ||| 1

  defp zip(files) do
    {locals, centrals, _offset} =
      Enum.reduce(files, {[], [], 0}, fn {name, bytes}, {locals, centrals, offset} ->
        common =
          <<20::little-16, 0::little-16, 0::little-16, 0::little-16, @dos_date::little-16,
            :erlang.crc32(bytes)::little-32, byte_size(bytes)::little-32,
            byte_size(bytes)::little-32, byte_size(name)::little-16, 0::little-16>>

        local = [<<0x04034B50::little-32>>, common, name, bytes]

        central = [
          <<0x02014B50::little-32, 20::little-16>>,
          common,
          <<0::little-16, 0::little-16, 0::little-16, 0::little-32, offset::little-32>>,
          name
        ]

        {[local | locals], [central | centrals], offset + IO.iodata_length(local)}
      end)

    locals = Enum.reverse(locals)
    centrals = Enum.reverse(centrals)
    start = IO.iodata_length(locals)
    count = length(files)

    IO.iodata_to_binary([
      locals,
      centrals,
      <<0x06054B50::little-32, 0::little-16, 0::little-16, count::little-16, count::little-16,
        IO.iodata_length(centrals)::little-32, start::little-32, 0::little-16>>
    ])
  end
end
