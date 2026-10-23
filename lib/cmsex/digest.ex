defmodule Cmsex.Digest do
  @moduledoc false
  # Digests of a binary, of a stream read once, or given ready.
  #
  # The names are those of `Cmsex.OID`. `:shake256` and `:shake256_len` both
  # mean SHAKE256 with 512 bits of output, the only use CMS makes of it
  # (RFC 8419, 2.3).

  @type hash :: :md5 | :sha1 | :sha224 | :sha256 | :sha384 | :sha512 | :shake256 | :shake256_len
  @type content :: binary() | {:stream, Enumerable.t()} | {:digest, hash(), binary()}

  @hashes [:md5, :sha1, :sha224, :sha256, :sha384, :sha512, :shake256, :shake256_len]

  @doc "The hashes this module computes."
  @spec hashes() :: [hash(), ...]
  def hashes, do: @hashes

  @doc "The size of a digest, in bytes."
  @spec size(hash()) :: 16 | 20 | 28 | 32 | 48 | 64
  def size(:md5), do: 16
  def size(:sha1), do: 20
  def size(:sha224), do: 28
  def size(:sha256), do: 32
  def size(:sha384), do: 48
  def size(:sha512), do: 64
  def size(:shake256), do: 64
  def size(:shake256_len), do: 64

  @doc "The digest of iodata."
  @spec hash(hash(), iodata()) :: binary()
  def hash(hash, data) when hash in [:shake256, :shake256_len],
    do: :crypto.hash_xof(:shake256, data, 512)

  def hash(hash, data), do: :crypto.hash(crypto(hash), data)

  @doc "The name `:crypto` uses for a hash."
  @spec crypto(hash()) :: atom()
  def crypto(:sha1), do: :sha
  def crypto(hash) when hash in [:shake256, :shake256_len], do: :shake256
  def crypto(hash), do: hash

  @doc """
  The digests of a content for each hash in `hashes`, as a map. A stream is
  read once, whatever the number of hashes. A ready digest only answers for
  its own hash; the others are missing from the map.
  """
  @spec many(content(), [hash()]) :: %{hash() => binary()}
  def many({:digest, hash, value}, hashes) do
    if hash in hashes, do: %{hash => value}, else: %{}
  end

  def many({:stream, enumerable}, hashes) do
    hashes = Enum.uniq(hashes)
    initial = Map.new(hashes, &{&1, :crypto.hash_init(crypto(&1))})

    enumerable
    |> Enum.reduce(initial, fn chunk, states ->
      Map.new(states, fn {hash, state} -> {hash, :crypto.hash_update(state, chunk)} end)
    end)
    |> Map.new(fn {hash, state} -> {hash, final(hash, state)} end)
  end

  def many(data, hashes) when is_binary(data),
    do: hashes |> Enum.uniq() |> Map.new(&{&1, hash(&1, data)})

  defp final(hash, state) when hash in [:shake256, :shake256_len],
    do: :crypto.hash_final_xof(state, 512)

  defp final(_hash, state), do: :crypto.hash_final(state)
end
