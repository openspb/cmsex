defmodule Cmsex.KDF do
  @moduledoc false
  # Key derivation: the KDF of ANSI X9.63 that RFC 5753 and RFC 8418 use
  # with ECDH, HKDF (RFC 5869) for RFC 8418, and PBKDF2 (RFC 8018, 5.2) for
  # passwords (RFC 3211).

  alias Cmsex.Digest

  @doc """
  The ANSI X9.63 KDF (RFC 5753, 7.2; SEC 1, 3.6.1): the hash of the shared
  secret, a 32-bit counter from 1 and the shared info, block after block.
  """
  @spec x963(Digest.hash(), binary(), binary(), pos_integer()) :: binary()
  def x963(hash, secret, shared_info, length) when length > 0 do
    hash = Digest.crypto(hash)

    1..blocks(hash, length)
    |> Enum.map(&:crypto.hash(hash, [secret, <<&1::32>>, shared_info]))
    |> IO.iodata_to_binary()
    |> binary_part(0, length)
  end

  @doc """
  HKDF (RFC 5869): extract with `salt`, then expand with `info`. An empty
  salt is the same as a salt of zeros (RFC 5869, 2.2).
  """
  @spec hkdf(Digest.hash(), binary(), binary(), binary(), pos_integer()) :: binary()
  def hkdf(hash, salt, secret, info, length) when length > 0 do
    hash = Digest.crypto(hash)
    count = blocks(hash, length)

    unless count <= 255, do: raise(ArgumentError, "HKDF output too long")

    prk = :crypto.mac(:hmac, hash, salt, secret)

    1..count
    |> Enum.map_reduce(<<>>, fn i, previous ->
      block = :crypto.mac(:hmac, hash, prk, [previous, info, <<i>>])
      {block, block}
    end)
    |> elem(0)
    |> IO.iodata_to_binary()
    |> binary_part(0, length)
  end

  @doc "PBKDF2 (RFC 8018, 5.2) with HMAC of `hash` as the pseudorandom function."
  @spec pbkdf2(Digest.hash(), binary(), binary(), pos_integer(), pos_integer()) :: binary()
  def pbkdf2(hash, password, salt, iterations, length) do
    :crypto.pbkdf2_hmac(Digest.crypto(hash), password, salt, iterations, length)
  end

  defp blocks(hash, length) do
    size = byte_size(:crypto.hash(hash, <<>>))
    div(length + size - 1, size)
  end
end
