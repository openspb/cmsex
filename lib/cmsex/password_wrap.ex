defmodule Cmsex.PasswordWrap do
  @moduledoc false
  # The key wrap of id-alg-PWRI-KEK (RFC 3211, 2.3): the content-encryption
  # key, formatted with its length and a check value, encrypted twice in
  # CBC mode with the key derived from the password.

  import Bitwise

  @doc """
  Wraps `cek` with a CBC cipher of `:crypto`, its key and IV, and the
  block size (RFC 3211, 2.3.1). `padding` makes the formatted key whole
  blocks and at least two; it is random unless given, for the tests.
  """
  @spec wrap(atom(), binary(), binary(), pos_integer(), binary(), binary() | nil) :: binary()
  def wrap(cipher, kek, iv, block_size, cek, padding \\ nil)
      when byte_size(cek) in 3..255 do
    formatted = <<byte_size(cek)>> <> check(cek) <> cek
    size = max(2 * block_size, round_up(byte_size(formatted), block_size))
    padding = padding || :crypto.strong_rand_bytes(size - byte_size(formatted))

    unless byte_size(formatted) + byte_size(padding) == size,
      do: raise(ArgumentError, "the padding must make #{size} bytes")

    first = :crypto.crypto_one_time(cipher, kek, iv, [formatted, padding], true)
    last = binary_part(first, byte_size(first) - block_size, block_size)
    :crypto.crypto_one_time(cipher, kek, last, first, true)
  end

  @doc """
  Unwraps a key (RFC 3211, 2.3.2). Returns `:error` when the length is not
  whole blocks and at least two, the count is out of range, or the check
  value does not match: that is, for a wrong password.
  """
  @spec unwrap(atom(), binary(), binary(), pos_integer(), binary()) :: {:ok, binary()} | :error
  def unwrap(cipher, kek, iv, block_size, wrapped)
      when is_integer(block_size) and byte_size(wrapped) >= 2 * block_size and
             rem(byte_size(wrapped), block_size) == 0 do
    head_size = byte_size(wrapped) - block_size
    <<head::binary-size(head_size), last::binary-size(block_size)>> = wrapped
    previous = binary_part(head, head_size - block_size, block_size)

    # The outer layer: the last block with the one before as IV, then the
    # others with that result as IV.
    last_inner = :crypto.crypto_one_time(cipher, kek, previous, last, false)
    head_inner = :crypto.crypto_one_time(cipher, kek, last_inner, head, false)

    <<count, check::binary-size(3), rest::binary>> =
      :crypto.crypto_one_time(cipher, kek, iv, head_inner <> last_inner, false)

    # Both checks run, and the check value is compared over the bytes that
    # are there whatever the count says.
    fits = count >= 3 and count <= byte_size(rest)
    <<first::binary-size(3), _::binary>> = rest

    if :crypto.hash_equals(check(first), check) and fits,
      do: {:ok, binary_part(rest, 0, count)},
      else: :error
  end

  def unwrap(_cipher, _kek, _iv, _block_size, _wrapped), do: :error

  # The bitwise complement of the first three bytes.
  defp check(<<a, b, c, _::binary>>), do: <<bnot(a) &&& 0xFF, bnot(b) &&& 0xFF, bnot(c) &&& 0xFF>>

  defp round_up(n, block), do: div(n + block - 1, block) * block
end
