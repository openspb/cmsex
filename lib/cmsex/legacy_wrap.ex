defmodule Cmsex.LegacyWrap do
  @moduledoc false
  # The Triple-DES and RC2 key wraps of RFC 3217, which older messages use
  # to wrap a content-encryption key in a KEKRecipientInfo or a
  # KeyAgreeRecipientInfo. The library only unwraps with them; wrapping is
  # here so that the tests can check both against the examples of the RFC.

  import Bitwise

  # RFC 3217, 3.1, step 8, and 4.1, step 10.
  @iv2 <<0x4ADDA22C79E82105::64>>

  @doc """
  Wraps a Triple-DES key (RFC 3217, 3.1), with the IV of step 4 given.
  """
  @spec des3_wrap(<<_::192>>, <<_::192>>, <<_::64>>) :: <<_::320>>
  def des3_wrap(kek, <<_::binary-size(24)>> = cek, <<_::binary-size(8)>> = iv) do
    cek = odd_parity(cek)
    double_cbc(:des_ede3_cbc, kek, iv, cek <> icv(cek))
  end

  @doc """
  Unwraps a Triple-DES key (RFC 3217, 3.2): 40 bytes, the checksum and the
  parity must check.
  """
  @spec des3_unwrap(binary(), binary()) :: {:ok, binary()} | :error
  def des3_unwrap(<<_::binary-size(24)>> = kek, <<_::binary-size(40)>> = wrapped) do
    <<cek::binary-size(24), icv::binary-size(8)>> = undo_double_cbc(:des_ede3_cbc, kek, wrapped)

    if :crypto.hash_equals(icv(cek), icv) and odd_parity(cek) == cek,
      do: {:ok, cek},
      else: :error
  end

  def des3_unwrap(_kek, _wrapped), do: :error

  @doc """
  Wraps an RC2 key (RFC 3217, 4.1) with a 128-bit RC2 key, with the IV and
  the padding of steps 3 and 6 given.
  """
  @spec rc2_wrap(<<_::128>>, binary(), <<_::64>>, binary()) :: binary()
  def rc2_wrap(<<_::binary-size(16)>> = kek, cek, <<_::binary-size(8)>> = iv, pad)
      when byte_size(cek) in 1..255 and rem(1 + byte_size(cek) + byte_size(pad), 8) == 0 and
             byte_size(pad) < 8 do
    lcekpad = <<byte_size(cek)>> <> cek <> pad
    double_cbc(:rc2_cbc, kek, iv, lcekpad <> icv(lcekpad))
  end

  @doc """
  Unwraps an RC2 key (RFC 3217, 4.2) with a 128-bit RC2 key: the checksum
  must check, and the length and the padding fit.
  """
  @spec rc2_unwrap(binary(), binary()) :: {:ok, binary()} | :error
  def rc2_unwrap(<<_::binary-size(16)>> = kek, wrapped)
      when byte_size(wrapped) >= 24 and rem(byte_size(wrapped), 8) == 0 do
    lcekpadicv = undo_double_cbc(:rc2_cbc, kek, wrapped)
    size = byte_size(lcekpadicv) - 8
    <<lcekpad::binary-size(^size), icv::binary-size(8)>> = lcekpadicv
    <<length, rest::binary>> = lcekpad
    fits = length >= 1 and length <= byte_size(rest) and byte_size(rest) - length <= 7

    if :crypto.hash_equals(icv(lcekpad), icv) and fits,
      do: {:ok, binary_part(rest, 0, length)},
      else: :error
  end

  def rc2_unwrap(_kek, _wrapped), do: :error

  # RFC 3217, 3.1, steps 5 to 8: CBC with the IV, the IV put in front, the
  # whole reversed, and CBC again with the fixed IV.
  defp double_cbc(cipher, kek, iv, data) do
    temp1 = :crypto.crypto_one_time(cipher, kek, iv, data, true)
    temp3 = reverse(iv <> temp1)
    :crypto.crypto_one_time(cipher, kek, @iv2, temp3, true)
  end

  defp undo_double_cbc(cipher, kek, wrapped) do
    temp3 = :crypto.crypto_one_time(cipher, kek, @iv2, wrapped, false)
    <<iv::binary-size(8), temp1::binary>> = reverse(temp3)
    :crypto.crypto_one_time(cipher, kek, iv, temp1, false)
  end

  # RFC 3217, 2: the first 8 bytes of the SHA-1 hash.
  defp icv(data), do: binary_part(:crypto.hash(:sha, data), 0, 8)

  defp reverse(bin), do: bin |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

  # Odd parity on each byte: the low bit makes the count of ones odd.
  defp odd_parity(key) do
    for <<byte <- key>>, into: <<>> do
      high = byte &&& 0xFE
      ones = for(<<(bit::1 <- <<high>>)>>, do: bit) |> Enum.sum()
      <<high ||| if(rem(ones, 2) == 0, do: 1, else: 0)>>
    end
  end
end
