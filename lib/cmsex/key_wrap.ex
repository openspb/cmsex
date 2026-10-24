defmodule Cmsex.KeyWrap do
  @moduledoc """
  The AES key wrap of RFC 3394, and AES key wrap with padding of RFC 5649.

  CMS uses them to encrypt a content-encryption key with another key: the
  key-encryption key of a KEKRecipientInfo, or the key that a
  KeyAgreeRecipientInfo derives. They are written in Elixir over the AES
  block cipher of `:crypto`.

  The key-encryption key is 16, 24 or 32 bytes (AES-128, AES-192 or
  AES-256). `wrap/2` takes key data of 16 bytes or more, in multiples of
  8; `wrap_with_padding/2` takes any length from 1 byte. Unwrapping checks
  the integrity value and returns `:error` when it does not match, which
  happens with a wrong key-encryption key as well as with a changed
  ciphertext; nothing tells the two apart.

      iex> kek = Base.decode16!("000102030405060708090A0B0C0D0E0F")
      iex> key = Base.decode16!("00112233445566778899AABBCCDDEEFF")
      iex> wrapped = Cmsex.KeyWrap.wrap(kek, key)
      iex> Base.encode16(wrapped)
      "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
      iex> Cmsex.KeyWrap.unwrap(kek, wrapped)
      {:ok, key}
  """

  import Bitwise

  # RFC 3394, 2.2.3.1, and RFC 5649, 3.
  @iv <<0xA6A6A6A6A6A6A6A6::64>>
  @aiv_prefix <<0xA65959A6::32>>

  @doc """
  Wraps `key` with `kek` (RFC 3394, 2.2.1, with the default initial
  value). Raises ArgumentError for a key-encryption key that is not an AES
  key, or key data that is shorter than 16 bytes or not a multiple of 8.
  """
  @spec wrap(binary(), binary()) :: binary()
  def wrap(kek, key) when is_binary(kek) and is_binary(key) do
    cipher = cipher!(kek)

    unless byte_size(key) >= 16 and rem(byte_size(key), 8) == 0,
      do: raise(ArgumentError, "key data to wrap must be 16 bytes or more, in multiples of 8")

    wrap_blocks(cipher, kek, @iv, key)
  end

  @doc """
  Unwraps `wrapped` with `kek` (RFC 3394, 2.2.2). Returns `:error` when the
  integrity value does not match, or the ciphertext is not 24 bytes or
  more in multiples of 8.
  """
  @spec unwrap(binary(), binary()) :: {:ok, binary()} | :error
  def unwrap(kek, wrapped) when is_binary(kek) and is_binary(wrapped) do
    cipher = cipher!(kek)

    if byte_size(wrapped) >= 24 and rem(byte_size(wrapped), 8) == 0 do
      {a, key} = unwrap_blocks(cipher, kek, wrapped)
      if :crypto.hash_equals(a, @iv), do: {:ok, key}, else: :error
    else
      :error
    end
  end

  @doc """
  Wraps `key`, of any length from 1 byte, with `kek` (RFC 5649, 4.1).
  Raises ArgumentError for a key-encryption key that is not an AES key, or
  empty key data.
  """
  @spec wrap_with_padding(binary(), binary()) :: binary()
  def wrap_with_padding(kek, key) when is_binary(kek) and is_binary(key) do
    cipher = cipher!(kek)
    size = byte_size(key)

    unless size >= 1 and size < 1 <<< 32,
      do: raise(ArgumentError, "key data to wrap must be from 1 byte to 2^32 - 1 bytes")

    aiv = @aiv_prefix <> <<size::32>>
    padded = key <> :binary.copy(<<0>>, rem(8 - rem(size, 8), 8))

    case padded do
      <<_::binary-size(8)>> -> ecb(cipher, kek, true, aiv <> padded)
      _ -> wrap_blocks(cipher, kek, aiv, padded)
    end
  end

  @doc """
  Unwraps `wrapped` with `kek` (RFC 5649, 4.2). Returns `:error` when the
  integrity value or the padding does not check, or the ciphertext is not
  16 bytes or more in multiples of 8.
  """
  @spec unwrap_with_padding(binary(), binary()) :: {:ok, binary()} | :error
  def unwrap_with_padding(kek, wrapped) when is_binary(kek) and is_binary(wrapped) do
    cipher = cipher!(kek)

    cond do
      byte_size(wrapped) == 16 ->
        <<a::binary-size(8), padded::binary>> = ecb(cipher, kek, false, wrapped)
        unpad(a, padded)

      byte_size(wrapped) >= 24 and rem(byte_size(wrapped), 8) == 0 ->
        {a, padded} = unwrap_blocks(cipher, kek, wrapped)
        unpad(a, padded)

      true ->
        :error
    end
  end

  # RFC 5649, 3: the three checks of the alternative initial value. They
  # all run, so that the time does not say which one failed.
  defp unpad(<<prefix::binary-size(4), mli::32>>, padded) do
    n = div(byte_size(padded), 8)
    length_ok = mli > 8 * (n - 1) and mli <= 8 * n
    size = if length_ok, do: mli, else: byte_size(padded)
    pad = byte_size(padded) - size
    <<key::binary-size(^size), padding::binary-size(^pad)>> = padded

    checks = [
      :crypto.hash_equals(prefix, @aiv_prefix),
      length_ok,
      padding == :binary.copy(<<0>>, pad)
    ]

    if Enum.all?(checks), do: {:ok, key}, else: :error
  end

  # The index-based process of RFC 3394, 2.2.1.
  defp wrap_blocks(cipher, kek, a, data) do
    blocks = for <<block::binary-size(8) <- data>>, do: block
    state = :crypto.crypto_init(cipher, kek, true)
    {a, r} = Enum.reduce(0..5, {a, blocks}, &wrap_round(state, length(blocks), &1, &2))
    IO.iodata_to_binary([a | r])
  end

  defp wrap_round(state, n, j, {a, r}) do
    {a, out} =
      r
      |> Enum.with_index(1)
      |> Enum.reduce({a, []}, fn {block, i}, {a, out} ->
        <<msb::64, lsb::binary-size(8)>> = :crypto.crypto_update(state, a <> block)
        {<<bxor(msb, n * j + i)::64>>, [lsb | out]}
      end)

    {a, Enum.reverse(out)}
  end

  # The index-based process of RFC 3394, 2.2.2, without the check of the
  # initial value: it returns the value found, and the key data. The
  # blocks go from the last one to the first.
  defp unwrap_blocks(cipher, kek, <<a::binary-size(8), data::binary>>) do
    blocks = for <<block::binary-size(8) <- data>>, do: block
    state = :crypto.crypto_init(cipher, kek, false)

    {a, reversed} =
      Enum.reduce(
        5..0//-1,
        {a, Enum.reverse(blocks)},
        &unwrap_round(state, length(blocks), &1, &2)
      )

    {a, IO.iodata_to_binary(Enum.reverse(reversed))}
  end

  defp unwrap_round(state, n, j, {a, reversed}) do
    {a, out} =
      reversed
      |> Enum.with_index()
      |> Enum.reduce({a, []}, fn {block, k}, {<<a::64>>, out} ->
        t = n * j + (n - k)

        <<msb::binary-size(8), lsb::binary-size(8)>> =
          :crypto.crypto_update(state, <<bxor(a, t)::64>> <> block)

        {msb, [lsb | out]}
      end)

    {a, Enum.reverse(out)}
  end

  defp ecb(cipher, kek, encrypt?, block),
    do: :crypto.crypto_one_time(cipher, kek, block, encrypt?)

  defp cipher!(kek) do
    case byte_size(kek) do
      16 ->
        :aes_128_ecb

      24 ->
        :aes_192_ecb

      32 ->
        :aes_256_ecb

      size ->
        raise ArgumentError, "the key-encryption key must be 16, 24 or 32 bytes, got #{size}"
    end
  end
end
