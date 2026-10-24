defmodule Cmsex.KeyWrapTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Cmsex.KeyWrap

  doctest Cmsex.KeyWrap

  defp hex(string), do: Base.decode16!(String.replace(string, " ", ""), case: :mixed)

  @kek128 "000102030405060708090A0B0C0D0E0F"
  @kek192 "000102030405060708090A0B0C0D0E0F1011121314151617"
  @kek256 "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
  @key128 "00112233445566778899AABBCCDDEEFF"
  @key192 "00112233445566778899AABBCCDDEEFF0001020304050607"
  @key256 "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"

  # RFC 3394, 4.
  @rfc3394 [
    {"4.1", @kek128, @key128, "1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"},
    {"4.2", @kek192, @key128, "96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"},
    {"4.3", @kek256, @key128, "64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"},
    {"4.4", @kek192, @key192,
     "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"},
    {"4.5", @kek256, @key192,
     "A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"},
    {"4.6", @kek256, @key256,
     "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"}
  ]

  describe "RFC 3394" do
    for {section, kek, key, wrapped} <- @rfc3394 do
      test "#{section} wraps and unwraps" do
        kek = hex(unquote(kek))
        key = hex(unquote(key))
        wrapped = hex(unquote(wrapped))

        assert KeyWrap.wrap(kek, key) == wrapped
        assert KeyWrap.unwrap(kek, wrapped) == {:ok, key}
      end
    end

    test "a changed byte, or another key-encryption key, gives :error" do
      kek = hex(@kek128)
      wrapped = KeyWrap.wrap(kek, hex(@key128))

      for at <- 0..(byte_size(wrapped) - 1) do
        <<head::binary-size(^at), byte, tail::binary>> = wrapped
        assert KeyWrap.unwrap(kek, <<head::binary, bxor(byte, 1), tail::binary>>) == :error
      end

      assert KeyWrap.unwrap(hex(@kek192), KeyWrap.wrap(hex(@kek192), hex(@key128))) ==
               {:ok, hex(@key128)}

      assert KeyWrap.unwrap(:binary.copy(<<0>>, 16), wrapped) == :error
    end

    test "ciphertexts of the wrong size give :error" do
      kek = hex(@kek128)

      for size <- [0, 8, 16, 23, 25, 31] do
        assert KeyWrap.unwrap(kek, :binary.copy(<<1>>, size)) == :error
      end
    end

    test "wrong arguments raise" do
      assert_raise ArgumentError, ~r/16, 24 or 32 bytes/, fn ->
        KeyWrap.wrap(<<0::120>>, hex(@key128))
      end

      for size <- [0, 8, 15, 17, 20] do
        assert_raise ArgumentError, ~r/multiples of 8/, fn ->
          KeyWrap.wrap(hex(@kek128), :binary.copy(<<1>>, size))
        end
      end
    end
  end

  # RFC 5649, 6.
  @kek "5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"
  @rfc5649 [
    {"20 bytes", "c37b7e6492584340 bed1220780894115 5068f738",
     "138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a"},
    {"7 bytes", "466f7250617369", "afbeb0f07dfbf541 9200f2ccb50bb24f"}
  ]

  describe "RFC 5649" do
    for {name, key, wrapped} <- @rfc5649 do
      test "6, #{name}, wraps and unwraps" do
        kek = hex(@kek)
        key = hex(unquote(key))
        wrapped = hex(unquote(wrapped))

        assert KeyWrap.wrap_with_padding(kek, key) == wrapped
        assert KeyWrap.unwrap_with_padding(kek, wrapped) == {:ok, key}
      end
    end

    test "a changed byte, or another key-encryption key, gives :error" do
      kek = hex(@kek)

      for {_, key, _} <- @rfc5649 do
        wrapped = KeyWrap.wrap_with_padding(kek, hex(key))

        for at <- 0..(byte_size(wrapped) - 1) do
          <<head::binary-size(^at), byte, tail::binary>> = wrapped
          changed = <<head::binary, bxor(byte, 0x80), tail::binary>>
          assert KeyWrap.unwrap_with_padding(kek, changed) == :error
        end

        assert KeyWrap.unwrap_with_padding(hex(@kek192), wrapped) == :error
      end
    end

    # An integrity value that is right, with a length or padding that is
    # not, made by wrapping with the plain process.
    test "a wrong length or padding behind a right prefix gives :error" do
      kek = hex(@kek128)

      for {mli, padded} <- [
            {0, <<1::64>>},
            {9, <<1::64>>},
            {7, <<1::64>>},
            {8, <<1::128>>},
            {17, <<1::128>>},
            {12, <<1::128>>}
          ] do
        aiv = <<0xA65959A6::32, mli::32>>
        wrapped = plain_wrap(kek, aiv, padded)
        assert KeyWrap.unwrap_with_padding(kek, wrapped) == :error, "MLI #{mli}"
      end

      # The same helper, with values that are right.
      for {mli, padded, key} <- [{16, <<1::128>>, <<1::128>>}, {12, <<1::96, 0::32>>, <<1::96>>}] do
        wrapped = plain_wrap(kek, <<0xA65959A6::32, mli::32>>, padded)
        assert KeyWrap.unwrap_with_padding(kek, wrapped) == {:ok, key}
      end
    end

    test "the RFC 3394 value is not taken for the RFC 5649 one" do
      kek = hex(@kek128)
      wrapped = KeyWrap.wrap(kek, hex(@key128))
      assert KeyWrap.unwrap_with_padding(kek, wrapped) == :error
      assert KeyWrap.unwrap(kek, KeyWrap.wrap_with_padding(kek, hex(@key128))) == :error
    end

    test "wrong arguments raise" do
      assert_raise ArgumentError, ~r/from 1 byte/, fn ->
        KeyWrap.wrap_with_padding(hex(@kek128), <<>>)
      end
    end
  end

  # The process of RFC 3394 with any initial value, for the test above. A
  # single block goes through AES in ECB mode, as in RFC 5649, 4.1.
  defp plain_wrap(kek, aiv, <<_::64>> = block),
    do: :crypto.crypto_one_time(:aes_128_ecb, kek, aiv <> block, true)

  defp plain_wrap(kek, aiv, data) do
    blocks = for <<block::binary-size(8) <- data>>, do: block
    n = length(blocks)

    {a, r} =
      Enum.reduce(0..5, {aiv, blocks}, fn j, {a, r} ->
        {a, out} =
          r
          |> Enum.with_index(1)
          |> Enum.reduce({a, []}, fn {block, i}, {a, out} ->
            <<msb::64, lsb::binary>> =
              :crypto.crypto_one_time(:aes_128_ecb, kek, a <> block, true)

            {<<bxor(msb, n * j + i)::64>>, [lsb | out]}
          end)

        {a, Enum.reverse(out)}
      end)

    IO.iodata_to_binary([a | r])
  end

  property "what is wrapped unwraps" do
    check all kek_size <- member_of([16, 24, 32]),
              kek <- binary(length: kek_size),
              blocks <- integer(2..64),
              key <- binary(length: blocks * 8),
              any <- binary(min_length: 1, max_length: 300) do
      assert KeyWrap.unwrap(kek, KeyWrap.wrap(kek, key)) == {:ok, key}
      assert KeyWrap.unwrap_with_padding(kek, KeyWrap.wrap_with_padding(kek, any)) == {:ok, any}
    end
  end
end
