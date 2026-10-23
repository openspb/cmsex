defmodule Cmsex.DERTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Cmsex.DER

  describe "decode/2" do
    test "keeps the content and the raw element" do
      bin = <<0x30, 6, 0x02, 1, 3, 0x04, 1, "x">>
      assert {:ok, {0x30, content, ^bin} = seq} = DER.decode(bin)
      assert content == <<0x02, 1, 3, 0x04, 1, "x">>
      assert DER.children(seq) == [{0x02, <<3>>, <<0x02, 1, 3>>}, {0x04, "x", <<0x04, 1, "x">>}]
      assert DER.children({0x04, "x", <<0x04, 1, "x">>}) == []
    end

    test "long-form lengths" do
      content = :binary.copy("a", 300)
      assert {:ok, {0x04, ^content, _}} = DER.decode(<<0x04, 0x82, 300::16, content::binary>>)
      assert {:ok, {0x04, "a", _}} = DER.decode(<<0x04, 0x81, 1, "a">>)
    end

    test "indefinite lengths (BER)" do
      bin = <<0x30, 0x80, 0x04, 1, "a", 0x30, 0x80, 0, 0, 0, 0>>
      assert {:ok, {0x30, content, ^bin} = seq} = DER.decode(bin)
      assert content == <<0x04, 1, "a", 0x30, 0x80, 0, 0>>

      assert DER.children(seq) == [
               {0x04, "a", <<0x04, 1, "a">>},
               {0x30, <<>>, <<0x30, 0x80, 0, 0>>}
             ]
    end

    test "nested indefinite lengths inside a definite one" do
      inner = <<0xA0, 0x80, 0x24, 0x80, 0x04, 1, "a", 0x04, 1, "b", 0, 0, 0, 0>>
      bin = <<0x30, byte_size(inner) + 3>> <> inner <> <<0x01, 1, 0xFF>>
      assert {:ok, seq} = DER.decode(bin)
      assert [{0xA0, _, ^inner} = tagged, {0x01, <<0xFF>>, _}] = DER.children(seq)
      assert [segmented] = DER.children(tagged)
      assert DER.octets(segmented) == {:ok, "ab"}
    end

    test "high tag numbers" do
      assert {:ok, {{0x80, 31}, "x", _}} = DER.decode(<<0x9F, 31, 1, "x">>)
      assert {:ok, {{0xA0, 200}, <<0x05, 0>>, _} = el} = DER.decode(<<0xBF, 0x81, 0x48, 2, 5, 0>>)
      assert DER.constructed?(elem(el, 0))
      assert DER.children(el) == [{0x05, <<>>, <<0x05, 0>>}]
    end

    test "rejects what a reader cannot trust" do
      for bin <- [
            <<>>,
            <<0x30>>,
            # truncated
            <<0x04, 5, "abc">>,
            <<0x30, 0x80, 0x04, 1, "a">>,
            <<0x30, 0x80, 0x04, 1, "a", 0>>,
            <<0x04, 0x82, 1>>,
            # trailing data
            <<0x04, 1, "a", 0>>,
            # indefinite length on a primitive
            <<0x04, 0x80, "a", 0, 0>>,
            # length of more than 4 bytes
            <<0x04, 0x85, 0, 0, 0, 0, 1, "a">>,
            # reserved length octet
            <<0x04, 0xFF, "a">>,
            # an end-of-contents marker where an element should be
            <<0, 0>>,
            <<0x30, 2, 0, 0>>,
            <<0x20, 0>>,
            # high tag number form for a number below 31, or with padding
            <<0x9F, 30, 0>>,
            <<0x9F, 0x80, 0x81, 0>>,
            <<0x9F, 0x81>>,
            # high tag number above 32 bits
            <<0x9F, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0>>,
            # children that do not fill the parent
            <<0x30, 3, 0x04, 2, "a">>
          ] do
        assert DER.decode(bin) == {:error, :malformed}, inspect(bin)
      end
    end

    test "limits the nesting depth" do
      nested = fn depth ->
        Enum.reduce(1..depth, <<0x05, 0>>, fn _, acc -> <<0x30, 0x80>> <> acc <> <<0, 0>> end)
      end

      assert {:ok, _} = DER.decode(nested.(31))
      assert DER.decode(nested.(32)) == {:error, {:limit_exceeded, :max_depth}}
      assert {:ok, _} = DER.decode(nested.(32), max_depth: 33)
      assert DER.decode(nested.(100_000)) == {:error, {:limit_exceeded, :max_depth}}
    end

    test "limits the number of elements" do
      items = :binary.copy(<<0x05, 0>>, 99)
      bin = <<0x30, 0x81, byte_size(items)>> <> items
      assert {:ok, _} = DER.decode(bin, max_elements: 100)
      assert DER.decode(bin, max_elements: 99) == {:error, {:limit_exceeded, :max_elements}}
    end

    test "a huge declared length is refused before anything is allocated" do
      assert DER.decode(<<0x04, 0x84, 0xFFFFFFFF::32, "abc">>) == {:error, :malformed}
    end
  end

  describe "values" do
    test "segmented strings" do
      {:ok, el} = DER.decode(<<0x24, 0x80, 0x04, 1, "a", 0x24, 3, 0x04, 1, "b", 0x04, 0, 0, 0>>)
      assert DER.octets(el) == {:ok, "ab"}

      # An implicitly tagged OCTET STRING: [0] primitive, or constructed from
      # universal OCTET STRING segments.
      {:ok, el} = DER.decode(<<0x80, 2, "ab">>)
      assert DER.string(el, 0x80) == {:ok, "ab"}
      {:ok, el} = DER.decode(<<0xA0, 6, 0x04, 1, "a", 0x04, 1, "b">>)
      assert DER.string(el, 0x80) == {:ok, "ab"}

      # Segments of the wrong type.
      {:ok, el} = DER.decode(<<0x24, 3, 0x0C, 1, "a">>)
      assert DER.octets(el) == :error
      assert DER.octets({0x30, <<>>, <<0x30, 0>>}) == :error
    end

    test "integers" do
      for {bytes, n} <- [
            {<<0>>, 0},
            {<<0x7F>>, 127},
            {<<0, 0x80>>, 128},
            {<<0xFF>>, -1},
            {<<0x80>>, -128},
            {<<0xFF, 0x7F>>, -129}
          ] do
        assert DER.integer({0x02, bytes, <<>>}) == {:ok, n}
        assert DER.encode({:int, n}) == <<0x02, byte_size(bytes)>> <> bytes
      end

      # Not minimal, but read: serial numbers appear like this.
      assert DER.integer({0x02, <<0, 1>>, <<>>}) == {:ok, 1}
      assert DER.integer({0x02, <<>>, <<>>}) == :error
    end

    test "bit strings" do
      assert DER.bit_string({0x03, <<0, 1, 2>>, <<>>}) == {:ok, <<1, 2>>}
      assert DER.bit_string({0x03, <<1, 2>>, <<>>}) == :error

      # keyUsage with digitalSignature (0) and nonRepudiation (1)
      assert DER.named_bits({0x03, <<6, 0xC0>>, <<>>}) == {:ok, [0, 1]}
      assert DER.encode({:named_bits, [0, 1]}) == <<0x03, 2, 6, 0xC0>>
      assert DER.named_bits({0x03, <<7, 0x80>>, <<>>}) == {:ok, [0]}
      assert DER.encode({:named_bits, [0]}) == <<0x03, 2, 7, 0x80>>
      assert DER.named_bits({0x03, <<0>>, <<>>}) == {:ok, []}
      assert DER.encode({:named_bits, []}) == <<0x03, 1, 0>>
      assert DER.named_bits({0x03, <<0, 0x00, 0x80>>, <<>>}) == {:ok, [8]}
      assert DER.encode({:named_bits, [8]}) == <<0x03, 3, 7, 0x00, 0x80>>
      assert DER.named_bits({0x03, <<1>>, <<>>}) == :error
      assert DER.named_bits({0x03, <<8, 0>>, <<>>}) == :error
    end

    test "booleans and null" do
      assert DER.boolean({0x01, <<0>>, <<>>}) == {:ok, false}
      assert DER.boolean({0x01, <<0xFF>>, <<>>}) == {:ok, true}
      assert DER.boolean({0x01, <<1>>, <<>>}) == {:ok, true}
      assert DER.boolean({0x01, <<1, 1>>, <<>>}) == :error
      assert DER.null?({0x05, <<>>, <<>>})
      refute DER.null?({0x05, <<0>>, <<>>})
    end

    test "times" do
      assert {:ok, ~U[2049-12-31 23:59:59Z], :utc_time} = DER.time({0x17, "491231235959Z", <<>>})
      assert {:ok, ~U[1950-01-01 00:00:00Z], :utc_time} = DER.time({0x17, "500101000000Z", <<>>})

      assert {:ok, ~U[2050-01-01 00:00:00Z], :generalized_time} =
               DER.time({0x18, "20500101000000Z", <<>>})

      for bad <- [
            {0x17, "4912312359Z", <<>>},
            {0x17, "491231235959+0000", <<>>},
            {0x17, "491331235959Z", <<>>},
            {0x17, "4912312359-1Z", <<>>},
            {0x18, "20500101000000.5Z", <<>>},
            {0x18, "205001010000Z", <<>>},
            {0x18, "20500230000000Z", <<>>},
            {0x0C, "20500101000000Z", <<>>}
          ] do
        assert DER.time(bad) == :error, inspect(bad)
      end
    end

    test "writes UTCTime from 1950 to 2049 and GeneralizedTime outside" do
      assert DER.encode({:time, ~U[2049-12-31 23:59:59Z]}) == <<0x17, 13, "491231235959Z">>
      assert DER.encode({:time, ~U[1950-01-01 00:00:00Z]}) == <<0x17, 13, "500101000000Z">>
      assert DER.encode({:time, ~U[2050-01-01 00:00:00Z]}) == <<0x18, 15, "20500101000000Z">>
      assert DER.encode({:time, ~U[1949-12-31 23:59:59Z]}) == <<0x18, 15, "19491231235959Z">>
      # Fractions of a second are dropped.
      assert DER.encode({:time, ~U[2026-10-23 12:00:00.999Z]}) == <<0x17, 13, "261023120000Z">>
    end
  end

  describe "der?/1" do
    test "accepts DER" do
      assert DER.der?(<<0x30, 3, 0x02, 1, 0>>)
      assert DER.der?(<<0x31, 6, 0x02, 1, 1, 0x02, 1, 2>>)
      assert DER.der?(<<0x04, 0x81, 0x80>> <> :binary.copy("a", 128))
      assert DER.der?(DER.encode({:set, [{:int, 2}, {:int, 1}, {:octets, "x"}]}))
    end

    test "rejects what is only BER" do
      for bin <- [
            # indefinite length
            <<0x30, 0x80, 0, 0>>,
            # length not minimal
            <<0x04, 0x81, 1, "a">>,
            <<0x04, 0x82, 0, 0x80>> <> :binary.copy("a", 128),
            # constructed string
            <<0x24, 3, 0x04, 1, "a">>,
            # INTEGER not minimal
            <<0x02, 2, 0, 1>>,
            <<0x02, 2, 0xFF, 0x80>>,
            <<0x02, 0>>,
            # BOOLEAN true not as 0xFF
            <<0x01, 1, 1>>,
            # SET OF not sorted
            <<0x31, 6, 0x02, 1, 2, 0x02, 1, 1>>,
            # not DER inside
            <<0x30, 3, 0x01, 1, 1>>,
            # trailing data
            <<0x05, 0, 0>>
          ] do
        refute DER.der?(bin), inspect(bin)
      end
    end
  end

  describe "encode/1" do
    test "the term language" do
      assert DER.encode({:seq, [{:int, 1}, :null, {:bool, true}, {:bool, false}]}) ==
               <<0x30, 11, 0x02, 1, 1, 0x05, 0, 0x01, 1, 0xFF, 0x01, 1, 0>>

      assert DER.encode({:oid, :data}) == <<0x06, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 7, 1>>
      assert DER.encode({:explicit, 0, {:int, 5}}) == <<0xA0, 3, 0x02, 1, 5>>
      assert DER.encode({:implicit, 1, {:octets, "ab"}}) == <<0x81, 2, "ab">>
      assert DER.encode({:implicit, 0, {:set, [{:int, 5}]}}) == <<0xA0, 3, 0x02, 1, 5>>
      assert DER.encode({:constructed, 0xA3, [{:int, 5}]}) == <<0xA3, 3, 0x02, 1, 5>>
      assert DER.encode({:primitive, 0x82, "x"}) == <<0x82, 1, "x">>
      assert DER.encode({:raw, [<<0x05>>, <<0>>]}) == <<0x05, 0>>
      assert DER.encode({:utf8, "São"}) == <<0x0C, 4, "São">>
      assert DER.encode({:printable, "A"}) == <<0x13, 1, "A">>
      assert DER.encode({:ia5, "a@b"}) == <<0x16, 3, "a@b">>
      assert DER.encode({:bits, <<1>>}) == <<0x03, 2, 0, 1>>
      assert DER.retag(<<0xA0, 0>>, 0x31) == <<0x31, 0>>
    end

    test "sorts SET OF by encoding" do
      # The shorter encoding first when it is a prefix of the longer one.
      assert DER.encode({:set, [{:octets, "ab"}, {:octets, "a"}, {:int, 1}]}) ==
               <<0x31, 10, 0x02, 1, 1, 0x04, 1, "a", 0x04, 2, "ab">>
    end

    test "long lengths" do
      big = :binary.copy("a", 70_000)
      assert <<0x04, 0x83, 70_000::24, ^big::binary>> = DER.encode({:octets, big})
      assert DER.encode_length(127) == <<127>>
      assert DER.encode_length(128) == <<0x81, 128>>
      assert DER.encode_length(256) == <<0x82, 1, 0>>
    end
  end

  describe "properties" do
    property "integers round-trip in minimal form" do
      check all n <- one_of([integer(), integer(-(2 ** 200)..(2 ** 200))]) do
        der = DER.encode({:int, n})
        assert {:ok, el} = DER.decode(der)
        assert DER.integer(el) == {:ok, n}
        assert DER.der?(der)
      end
    end

    property "what encode/1 writes is DER and reads back" do
      check all term <- der_term() do
        der = DER.encode(term)
        assert DER.der?(der)
        assert {:ok, {_, _, ^der}} = DER.decode(der)
      end
    end

    property "segmented OCTET STRINGs join to the same value" do
      check all parts <- list_of(binary(max_length: 20), max_length: 10) do
        segments = Enum.map(parts, &DER.encode({:octets, &1}))

        definite =
          <<0x24>> <>
            DER.encode_length(IO.iodata_length(segments)) <> IO.iodata_to_binary(segments)

        indefinite = IO.iodata_to_binary([0x24, 0x80, segments, 0, 0])
        value = IO.iodata_to_binary(parts)

        for bin <- [definite, indefinite] do
          assert {:ok, el} = DER.decode(bin)
          assert DER.octets(el) == {:ok, value}
        end
      end
    end

    property "decode/2 never raises on random input" do
      check all bin <- binary(max_length: 64) do
        case DER.decode(bin) do
          {:ok, el} -> walk(el)
          {:error, _} -> :ok
        end
      end
    end
  end

  defp walk(el), do: Enum.each(DER.children(el), &walk/1)

  defp der_term do
    leaf =
      one_of([
        map(integer(), &{:int, &1}),
        map(binary(max_length: 200), &{:octets, &1}),
        map(boolean(), &{:bool, &1}),
        constant(:null),
        map(string(:alphanumeric, max_length: 10), &{:utf8, &1}),
        map(list_of(integer(0..20), max_length: 5), &{:named_bits, Enum.uniq(&1)})
      ])

    tree(leaf, fn child ->
      one_of([
        map(list_of(child, max_length: 5), &{:seq, &1}),
        map(list_of(child, max_length: 5), &{:set, &1}),
        map(child, &{:explicit, 2, &1})
      ])
    end)
  end
end
