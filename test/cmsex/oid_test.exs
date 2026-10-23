defmodule Cmsex.OIDTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Cmsex.OID

  doctest Cmsex.OID

  test "encodes and decodes the content octets" do
    # X.690 8.19.5: 2.100.3 is encoded as 0x81 0x34 0x03.
    assert OID.encode({2, 100, 3}) == <<0x81, 0x34, 0x03>>
    assert OID.decode(<<0x81, 0x34, 0x03>>) == {:ok, {2, 100, 3}}
    assert OID.encode(:sha256) == <<0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1>>

    assert OID.decode(<<0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 7, 2>>) ==
             {:ok, OID.oid(:signed_data)}

    assert OID.decode(<<0>>) == {:ok, {0, 0}}
    assert OID.decode(<<40>>) == {:ok, {1, 0}}
    assert OID.decode(<<79>>) == {:ok, {1, 39}}
    assert OID.decode(<<80>>) == {:ok, {2, 0}}
  end

  test "rejects bad content octets" do
    assert OID.decode(<<>>) == :error
    # padding at the start of a subidentifier
    assert OID.decode(<<0x2A, 0x80, 0x01>>) == :error
    assert OID.decode(<<0x80, 0x01>>) == :error
    # last subidentifier not finished
    assert OID.decode(<<0x2A, 0x86>>) == :error
  end

  test "refuses to write an invalid OID" do
    for bad <- [{3, 1}, {1, 40}, {0, 40}, {1, -1}, {1, 2, -3}] do
      assert_raise ArgumentError, fn -> OID.encode(bad) end
    end

    assert_raise ArgumentError, fn -> OID.oid(:no_such_name) end
  end

  test "names and OIDs are one to one" do
    {:docs_v1, _, _, _, %{"en" => doc}, _, _} = Code.fetch_docs(Cmsex.OID)
    rows = Regex.scan(~r/^\| `:(\w+)` \| ([\d.]+) \|$/m, doc)
    assert length(rows) > 100

    oids =
      for [_, name, dotted] <- rows do
        name = String.to_existing_atom(name)
        assert OID.dotted(name) == dotted
        assert OID.name(OID.oid(name)) == name
        OID.oid(name)
      end

    assert length(Enum.uniq(oids)) == length(oids)
  end

  test "unknown OIDs stay tuples" do
    assert OID.name({1, 2, 3, 4}) == {1, 2, 3, 4}
    assert OID.dotted({1, 2, 3, 4}) == "1.2.3.4"
  end

  property "round-trips any OID" do
    check all first <- integer(0..2),
              second <- if(first == 2, do: integer(0..10_000), else: integer(0..39)),
              rest <- list_of(one_of([integer(0..200), integer(0..(2 ** 70))]), max_length: 10) do
      oid = List.to_tuple([first, second | rest])
      assert OID.decode(OID.encode(oid)) == {:ok, oid}
    end
  end
end
