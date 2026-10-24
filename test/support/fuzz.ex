defmodule Cmsex.TestFuzz do
  @moduledoc false
  # Inputs for the robustness tests: the messages of the fixtures, changed
  # by a few random edits, and random bytes, alone or behind the header of
  # a SignedData, so that they get past the first checks. Every public
  # function that reads a message must return `{:ok, _}` or
  # `{:error, %Cmsex.Error{}}` for any of them, and never raise.

  use ExUnitProperties

  import Bitwise

  alias Cmsex.{DER, TestFixtures}

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)

  @doc "The messages to start from, by name."
  def corpus do
    generated =
      for name <- TestFixtures.messages(), do: {name, TestFixtures.read!(name)}

    rfc4134 =
      for path <- Path.wildcard(Path.join(@rfc4134, "*.bin")),
          do: {"rfc4134/" <> Path.basename(path), File.read!(path)}

    generated ++ rfc4134
  end

  @doc "A message of the corpus with one to eight edits."
  def mutated(corpus) do
    gen all {name, bin} <- member_of(corpus),
            edits <- list_of(edit(), min_length: 1, max_length: 8) do
      {name, edits, apply_edits(bin, edits)}
    end
  end

  @doc "Random bytes, or random bytes inside a ContentInfo of id-signedData."
  def random do
    one_of([
      binary(max_length: 2048),
      map(binary(max_length: 2048), &signed_data_header/1),
      map(list_of(binary(max_length: 64), max_length: 20), &nested/1)
    ])
  end

  # Bytes that mean something in BER: lengths, tags, end-of-contents.
  @interesting [
    0x00,
    0x01,
    0x02,
    0x04,
    0x06,
    0x30,
    0x31,
    0x7F,
    0x80,
    0x81,
    0x82,
    0x84,
    0xA0,
    0xFF
  ]

  defp edit do
    position = integer(0..(1 <<< 32))
    byte = one_of([integer(0..255), member_of(@interesting)])

    one_of([
      tuple({constant(:flip), position, integer(1..255)}),
      tuple({constant(:set), position, byte}),
      tuple({constant(:truncate), position}),
      tuple({constant(:insert), position, binary(min_length: 1, max_length: 8)}),
      tuple({constant(:delete), position, integer(1..64)}),
      tuple({constant(:duplicate), position, integer(1..64)})
    ])
  end

  @doc "Applies the edits of `mutated/1` in order."
  def apply_edits(bin, edits), do: Enum.reduce(edits, bin, &edit/2)

  defp edit({:insert, position, bytes}, bin) do
    {head, tail} = split(bin, rem(position, byte_size(bin) + 1))
    head <> bytes <> tail
  end

  defp edit({:truncate, position}, bin),
    do: binary_part(bin, 0, rem(position, byte_size(bin) + 1))

  defp edit(_edit, <<>>), do: <<>>

  defp edit({:flip, position, mask}, bin) do
    {head, <<byte, tail::binary>>} = split(bin, rem(position, byte_size(bin)))
    <<head::binary, bxor(byte, mask), tail::binary>>
  end

  defp edit({:set, position, value}, bin) do
    {head, <<_byte, tail::binary>>} = split(bin, rem(position, byte_size(bin)))
    <<head::binary, value, tail::binary>>
  end

  defp edit({:delete, position, size}, bin) do
    at = rem(position, byte_size(bin))
    {head, tail} = split(bin, at)

    head <>
      binary_part(tail, min(size, byte_size(tail)), byte_size(tail) - min(size, byte_size(tail)))
  end

  defp edit({:duplicate, position, size}, bin) do
    at = rem(position, byte_size(bin))
    slice = binary_part(bin, at, min(size, byte_size(bin) - at))
    {head, tail} = split(bin, at)

    head <>
      slice <> slice <> binary_part(tail, byte_size(slice), byte_size(tail) - byte_size(slice))
  end

  defp split(bin, at), do: {binary_part(bin, 0, at), binary_part(bin, at, byte_size(bin) - at)}

  defp signed_data_header(bytes),
    do: DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, {:raw, bytes}}]})

  # Random pieces as the fields of a SignedData, each in a SEQUENCE.
  defp nested(pieces) do
    fields = [{:int, 1} | Enum.map(pieces, &{:seq, [{:raw, &1}]})]
    DER.encode({:seq, [{:oid, :signed_data}, {:explicit, 0, {:seq, fields}}]})
  end

  @doc """
  Runs every reader on `input`, and returns the results that are neither
  `{:ok, _}` nor `{:error, %Cmsex.Error{}}`, with the function. An
  exception is caught and returned as such.
  """
  def bad_results(input, roots) do
    opts = [trust: roots, allow_sha1: true, min_rsa_bits: 1024, countersignatures: true]

    [
      decode: fn -> Cmsex.decode(input) end,
      certificates: fn -> Cmsex.certificates(input) end,
      verify: fn -> Cmsex.verify(input, opts) end,
      verify_any: fn -> Cmsex.verify(input, [signers: :any] ++ opts) end,
      verify_detached: fn -> Cmsex.verify(input, content: TestFixtures.content()) end,
      verify_each: fn -> Cmsex.verify_each(input, opts) end
    ]
    |> Enum.flat_map(fn {name, fun} ->
      case run(fun) do
        :ok -> []
        bad -> [{name, bad}]
      end
    end)
  end

  defp run(fun) do
    case fun.() do
      {:ok, _} -> :ok
      {:ok, _, _} -> :ok
      {:error, %Cmsex.Error{}} -> :ok
      other -> {:returned, other}
    end
  rescue
    exception -> {:raised, exception, __STACKTRACE__}
  catch
    kind, value -> {kind, value}
  end
end
