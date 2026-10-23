defmodule Cmsex.DER do
  @moduledoc false
  # A BER/DER reader and a DER writer.
  #
  # An element is `{id, content, raw}`:
  #
  #   * `id` is the identifier octet for tag numbers up to 30 (0x30 for a
  #     SEQUENCE, 0xA0 for a constructed [0]), or `{octet, number}` for higher
  #     tag numbers, where `octet` keeps the class and constructed bits;
  #   * `content` is the content octets. For an element of indefinite length
  #     it stops before the end-of-contents octets;
  #   * `raw` is the whole element: identifier, length, content and, for an
  #     indefinite length, the end-of-contents octets.
  #
  # `content` and `raw` are sub-binaries of the input, so reading copies
  # nothing. `decode/2` checks the whole structure once (lengths, nesting and
  # the number of elements) without building it; `children/1` then reads one
  # level on demand. The memory used is the input plus what the caller walks
  # through, whatever the input claims.

  import Bitwise

  @type id :: byte() | {byte(), pos_integer()}
  @type element :: {id(), binary(), binary()}

  @default_max_depth 32
  @default_max_elements 100_000

  ## Reading

  @doc """
  Reads one element that spans the whole binary and checks its structure.

  Options: `:max_depth` (32) and `:max_elements` (100,000), the total number
  of elements at all levels.
  """
  @spec decode(binary(), keyword()) ::
          {:ok, element()}
          | {:error, :malformed | {:limit_exceeded, :max_depth | :max_elements}}
  def decode(bin, opts \\ []) when is_binary(bin) do
    limits = {
      Keyword.get(opts, :max_depth, @default_max_depth),
      Keyword.get(opts, :max_elements, @default_max_elements)
    }

    case scan(bin, 1, 0, limits) do
      {:ok, element, <<>>, _count} -> {:ok, element}
      {:ok, _element, _rest, _count} -> {:error, :malformed}
      {:error, _} = error -> error
    end
  end

  @doc """
  The elements inside a constructed element, in order, or `[]` for a
  primitive one. The element must come from `decode/2`, which checked it.
  """
  @spec children(element()) :: [element()]
  def children({id, content, _raw}) do
    if constructed?(id), do: read_all(content, []), else: []
  end

  @doc "Whether an identifier is of the constructed form."
  @spec constructed?(id()) :: boolean()
  def constructed?({octet, _number}), do: (octet &&& 0x20) != 0
  def constructed?(octet), do: (octet &&& 0x20) != 0

  # The checks of `scan/4` already passed, so this only finds the boundaries:
  # a definite length gives them at once, and only an indefinite length makes
  # the reader walk its elements to find the end.
  defp read_all(<<>>, acc), do: Enum.reverse(acc)

  defp read_all(bin, acc) do
    {element, rest} = read(bin)
    read_all(rest, [element | acc])
  end

  defp read(bin) do
    {:ok, id, after_id} = read_id(bin)
    {:ok, length, after_length} = read_length(after_id)
    header_size = byte_size(bin) - byte_size(after_length)

    {content_size, trailer} =
      case length do
        {:definite, len} -> {len, 0}
        :indefinite -> {eoc_offset(after_length, 0), 2}
      end

    raw_size = header_size + content_size + trailer
    content = binary_part(after_length, 0, content_size)
    raw = binary_part(bin, 0, raw_size)
    {{id, content, raw}, binary_part(bin, raw_size, byte_size(bin) - raw_size)}
  end

  defp eoc_offset(<<0, 0, _::binary>>, offset), do: offset

  defp eoc_offset(bin, offset) do
    {{_, _, raw}, rest} = read(bin)
    eoc_offset(rest, offset + byte_size(raw))
  end

  # Checks the element at the start of `bin`; returns it and what follows.
  defp scan(_bin, depth, _count, {max_depth, _}) when depth > max_depth,
    do: {:error, {:limit_exceeded, :max_depth}}

  defp scan(_bin, _depth, count, {_, max_elements}) when count >= max_elements,
    do: {:error, {:limit_exceeded, :max_elements}}

  defp scan(bin, depth, count, limits) do
    with {:ok, id, after_id} <- read_id(bin),
         {:ok, length, after_length} <- read_length(after_id) do
      header_size = byte_size(bin) - byte_size(after_length)
      scan_body(bin, id, length, after_length, header_size, depth, count + 1, limits)
    end
  end

  defp scan_body(bin, id, {:definite, len}, rest, header_size, depth, count, limits)
       when byte_size(rest) >= len do
    content = binary_part(rest, 0, len)
    after_element = binary_part(rest, len, byte_size(rest) - len)
    raw = binary_part(bin, 0, header_size + len)

    if constructed?(id) do
      with {:ok, count} <- scan_contents(content, depth + 1, count, limits),
           do: {:ok, {id, content, raw}, after_element, count}
    else
      {:ok, {id, content, raw}, after_element, count}
    end
  end

  defp scan_body(_bin, _id, {:definite, _len}, _rest, _header, _depth, _count, _limits),
    do: {:error, :malformed}

  defp scan_body(bin, id, :indefinite, rest, header_size, depth, count, limits) do
    if constructed?(id) do
      with {:ok, size, count} <- scan_until_eoc(rest, 0, depth + 1, count, limits) do
        content = binary_part(rest, 0, size)
        raw = binary_part(bin, 0, header_size + size + 2)
        after_element = binary_part(rest, size + 2, byte_size(rest) - size - 2)
        {:ok, {id, content, raw}, after_element, count}
      end
    else
      {:error, :malformed}
    end
  end

  defp scan_contents(<<>>, _depth, count, _limits), do: {:ok, count}

  defp scan_contents(bin, depth, count, limits) do
    with {:ok, _element, rest, count} <- scan(bin, depth, count, limits),
         do: scan_contents(rest, depth, count, limits)
  end

  defp scan_until_eoc(<<0, 0, _::binary>>, size, _depth, count, _limits), do: {:ok, size, count}

  defp scan_until_eoc(bin, size, depth, count, limits) when byte_size(bin) >= 2 do
    with {:ok, {_, _, raw}, rest, count} <- scan(bin, depth, count, limits),
         do: scan_until_eoc(rest, size + byte_size(raw), depth, count, limits)
  end

  defp scan_until_eoc(_bin, _size, _depth, _count, _limits), do: {:error, :malformed}

  # Tag 0 of the universal class is reserved for the end-of-contents marker.
  defp read_id(<<octet, _::binary>>) when (octet &&& 0xDF) == 0, do: {:error, :malformed}
  defp read_id(<<octet, rest::binary>>) when (octet &&& 0x1F) != 0x1F, do: {:ok, octet, rest}
  defp read_id(<<octet, rest::binary>>), do: read_high_tag(rest, octet, 0, 0)
  defp read_id(<<>>), do: {:error, :malformed}

  # X.690 8.1.2.4: base 128, no leading 0x80, and a number above 30. Five
  # octets hold any tag number that fits in 32 bits.
  defp read_high_tag(<<0x80, _::binary>>, _octet, 0, 0), do: {:error, :malformed}

  defp read_high_tag(<<1::1, bits::7, rest::binary>>, octet, n, size) when size < 4,
    do: read_high_tag(rest, octet, n <<< 7 ||| bits, size + 1)

  defp read_high_tag(<<0::1, bits::7, rest::binary>>, octet, n, _size) do
    number = n <<< 7 ||| bits
    if number > 30, do: {:ok, {octet &&& 0xE0, number}, rest}, else: {:error, :malformed}
  end

  defp read_high_tag(_bin, _octet, _n, _size), do: {:error, :malformed}

  defp read_length(<<0x80, rest::binary>>), do: {:ok, :indefinite, rest}
  defp read_length(<<len, rest::binary>>) when len < 0x80, do: {:ok, {:definite, len}, rest}

  defp read_length(<<n, rest::binary>>) when n in 0x81..0x84 and byte_size(rest) >= n - 0x80 do
    size = n - 0x80
    <<len::unsigned-size(size)-unit(8), rest::binary>> = rest
    {:ok, {:definite, len}, rest}
  end

  defp read_length(_bin), do: {:error, :malformed}

  ## Values

  @doc """
  The value of a string type, primitive or, in BER, constructed from
  segments. `primitive_id` is the identifier of the primitive form: `0x04`
  for an OCTET STRING, or the implicit tag that replaces it, such as `0x80`.
  The segments of a constructed string are universal strings of the type
  (X.690 8.7.3.2), `segment_id` in the primitive form, themselves primitive
  or constructed.
  """
  @spec string(element(), byte(), byte()) :: {:ok, binary()} | :error
  def string(element, primitive_id, segment_id \\ 0x04)

  def string({id, content, _raw}, id, _segment_id) when is_integer(id), do: {:ok, content}

  def string({id, _content, _raw} = element, primitive_id, segment_id)
      when is_integer(id) and id == (primitive_id ||| 0x20) do
    with {:ok, parts} <- join(children(element), segment_id, []),
         do: {:ok, IO.iodata_to_binary(parts)}
  end

  def string(_element, _primitive_id, _segment_id), do: :error

  defp join([], _segment_id, acc), do: {:ok, Enum.reverse(acc)}
  defp join([{id, content, _} | rest], id, acc), do: join(rest, id, [content | acc])

  defp join([{constructed, _, _} = element | rest], id, acc) when constructed == (id ||| 0x20) do
    with {:ok, parts} <- join(children(element), id, []), do: join(rest, id, [parts | acc])
  end

  defp join(_elements, _id, _acc), do: :error

  @doc "An OCTET STRING, primitive or segmented."
  @spec octets(element()) :: {:ok, binary()} | :error
  def octets(element), do: string(element, 0x04)

  @doc "An INTEGER, in two's complement (X.690 8.3)."
  @spec integer(element()) :: {:ok, integer()} | :error
  def integer({0x02, <<_, _::binary>> = bytes, _raw}) do
    size = bit_size(bytes)
    <<n::signed-size(size)>> = bytes
    {:ok, n}
  end

  def integer(_element), do: :error

  @doc "An OBJECT IDENTIFIER, as a tuple."
  @spec oid(element()) :: {:ok, tuple()} | :error
  def oid({0x06, content, _raw}), do: Cmsex.OID.decode(content)
  def oid(_element), do: :error

  @doc "A BIT STRING with no unused bits."
  @spec bit_string(element()) :: {:ok, binary()} | :error
  def bit_string({0x03, <<0, bytes::binary>>, _raw}), do: {:ok, bytes}
  def bit_string(_element), do: :error

  @doc """
  A BIT STRING as named bits: the positions of the bits that are set, from
  0, as in the keyUsage extension.
  """
  @spec named_bits(element()) :: {:ok, [non_neg_integer()]} | :error
  def named_bits({0x03, <<unused, bytes::binary>>, _raw})
      when unused < 8 and (bytes != <<>> or unused == 0) do
    used = bit_size(bytes) - unused
    <<bits::bitstring-size(used), _::bitstring>> = bytes
    {:ok, for({1, i} <- Enum.with_index(for(<<bit::1 <- bits>>, do: bit)), do: i)}
  end

  def named_bits(_element), do: :error

  @doc "Whether an element is a NULL."
  @spec null?(element()) :: boolean()
  def null?({0x05, <<>>, _raw}), do: true
  def null?(_element), do: false

  @doc "A BOOLEAN; BER takes any octet other than 0 as true."
  @spec boolean(element()) :: {:ok, boolean()} | :error
  def boolean({0x01, <<0>>, _raw}), do: {:ok, false}
  def boolean({0x01, <<_>>, _raw}), do: {:ok, true}
  def boolean(_element), do: :error

  @doc """
  A UTCTime or a GeneralizedTime in the form RFC 5280 and RFC 5652 require:
  in UTC (`Z`), with seconds, without fractions.
  """
  @spec time(element()) :: {:ok, DateTime.t(), :utc_time | :generalized_time} | :error
  def time({0x17, <<yy::binary-size(2), rest::binary-size(10), "Z">>, _raw}) do
    century = if yy >= "50", do: "19", else: "20"

    case parse_time(century <> yy <> rest) do
      {:ok, dt} -> {:ok, dt, :utc_time}
      :error -> :error
    end
  end

  def time({0x18, <<digits::binary-size(14), "Z">>, _raw}) do
    case parse_time(digits) do
      {:ok, dt} -> {:ok, dt, :generalized_time}
      :error -> :error
    end
  end

  def time(_element), do: :error

  defp parse_time(digits) do
    with true <- digits?(digits),
         <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
           minute::binary-size(2), second::binary-size(2)>> <- digits,
         {:ok, date} <- Date.new(int(year), int(month), int(day)),
         {:ok, time} <- Time.new(int(hour), int(minute), int(second)),
         {:ok, dt} <- DateTime.new(date, time, "Etc/UTC") do
      {:ok, dt}
    else
      _ -> :error
    end
  end

  defp digits?(bin), do: for(<<c <- bin>>, reduce: true, do: (ok -> ok and c in ?0..?9))
  defp int(bin), do: String.to_integer(bin)

  ## Strict DER

  # Universal string types that DER requires in the primitive form.
  @strings [0x03, 0x04, 0x0C, 0x12, 0x13, 0x14, 0x15, 0x16, 0x19, 0x1A, 0x1B, 0x1C, 0x1E]
  @constructed_strings Enum.map(@strings, &(&1 ||| 0x20))

  @doc """
  Whether the encoding of one element is DER: definite and minimal lengths,
  primitive strings, minimal INTEGERs, BOOLEAN as 0x00 or 0xFF, and the
  elements of each universal SET in ascending order (X.690 10 and 11).
  """
  @spec der?(binary()) :: boolean()
  def der?(raw) when is_binary(raw), do: strict(raw) == {:ok, <<>>}

  defp strict(bin) do
    with {:ok, id, after_id} <- read_id(bin),
         {:ok, {:definite, len}, rest} <- read_length(after_id),
         true <- minimal_length?(after_id, len),
         true <- byte_size(rest) >= len,
         true <- strict_content?(id, binary_part(rest, 0, len)) do
      {:ok, binary_part(rest, len, byte_size(rest) - len)}
    else
      _ -> :error
    end
  end

  defp minimal_length?(<<first, _::binary>>, len) when len < 0x80, do: first == len

  defp minimal_length?(<<first, _::binary>>, len),
    do: first == 0x80 + byte_size(:binary.encode_unsigned(len))

  defp strict_content?(id, _content) when id in @constructed_strings, do: false
  defp strict_content?(0x01, content), do: content in [<<0>>, <<0xFF>>]
  defp strict_content?(0x02, <<0, second, _::binary>>) when second < 0x80, do: false
  defp strict_content?(0x02, <<0xFF, second, _::binary>>) when second >= 0x80, do: false
  defp strict_content?(0x02, content), do: content != <<>>

  defp strict_content?(0x31, content) do
    case strict_list(content, []) do
      {:ok, raws} -> raws == Enum.sort(raws)
      :error -> false
    end
  end

  defp strict_content?(id, content) do
    if constructed?(id), do: match?({:ok, _}, strict_list(content, [])), else: true
  end

  defp strict_list(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp strict_list(bin, acc) do
    case strict(bin) do
      {:ok, rest} ->
        strict_list(rest, [binary_part(bin, 0, byte_size(bin) - byte_size(rest)) | acc])

      :error ->
        :error
    end
  end

  ## Writing

  @typedoc "What `encode/1` writes. A `{:set, list}` is sorted as DER requires."
  @type term_ ::
          {:seq, [term_()]}
          | {:set, [term_()]}
          | {:int, integer()}
          | {:oid, tuple() | atom()}
          | {:octets, iodata()}
          | {:bits, binary()}
          | {:named_bits, [non_neg_integer()]}
          | :null
          | {:bool, boolean()}
          | {:utf8, String.t()}
          | {:printable, String.t()}
          | {:ia5, String.t()}
          | {:utc_time, DateTime.t()}
          | {:generalized_time, DateTime.t()}
          | {:time, DateTime.t()}
          | {:explicit, 0..30, term_()}
          | {:implicit, 0..30, term_()}
          | {:constructed, byte(), [term_()]}
          | {:primitive, byte(), iodata()}
          | {:raw, iodata()}

  @doc "Encodes a term in DER."
  @spec encode(term_()) :: binary()
  def encode(term), do: term |> to_iodata() |> IO.iodata_to_binary()

  @doc "Encodes a term in DER, as iodata."
  @spec to_iodata(term_()) :: iodata()
  def to_iodata({:seq, items}), do: tlv(0x30, Enum.map(items, &to_iodata/1))
  def to_iodata({:set, items}), do: tlv(0x31, items |> Enum.map(&encode/1) |> Enum.sort())
  def to_iodata({:int, n}) when is_integer(n), do: tlv(0x02, integer_octets(n))
  def to_iodata({:oid, oid}), do: tlv(0x06, Cmsex.OID.encode(oid))
  def to_iodata({:octets, bytes}), do: tlv(0x04, bytes)
  def to_iodata({:bits, bytes}) when is_binary(bytes), do: tlv(0x03, [0, bytes])
  def to_iodata({:named_bits, positions}), do: tlv(0x03, named_bits_octets(positions))
  def to_iodata(:null), do: <<0x05, 0>>
  def to_iodata({:bool, true}), do: <<0x01, 1, 0xFF>>
  def to_iodata({:bool, false}), do: <<0x01, 1, 0>>
  def to_iodata({:utf8, s}) when is_binary(s), do: tlv(0x0C, s)
  def to_iodata({:printable, s}) when is_binary(s), do: tlv(0x13, s)
  def to_iodata({:ia5, s}) when is_binary(s), do: tlv(0x16, s)

  def to_iodata({:utc_time, %DateTime{} = dt}) do
    <<_century::binary-size(2), digits::binary>> = utc_digits(dt)
    tlv(0x17, [digits, ?Z])
  end

  def to_iodata({:generalized_time, %DateTime{} = dt}), do: tlv(0x18, [utc_digits(dt), ?Z])

  # RFC 5652 11.3 and RFC 5280 4.1.2.5: UTCTime from 1950 to 2049,
  # GeneralizedTime outside that range.
  def to_iodata({:time, %DateTime{} = dt}) do
    utc = DateTime.shift_zone!(dt, "Etc/UTC")

    if utc.year in 1950..2049,
      do: to_iodata({:utc_time, utc}),
      else: to_iodata({:generalized_time, utc})
  end

  def to_iodata({:explicit, n, term}) when n in 0..30, do: tlv(0xA0 + n, to_iodata(term))

  def to_iodata({:implicit, n, term}) when n in 0..30 do
    <<id, rest::binary>> = encode(term)
    [(id &&& 0x20) ||| 0x80 ||| n, rest]
  end

  def to_iodata({:constructed, id, items}), do: tlv(id, Enum.map(items, &to_iodata/1))
  def to_iodata({:primitive, id, content}), do: tlv(id, content)
  def to_iodata({:raw, der}), do: der

  defp tlv(id, content), do: [id, encode_length(IO.iodata_length(content)), content]

  @doc "The DER length octets."
  @spec encode_length(non_neg_integer()) :: binary()
  def encode_length(len) when len < 0x80, do: <<len>>

  def encode_length(len) do
    bytes = :binary.encode_unsigned(len)
    <<0x80 + byte_size(bytes), bytes::binary>>
  end

  @doc "Replaces the identifier octet of an encoded element."
  @spec retag(binary(), byte()) :: binary()
  def retag(<<_id, rest::binary>>, id), do: <<id, rest::binary>>

  defp integer_octets(n) when n >= 0 do
    bytes = :binary.encode_unsigned(n)
    if :binary.first(bytes) >= 0x80, do: <<0, bytes::binary>>, else: bytes
  end

  # A negative n fits in the bytes of -n - 1 plus a sign bit.
  defp integer_octets(n) do
    bytes = :binary.encode_unsigned(-n - 1)
    size = if :binary.first(bytes) >= 0x80, do: byte_size(bytes) + 1, else: byte_size(bytes)
    <<n::signed-size(size)-unit(8)>>
  end

  # X.690 11.2.2: named bits without the trailing zero bits.
  defp named_bits_octets([]), do: <<0>>

  defp named_bits_octets(positions) do
    size = Enum.max(positions) + 1
    value = Enum.reduce(positions, 0, fn i, acc -> acc ||| 1 <<< (size - 1 - i) end)
    padding = rem(8 - rem(size, 8), 8)
    <<padding, value::size(size), 0::size(padding)>>
  end

  defp utc_digits(dt) do
    dt = DateTime.shift_zone!(dt, "Etc/UTC")

    [{dt.year, 4}, {dt.month, 2}, {dt.day, 2}, {dt.hour, 2}, {dt.minute, 2}, {dt.second, 2}]
    |> Enum.map_join(fn {value, width} ->
      value |> Integer.to_string() |> String.pad_leading(width, "0")
    end)
  end
end
