defmodule Cmsex.TestFuzz do
  @moduledoc false
  # Inputs for the robustness tests: the messages of the fixtures, signed
  # and encrypted, changed
  # by a few random edits, and random bytes, alone or behind the header of
  # a SignedData, so that they get past the first checks. Every public
  # function that reads or changes a message must return `{:ok, _}` or
  # `{:error, %Cmsex.Error{}}` for any of them, and never raise.

  use ExUnitProperties

  import Bitwise

  alias Cmsex.{DER, EncryptedFixtures, TestFixtures}

  @rfc4134 Path.expand("../fixtures/rfc4134", __DIR__)

  @doc "The messages to start from, by name."
  def corpus do
    generated =
      for name <- TestFixtures.messages(), do: {name, TestFixtures.read!(name)}

    encrypted =
      for name <- EncryptedFixtures.messages(),
          do: {"encrypted/" <> name, EncryptedFixtures.read!(name)}

    rfc4134 =
      for path <- Path.wildcard(Path.join(@rfc4134, "*.bin")),
          do: {"rfc4134/" <> Path.basename(path), File.read!(path)}

    generated ++ encrypted ++ rfc4134
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
  Runs every reader, and every function that changes a message, on
  `input`, and returns the results that are neither `{:ok, _}` nor
  `{:error, %Cmsex.Error{}}`, with the function. An exception is caught
  and returned as such.
  """
  def bad_results(input, roots) do
    opts = [trust: roots, allow_sha1: true, min_rsa_bits: 1024, countersignatures: true]

    [
      decode: fn -> Cmsex.decode(input) end,
      certificates: fn -> Cmsex.certificates(input) end,
      verify: fn -> Cmsex.verify(input, opts) end,
      verify_any: fn -> Cmsex.verify(input, [signers: :any] ++ opts) end,
      verify_detached: fn -> Cmsex.verify(input, content: TestFixtures.content()) end,
      verify_each: fn -> Cmsex.verify_each(input, opts) end,
      verify_digest: fn -> Cmsex.verify_digest(input, allow_sha1: true) end,
      verify_digest_detached: fn -> Cmsex.verify_digest(input, content: "x") end
    ]
    |> Kernel.++(secrets(input))
    |> Kernel.++(changes(input))
    |> Enum.flat_map(fn {name, fun} ->
      case run(fun) do
        :ok -> []
        bad -> [{name, bad}]
      end
    end)
  end

  # Decryption and MACs with each kind of credentials of the encrypted
  # fixtures, with few iterations of PBKDF2 so that a changed count stays
  # quick.
  defp secrets(input) do
    limits = [max_iterations: 4096]

    credentials = [
      rsa: EncryptedFixtures.credentials("rsa2048"),
      ec: EncryptedFixtures.credentials("p256"),
      x25519: EncryptedFixtures.credentials("x25519"),
      kek: [kek: {EncryptedFixtures.kek_id(), EncryptedFixtures.secret(16)}],
      password: [password: EncryptedFixtures.password()],
      content_key: [content_key: EncryptedFixtures.secret(16)]
    ]

    for {name, opts} <- credentials, function <- [:decrypt, :verify_mac] do
      # verify_mac/2 takes the key itself as :mac_key.
      opts =
        if function == :verify_mac and name == :content_key,
          do: [mac_key: EncryptedFixtures.secret(16)],
          else: opts

      {:"#{function}_#{name}", fn -> apply(Cmsex, function, [input, opts ++ limits]) end}
    end
  end

  # The functions that change a message. A position that the message does
  # not have raises ArgumentError, so they go only to the first signer of
  # a message that has one.
  defp changes(input) do
    signer = %Cmsex.Signer{certificate: TestFixtures.cert("p256"), key: TestFixtures.key("p256")}
    attribute = Cmsex.Attribute.new({1, 3, 6, 1, 4, 1, 32_473, 3}, [DER.encode(:null)])
    added = [add_signer: fn -> Cmsex.add_signer(input, signer) end]

    case Cmsex.decode(input) do
      {:ok, %{signer_infos: [_ | _]}} ->
        added ++
          [
            countersign: fn -> Cmsex.countersign(input, 0, signer) end,
            add_unsigned_attribute: fn -> Cmsex.add_unsigned_attribute(input, 0, attribute) end
          ]

      _ ->
        added
    end
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
