defmodule Cmsex.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise
  import Cmsex.TestFixtures

  alias Cmsex.{Attribute, DER, Error, Signer, TestFuzz}

  # The keys and certificates of the fixtures, made by OpenSSL.
  @keys ~w(rsa2048 rsa3072 rsapss p256 p384 p521 ed25519 ed448)
  @rsa ~w(rsa2048 rsa3072)

  # An arc of RFC 5612, for documentation.
  @arc [1, 3, 6, 1, 4, 1, 32_473]

  ## Generators

  # Content of up to 64 KiB, from a seed, so that a failure repeats.
  defp bytes do
    one_of([
      binary(max_length: 64),
      gen all size <- integer(0..65_536), seed <- integer() do
        {bytes, _} = :rand.bytes_s(size, :rand.seed_s(:exsss, seed))
        bytes
      end
    ])
  end

  defp time do
    map(integer(-631_152_000..4_102_444_800), &DateTime.from_unix!/1)
  end

  defp attributes(type, max) do
    gen all numbers <- uniq_list_of(integer(1..1000), max_length: max),
            values <- list_of(string(:printable, max_length: 16), length: length(numbers)) do
      for {number, value} <- Enum.zip(numbers, values) do
        Attribute.new(List.to_tuple(@arc ++ [type, number]), [DER.encode({:utf8, value})])
      end
    end
  end

  defp signer(no_attributes?) do
    gen all name <- member_of(@keys),
            padding <- member_of([:pkcs1, :pss]),
            identifier <- member_of([:issuer_and_serial, :subject_key_identifier]),
            protection <- boolean(),
            signing_time <- one_of([constant(false), constant(true), time()]),
            signed <- attributes(1, if(no_attributes?, do: 0, else: 3)),
            unsigned <- attributes(2, 2) do
      %Signer{
        certificate: cert(name),
        key: key(name),
        rsa_padding: if(name in @rsa, do: padding),
        identifier: identifier,
        algorithm_protection: protection,
        signing_time: signing_time,
        signed_attributes: signed,
        unsigned_attributes: unsigned
      }
    end
  end

  defp message do
    gen all no_attributes <- boolean(),
            detached <- boolean(),
            signers <- list_of(signer(no_attributes), min_length: 1, max_length: 3),
            content <- bytes() do
      %{
        content: content,
        signers: signers,
        opts: [detached: detached, no_attributes: no_attributes]
      }
    end
  end

  defp sign!(%{content: content, signers: signers, opts: opts}),
    do: Cmsex.sign!(content, signers, opts)

  ## Sign, then verify

  property "what sign/3 writes, verify/2 verifies" do
    check all message <- message(), max_runs: 60 do
      der = sign!(message)
      detached = message.opts[:detached]
      content = if detached, do: [content: message.content], else: []

      assert {:ok, verified} = Cmsex.verify(der, [trust: roots()] ++ content)
      assert verified.content == if(detached, do: nil, else: message.content)
      assert verified.content_type == :data

      # The SET OF SignerInfo is sorted, so the order is that of the bytes.
      assert Enum.sort(Enum.map(verified.signers, &expected/1)) ==
               Enum.sort(Enum.map(message.signers, &expected(&1, message.opts)))

      assert Enum.map(verified.signers, & &1.index) ==
               Enum.to_list(0..(length(message.signers) - 1))
    end
  end

  defp expected(signer) do
    attributes =
      for %{type: {1, 3, 6, 1, 4, 1, 32_473, 1, _}} = attribute <-
            signer.signer_info.signed_attributes || [],
          do: attribute

    {signer.certificate, signing_time(signer.signing_time), Enum.sort(attributes),
     Enum.sort(signer.signer_info.unsigned_attributes)}
  end

  defp expected(%Signer{} = signer, opts) do
    time =
      cond do
        opts[:no_attributes] -> nil
        signer.signing_time == true -> :now
        signer.signing_time == false -> nil
        true -> signer.signing_time
      end

    {signer.certificate, time, Enum.sort(signer.signed_attributes),
     Enum.sort(signer.unsigned_attributes)}
  end

  defp signing_time(nil), do: nil

  defp signing_time(time) do
    if abs(DateTime.diff(time, DateTime.utc_now())) < 600, do: :now, else: time
  end

  ## DER

  property "every SET OF that sign/3 writes is in DER order" do
    check all message <- message(), max_runs: 60 do
      for {name, set} <- sets(sign!(message)) do
        encodings = Enum.map(DER.children(set), &elem(&1, 2))
        assert der_order?(encodings), "#{name} is not sorted"
      end
    end
  end

  # The SETs of a SignedData: digest algorithms, certificates, signers, the
  # signed and unsigned attributes of each signer, and the values of each
  # attribute.
  defp sets(der) do
    {:ok, root} = DER.decode(der)
    [_oid, explicit] = DER.children(root)
    [signed_data] = DER.children(explicit)
    [_version, digests, _encap | rest] = DER.children(signed_data)
    signer_infos = List.last(rest)
    certificates = for {0xA0, _, _} = set <- rest, do: {:certificates, set}

    attribute_sets =
      for info <- DER.children(signer_infos),
          {id, _, _} = set <- DER.children(info),
          id in [0xA0, 0xA1],
          do: {:attributes, set}

    values =
      for {_, set} <- attribute_sets,
          attribute <- DER.children(set),
          do: {:values, Enum.at(DER.children(attribute), 1)}

    [digest_algorithms: digests, signer_infos: signer_infos] ++
      certificates ++ attribute_sets ++ values
  end

  # X.690, 11.6: ascending order of the encodings, compared as octet
  # strings, the shorter padded at the end with zeros.
  defp der_order?(encodings) do
    encodings
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.all?(fn [a, b] -> padded(a, b) <= padded(b, a) end)
  end

  defp padded(a, b), do: a <> :binary.copy(<<0>>, max(byte_size(b) - byte_size(a), 0))

  ## Mutation

  # One message per kind of signature, with an unsigned attribute whose
  # value is 32 bytes of 0x55.
  @marker :binary.copy(<<0x55>>, 32)
  @mutation_keys ~w(rsa2048 rsapss p256 ed25519 ed448)

  setup_all do
    unsigned = Attribute.new(List.to_tuple(@arc ++ [3]), [DER.encode({:octets, @marker})])

    messages =
      Map.new(@mutation_keys, fn name ->
        signer = %Signer{certificate: cert(name), key: key(name), unsigned_attributes: [unsigned]}
        der = Cmsex.sign!(content(), signer)
        {:ok, %{signer_infos: [signer_info]}} = Cmsex.decode(der)
        {name, {der, regions(der, signer_info)}}
      end)

    %{messages: messages}
  end

  # Where each part is in the message, as {offset, size}.
  defp regions(der, signer_info) do
    %{
      content: :binary.match(der, content()),
      signed_attributes: :binary.match(der, signer_info.raw.signed_attributes),
      signature: :binary.match(der, signer_info.signature),
      unsigned_value: :binary.match(der, @marker)
    }
  end

  defp flip(der, {offset, size}, position, mask) do
    at = offset + rem(position, size)
    <<head::binary-size(at), byte, tail::binary>> = der
    <<head::binary, bxor(byte, mask), tail::binary>>
  end

  property "any byte changed in the content, the signed attributes or the signature fails",
           ctx do
    check all name <- member_of(@mutation_keys),
              region <- member_of([:content, :signed_attributes, :signature]),
              position <- integer(0..(1 <<< 20)),
              mask <- integer(1..255) do
      {der, regions} = ctx.messages[name]
      changed = flip(der, regions[region], position, mask)
      assert {:error, %Error{}} = Cmsex.verify(changed, trust: roots())
    end
  end

  # The unsigned attributes are outside the signature: RFC 5652, 5.3. A
  # change there is not seen, and an application that relies on one must
  # check it by other means (a timestamp token, for one, is signed itself).
  property "a byte changed in an unsigned attribute is not seen", ctx do
    check all name <- member_of(@mutation_keys),
              position <- integer(0..(1 <<< 20)),
              mask <- integer(1..255) do
      {der, regions} = ctx.messages[name]
      changed = flip(der, regions.unsigned_value, position, mask)

      assert {:ok, %{signers: [signer]}} = Cmsex.verify(changed, trust: roots())
      assert [%Attribute{values: [value]}] = signer.signer_info.unsigned_attributes
      assert value != DER.encode({:octets, @marker})
    end
  end

  ## Robustness

  # The same as the fuzz tests, in fewer rounds.
  property "changed fixtures are read or refused, never raise" do
    corpus = TestFuzz.corpus()

    check all {name, edits, input} <- TestFuzz.mutated(corpus), max_runs: 300 do
      assert TestFuzz.bad_results(input, roots()) == [], "#{name} with #{inspect(edits)}"
    end
  end
end
