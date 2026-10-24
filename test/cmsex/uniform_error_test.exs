defmodule Cmsex.UniformErrorTest do
  # Not async, so that the times are taken with no other test running.
  use ExUnit.Case, async: false

  # RFC 3218: with RSA PKCS #1 v1.5 key transport, a padding that does not
  # check must fail as a good padding of a wrong key does, with the same
  # error and in about the same time. A decryption that tells them apart,
  # by either, answers the question of the million message attack, and
  # enough answers give the key away. The library takes a random key when
  # the padding does not check (2.3), so both go on to the content, or to
  # the MAC, with a key that is not the sender's.

  import Bitwise

  alias Cmsex.{Algorithm, Certificate, Cipher, Decrypted, DER, EncryptedFixtures, Error}

  @kinds [:enveloped_data, :auth_enveloped_data, :auth_data]

  setup_all do
    {:ok, cert} = Certificate.parse(EncryptedFixtures.cert("rsa2048"))
    {:rsa, n, e} = cert.public_key

    %{
      cert: cert,
      n: n,
      e: e,
      k: byte_size(:binary.encode_unsigned(n)),
      opts: EncryptedFixtures.credentials("rsa2048"),
      content: :crypto.strong_rand_bytes(1 <<< 20)
    }
  end

  ## The messages

  # The encrypted keys, by case, for a key `secret` of the size the message
  # needs: a good padding of another key, and paddings that do not check,
  # all of them below the modulus, so that each takes the RSA operation in
  # full.
  defp encrypted_keys(ctx, secret) do
    %{n: n, e: e, k: k} = ctx
    size = byte_size(secret)
    ps = nonzero(k - 3 - size)
    rsa = &:crypto.public_encrypt(:rsa, &1, [e, n], rsa_padding: :rsa_no_padding)

    [
      wrong_key:
        :crypto.public_encrypt(:rsa, flip(secret), [e, n], rsa_padding: :rsa_pkcs1_padding),
      # 00 02 PS 00 M (RFC 8017, 7.2.2), wrong in each part.
      first_byte: rsa.(<<1, 2, ps::binary, 0, secret::binary>>),
      block_type: rsa.(<<0, 1, ps::binary, 0, secret::binary>>),
      no_separator: rsa.(<<0, 2, ps::binary, 1, secret::binary>>),
      short_padding: rsa.(<<0, 2, binary_part(ps, 0, 7)::binary, 0, nonzero(k - 10)::binary>>),
      # A good padding, of a key of another size.
      other_size: rsa.(<<0, 2, nonzero(k - 11 - size)::binary, 0, nonzero(size + 8)::binary>>),
      # What an attacker sends.
      random: random_below(ctx)
    ]
  end

  # And those that are not below the modulus, or not of its size, which
  # are told by public values only.
  defp public_cases(ctx, secret) do
    {:ok, other} = Certificate.parse(EncryptedFixtures.cert("rsa3072"))
    {:rsa, n, e} = other.public_key

    [
      too_big: :binary.copy(<<0xFF>>, ctx.k),
      too_long: <<1>> <> random_below(ctx),
      short: <<1, 2, 3>>,
      empty: <<>>,
      other_recipient:
        :crypto.public_encrypt(:rsa, secret, [e, n], rsa_padding: :rsa_pkcs1_padding)
    ]
  end

  defp nonzero(size), do: for(_ <- 1..size, into: <<>>, do: <<Enum.random(1..255)>>)

  defp flip(<<byte, rest::binary>>), do: <<bxor(byte, 0xFF), rest::binary>>

  defp random_below(%{n: n, k: k} = ctx) do
    candidate = :crypto.strong_rand_bytes(k)
    if :binary.decode_unsigned(candidate) < n, do: candidate, else: random_below(ctx)
  end

  # A message of `kind` with `content`: its key, and a function that writes
  # the message with that key encrypted as given.
  defp builder(:enveloped_data, ctx, content) do
    cipher = Cipher.new(:aes128_cbc)
    cek = Cipher.random_key(cipher)
    {ciphertext, nil} = Cipher.encrypt(cipher, cek, content)
    {cek, &message(:enveloped_data, [{:int, 0}, recipients(ctx, &1), eci(cipher, ciphertext)])}
  end

  defp builder(:auth_enveloped_data, ctx, content) do
    cipher = Cipher.new(:aes256_gcm)
    cek = Cipher.random_key(cipher)
    {ciphertext, tag} = Cipher.encrypt(cipher, cek, content)

    {cek,
     &message(:auth_enveloped_data, [
       {:int, 0},
       recipients(ctx, &1),
       eci(cipher, ciphertext),
       {:octets, tag}
     ])}
  end

  defp builder(:auth_data, ctx, content) do
    key = :crypto.strong_rand_bytes(32)

    {key,
     &message(:auth_data, [
       {:int, 0},
       recipients(ctx, &1),
       Algorithm.mac_identifier(:sha256),
       {:seq, [{:oid, :data}, {:explicit, 0, {:octets, content}}]},
       {:octets, :crypto.mac(:hmac, :sha256, key, content)}
     ])}
  end

  defp recipients(ctx, encrypted_key) do
    {:set,
     [
       {:seq,
        [
          {:int, 0},
          {:seq, [{:raw, ctx.cert.issuer}, {:int, ctx.cert.serial}]},
          {:seq, [{:oid, :rsa_encryption}, :null]},
          {:octets, encrypted_key}
        ]}
     ]}
  end

  defp message(type, fields),
    do: DER.encode({:seq, [{:oid, type}, {:explicit, 0, {:seq, fields}}]})

  defp eci(cipher, ciphertext),
    do: {:seq, [{:oid, :data}, Cipher.identifier(cipher), {:primitive, 0x80, ciphertext}]}

  defp run(:auth_data, cms, ctx), do: Cmsex.verify_mac(cms, ctx.opts)
  defp run(_kind, cms, ctx), do: Cmsex.decrypt(cms, ctx.opts)

  # With CBC, a key that is not the sender's decrypts to garbage about once
  # in 256 times, since nothing in an EnvelopedData can tell; either way,
  # not to the content. AES-GCM and the MAC make the failure certain.
  defp failed?(:enveloped_data, {:ok, %Decrypted{content: content}}, ctx),
    do: content != ctx.content

  defp failed?(:auth_data, result, _ctx), do: result == {:error, Error.new(:invalid_mac)}
  defp failed?(_kind, result, _ctx), do: result == {:error, Error.new(:decryption_failed)}

  ## The same error

  test "a padding that does not check fails as a wrong key does", ctx do
    for kind <- @kinds do
      {secret, build} = builder(kind, ctx, ctx.content)
      good = :crypto.public_encrypt(:rsa, secret, [ctx.e, ctx.n], rsa_padding: :rsa_pkcs1_padding)
      assert {:ok, %{content: content}} = run(kind, build.(good), ctx)
      assert content == ctx.content

      for {name, encrypted_key} <- encrypted_keys(ctx, secret) ++ public_cases(ctx, secret) do
        assert failed?(kind, run(kind, build.(encrypted_key), ctx), ctx), "#{kind}: #{name}"
      end
    end
  end

  ## In about the same time

  # A decryption that stopped at a padding that does not check would save
  # the work on the content, which is measured here as the time of the
  # same message with one byte of content instead of a MiB. The medians of
  # the cases must be closer to that of the wrong key than a third of it.
  # The times are taken in rounds, each case once in a random order in
  # each, so that what slows the machine down slows all of them; a
  # measure that does not pass is taken again, up to three times, since a
  # difference of the code would stay and noise would not.
  @rounds 60

  test "in about the same time", ctx do
    for kind <- @kinds do
      assert similar_times(kind, ctx, 3) == :ok
    end
  end

  defp similar_times(kind, ctx, tries) do
    {secret, build} = builder(kind, ctx, ctx.content)
    {_secret, small} = builder(kind, ctx, "x")
    keys = encrypted_keys(ctx, secret)

    cases = [
      {:content, small.(keys[:random])}
      | Enum.map(keys, fn {name, key} -> {name, build.(key)} end)
    ]

    medians = medians(cases, &run(kind, &1, ctx))
    %{wrong_key: base, content: without_content} = medians
    tolerance = (base - without_content) / 3

    off =
      for {name, time} <- medians,
          name not in [:wrong_key, :content],
          abs(time - base) >= tolerance,
          do: name

    cond do
      tolerance > 0 and off == [] -> :ok
      tries > 1 -> similar_times(kind, ctx, tries - 1)
      true -> {kind, off, Map.new(medians, fn {name, t} -> {name, microseconds(t)} end)}
    end
  end

  defp medians(cases, fun) do
    for _ <- 1..10, {_name, cms} <- cases, do: fun.(cms)

    for _ <- 1..@rounds, {name, cms} <- Enum.shuffle(cases) do
      start = System.monotonic_time()
      fun.(cms)
      {name, System.monotonic_time() - start}
    end
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Map.new(fn {name, times} -> {name, median(times)} end)
  end

  defp median(values), do: values |> Enum.sort() |> Enum.at(div(length(values), 2))

  defp microseconds(time), do: System.convert_time_unit(time, :native, :microsecond)
end
