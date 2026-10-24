defmodule Cmsex.Options do
  @moduledoc false
  # The options of the public functions: checked once at the entry, with
  # the defaults filled in, and passed on as a map. An unknown option or a
  # value of the wrong kind raises ArgumentError.

  @limits [:max_depth, :max_elements, :max_signers, :max_certificates, :max_attributes]

  @defaults %{
    max_depth: 32,
    max_elements: 100_000,
    max_signers: 64,
    max_certificates: 256,
    max_attributes: 64,
    allow_sha1: false,
    min_rsa_bits: 2048,
    ed25519_digest: :lenient,
    content: nil,
    certificates: [],
    signers: :all,
    trust: nil,
    path_validation: [],
    countersignatures: false
  }

  @type limit :: :max_depth | :max_elements | :max_signers | :max_certificates | :max_attributes

  @doc "The options that limit the reading of a message."
  @spec limits() :: [limit(), ...]
  def limits, do: @limits

  @doc """
  Checks `opts` against the allowed `keys` and returns them as a map, with
  the defaults of the keys that have one.
  """
  @spec take!(keyword(), [atom()]) :: map()
  def take!(opts, keys) when is_list(opts) do
    given =
      Map.new(opts, fn
        {key, value} when is_atom(key) ->
          unless key in keys, do: raise(ArgumentError, "unknown option #{inspect(key)}")
          check!(key, value)
          {key, value}

        other ->
          raise ArgumentError, "expected a keyword list of options, got: #{inspect(other)}"
      end)

    @defaults |> Map.take(keys) |> Map.merge(given)
  end

  def take!(opts, _keys),
    do: raise(ArgumentError, "expected a keyword list of options, got: #{inspect(opts)}")

  defp check!(key, value) when key in @limits or key == :min_rsa_bits do
    unless is_integer(value) and value > 0,
      do:
        raise(ArgumentError, "#{inspect(key)} must be a positive integer, got: #{inspect(value)}")
  end

  defp check!(:allow_sha1, value) do
    unless is_boolean(value),
      do: raise(ArgumentError, ":allow_sha1 must be a boolean, got: #{inspect(value)}")
  end

  defp check!(:ed25519_digest, value) do
    unless value in [:lenient, :strict],
      do:
        raise(
          ArgumentError,
          ":ed25519_digest must be :lenient or :strict, got: #{inspect(value)}"
        )
  end

  defp check!(:content, value) do
    unless content?(value),
      do:
        raise(
          ArgumentError,
          ":content must be a binary, {:stream, enumerable} or {:digest, hash, binary}, " <>
            "got: #{inspect(value, limit: 5)}"
        )
  end

  defp check!(:certificates, value), do: binaries!(:certificates, value)
  defp check!(:trust, nil), do: :ok
  defp check!(:trust, value), do: binaries!(:trust, value)

  defp check!(:signers, value) do
    unless value in [:all, :any],
      do: raise(ArgumentError, ":signers must be :all or :any, got: #{inspect(value)}")
  end

  defp check!(:path_validation, value) do
    unless Keyword.keyword?(value),
      do: raise(ArgumentError, ":path_validation must be a keyword list, got: #{inspect(value)}")
  end

  defp check!(:countersignatures, value) do
    unless is_boolean(value),
      do: raise(ArgumentError, ":countersignatures must be a boolean, got: #{inspect(value)}")
  end

  # The other options are checked where they are used.
  defp check!(_key, _value), do: :ok

  defp binaries!(key, value) do
    unless is_list(value) and Enum.all?(value, &is_binary/1),
      do:
        raise(
          ArgumentError,
          "#{inspect(key)} must be a list of DER binaries, got: #{inspect(value, limit: 5)}"
        )
  end

  @doc "Whether `value` is content as the functions take it."
  @spec content?(term()) :: boolean()
  def content?(value) when is_binary(value), do: true
  def content?({:stream, enumerable}), do: Enumerable.impl_for(enumerable) != nil

  def content?({:digest, hash, digest}) when is_binary(digest),
    do: hash in Cmsex.Digest.hashes() and byte_size(digest) == Cmsex.Digest.size(hash)

  def content?(_value), do: false
end
