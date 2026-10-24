defmodule Cmsex.Options do
  @moduledoc false
  # The options of the public functions: checked once at the entry, with
  # the defaults filled in, and passed on as a map. An unknown option, one
  # given twice or a value of the wrong kind raises ArgumentError.

  @limits [:max_depth, :max_elements, :max_signers, :max_certificates, :max_attributes]

  @defaults %{
    max_depth: 32,
    max_elements: 100_000,
    max_signers: 64,
    max_certificates: 256,
    max_attributes: 64,
    max_recipients: 64,
    max_iterations: 2_000_000,
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

    unique!(opts)
    @defaults |> Map.take(keys) |> Map.merge(given)
  end

  def take!(opts, _keys),
    do: raise(ArgumentError, "expected a keyword list of options, got: #{inspect(opts)}")

  defp check!(key, value)
       when key in @limits or key in [:min_rsa_bits, :max_recipients, :max_iterations] do
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
            "got #{kind(value)}"
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

  @doc """
  Raises `ArgumentError` when a key of the keyword list `opts` comes more
  than once: which of the values was meant cannot be told, and taking one
  in silence could weaken a check.
  """
  @spec unique!(list(), String.t()) :: :ok
  def unique!(opts, what \\ "option") do
    keys = for {key, _value} <- opts, do: key

    case keys -- Enum.uniq(keys) do
      [] -> :ok
      [key | _] -> raise ArgumentError, "the #{what} #{inspect(key)} is given more than once"
    end
  end

  @doc "Whether `value` is content as the functions take it."
  @spec content?(term()) :: boolean()
  def content?(value) when is_binary(value), do: true
  def content?({:stream, enumerable}), do: Enumerable.impl_for(enumerable) != nil

  def content?({:digest, hash, digest}) when is_binary(digest),
    do: hash in Cmsex.Digest.hashes() and byte_size(digest) == Cmsex.Digest.size(hash)

  def content?(_value), do: false

  @doc """
  What kind of term `value` is, for the message of an `ArgumentError` about
  an argument that may be a key or the content, and so is not shown.
  """
  @spec kind(term()) :: String.t()
  def kind(value) when is_binary(value), do: "a binary"
  def kind(value) when is_list(value), do: "a list"
  def kind(value) when is_tuple(value), do: "a tuple of #{tuple_size(value)} elements"
  def kind(%module{}), do: "a #{inspect(module)} struct"
  def kind(value) when is_map(value), do: "a map"
  def kind(value) when is_atom(value), do: inspect(value)
  def kind(value) when is_number(value), do: "a number"
  def kind(value) when is_function(value), do: "a function"
  def kind(_value), do: "a pid, port or reference"
end
