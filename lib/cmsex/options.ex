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
    ed25519_digest: :lenient
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

  # The other options are checked where they are used.
  defp check!(_key, _value), do: :ok
end
