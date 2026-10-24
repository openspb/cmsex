defmodule Cmsex.Digesting do
  @moduledoc false
  # Writing and verifying DigestedData (RFC 5652, 7): a content and its
  # digest, over the content octets of eContent. The digest shows that the
  # content was not changed by accident; whoever changes it can write a
  # new digest.

  alias Cmsex.{Algorithm, Compose, Digest, DigestedData, Error, Message, Options, PEM}

  @options %{digest: nil, content_type: :data, detached: nil}
  @keys Options.limits() ++ [:content, :allow_sha1]

  @doc "A DigestedData of `content`; see `Cmsex.digest/2`."
  @spec digest(Digest.content(), keyword()) :: {:ok, binary()}
  def digest(content, opts) do
    Compose.content!(content)
    opts = Compose.options!(opts, @options)
    detached = Compose.detached!(content, opts.detached)
    hash = hash!(content, opts.digest)
    %{^hash => digest} = Digest.many(content, [hash])

    fields = [
      {:int, if(opts.content_type == :data, do: 0, else: 2)},
      Algorithm.digest_identifier(hash),
      Compose.encap_content_info(opts.content_type, if(detached, do: nil, else: content)),
      {:octets, digest}
    ]

    {:ok, Compose.content_info(:digested_data, fields)}
  end

  # The hash of the option, of a ready digest, or SHA-256. A ready digest
  # must be of a hash that is written, and agree with the option.
  defp hash!({:digest, hash, _digest}, given) do
    unless hash in [:sha224, :sha256, :sha384, :sha512],
      do: raise(ArgumentError, "a ready digest must be of SHA-2, got: #{inspect(hash)}")

    unless given in [nil, hash],
      do:
        raise(
          ArgumentError,
          ":digest is #{inspect(given)}, but the ready digest is of #{inspect(hash)}"
        )

    hash
  end

  defp hash!(_content, given), do: given || :sha256

  @doc "Verifies a DigestedData; see `Cmsex.verify_digest/2`."
  @spec verify_digest(binary(), keyword()) :: {:ok, DigestedData.t()} | {:error, Error.t()}
  def verify_digest(cms, opts) do
    opts = Options.take!(opts, @keys)

    with {:ok, der} <- PEM.input(cms),
         {:ok, message} <- Message.parse(der, opts, [:digested_data]),
         {:ok, hash} <- hash(message, opts),
         {:ok, content} <- Message.content(message.content, opts.content),
         :ok <- check(message.digest, hash, content) do
      {:ok, message}
    end
  end

  defp hash(message, opts) do
    with {:ok, hash} <- Algorithm.digest(message.raw.digest_algorithm),
         :ok <- Algorithm.allowed_digest(hash, allow_sha1: opts.allow_sha1) do
      {:ok, hash}
    else
      {:error, reason, detail} -> {:error, Error.new(reason, detail)}
    end
  end

  # A ready digest only answers for its own hash.
  defp check(digest, hash, content) do
    case Digest.many(content, [hash]) do
      %{^hash => ^digest} -> :ok
      %{^hash => _other} -> {:error, Error.new(:digest_mismatch)}
      %{} -> {:error, Error.new(:content_required, hash)}
    end
  end
end
