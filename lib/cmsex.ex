defmodule Cmsex do
  @moduledoc """
  Cryptographic Message Syntax (CMS, RFC 5652) in pure Elixir.
  """

  alias Cmsex.{Error, Options, PEM, SignedData}

  @decode_options Options.limits()

  @doc """
  Reads a SignedData message without verifying it, for inspection and for
  the libraries built on this one. The message may be in DER, BER or PEM.

  Options, the limits on what the message may hold:

    * `:max_depth` - nesting of the encoding (32).
    * `:max_elements` - encoded elements at all levels (100,000).
    * `:max_signers` - signers, and countersignatures of one signer (64).
    * `:max_certificates` - certificates, and revocation lists (256).
    * `:max_attributes` - signed, and unsigned, attributes of one signer
      (64).

  A ContentInfo of another type gives `:unsupported_content_type`.
  """
  @spec decode(binary(), keyword()) :: {:ok, SignedData.t()} | {:error, Error.t()}
  def decode(cms, opts \\ []) do
    opts = Options.take!(opts, @decode_options)
    with {:ok, der} <- PEM.input(cms), do: SignedData.parse(der, opts)
  end

  @doc "Like `decode/2`, but raises `Cmsex.Error`."
  @spec decode!(binary(), keyword()) :: SignedData.t()
  def decode!(cms, opts \\ []) do
    case decode(cms, opts) do
      {:ok, signed_data} -> signed_data
      {:error, error} -> raise error
    end
  end

  @doc """
  The X.509 certificates of a SignedData message, in DER, in the order of
  the message: the certificates of a `.p7b` bundle, or those a signer
  included. Takes the options of `decode/2`.
  """
  @spec certificates(binary(), keyword()) :: {:ok, [binary()]} | {:error, Error.t()}
  def certificates(cms, opts \\ []) do
    with {:ok, signed_data} <- decode(cms, opts), do: {:ok, signed_data.certificates}
  end

  @doc "Like `certificates/2`, but raises `Cmsex.Error`."
  @spec certificates!(binary(), keyword()) :: [binary()]
  def certificates!(cms, opts \\ []) do
    case certificates(cms, opts) do
      {:ok, certificates} -> certificates
      {:error, error} -> raise error
    end
  end
end
