defmodule Cmsex.PEM do
  @moduledoc """
  The textual encoding of CMS messages (RFC 7468): Base64 between
  `-----BEGIN CMS-----` and `-----END CMS-----` lines.

  RFC 7468 gives two labels: `CMS` (section 9) and `PKCS7` (section 8), the
  older one, which more tools expect in a `.p7b` certificate bundle. Both
  are read; `encode/2` writes `CMS` unless asked otherwise.

  Every function of `Cmsex` that takes a message also takes it in PEM, so
  this module is only needed to write PEM, or to read it apart.

      iex> pem = Cmsex.PEM.encode(<<0x30, 0x03, 0x02, 0x01, 0x01>>)
      "-----BEGIN CMS-----\\nMAMCAQE=\\n-----END CMS-----\\n"
      iex> Cmsex.PEM.decode("Text before\\n" <> pem)
      {:ok, <<0x30, 0x03, 0x02, 0x01, 0x01>>}
  """

  alias Cmsex.Error

  @doc """
  Encodes a message in PEM, with the label `:cms` (the default) or
  `:pkcs7`, in lines of 64 characters.
  """
  @spec encode(binary(), :cms | :pkcs7) :: String.t()
  def encode(der, label \\ :cms)

  def encode(der, label) when is_binary(der) and label in [:cms, :pkcs7] do
    name = label_name(label)

    IO.iodata_to_binary([
      ["-----BEGIN ", name, "-----\n"],
      lines(Base.encode64(der)),
      ["-----END ", name, "-----\n"]
    ])
  end

  def encode(der, label) do
    raise ArgumentError,
          "expected a binary and :cms or :pkcs7, got: #{inspect(der, limit: 5)}, #{inspect(label)}"
  end

  @doc """
  Decodes the first PEM block labelled `CMS` or `PKCS7`. Text before and
  after the block, and blocks with other labels, are skipped; whitespace
  inside the block is ignored. The `END` line must carry the same label.
  """
  @spec decode(binary()) :: {:ok, binary()} | {:error, Error.t()}
  def decode(pem) when is_binary(pem) do
    with [_, _label, body] <-
           Regex.run(~r/-----BEGIN (CMS|PKCS7)-----(.*?)-----END \1-----/s, pem),
         {:ok, der} <- body |> String.replace(~r/[\t\n\v\f\r ]/, "") |> Base.decode64() do
      {:ok, der}
    else
      _ -> {:error, Error.new(:invalid_pem)}
    end
  end

  def decode(pem), do: raise(ArgumentError, "expected a binary, got: #{inspect(pem, limit: 5)}")

  @doc false
  # A message as the functions of Cmsex take it: DER or BER, or PEM.
  @spec input(binary()) :: {:ok, binary()} | {:error, Error.t()}
  def input(<<0x30, _::binary>> = der), do: {:ok, der}

  def input(bin) when is_binary(bin) do
    if String.contains?(bin, "-----BEGIN "),
      do: decode(bin),
      else: {:error, Error.new(:malformed)}
  end

  def input(other),
    do: raise(ArgumentError, "expected the message as a binary, got: #{inspect(other, limit: 5)}")

  defp lines(<<line::binary-size(64), rest::binary>>), do: [line, ?\n | lines(rest)]
  defp lines(<<>>), do: []
  defp lines(last), do: [last, ?\n]

  defp label_name(:cms), do: "CMS"
  defp label_name(:pkcs7), do: "PKCS7"
end
