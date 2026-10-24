defmodule Cmsex.TestFixtures do
  @moduledoc false
  # Access to test/fixtures/generated, made by gen_fixtures.sh: keys and
  # certificates of OpenSSL, and messages of several tools signed with them.

  @dir Path.expand("../fixtures/generated", __DIR__)

  def path(name), do: Path.join(@dir, name)
  def read!(name), do: File.read!(path(name))

  @doc "The content of every generated message."
  def content, do: read!("content.txt")

  @doc "A certificate of the material in DER, by its name without `.crt`."
  def cert(name) do
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(read!(name <> ".crt"))
    der
  end

  @doc "A private key of the material in PKCS #8 DER, by its name without `.key`."
  def key(name) do
    [{:PrivateKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(read!(name <> ".key"))
    der
  end

  @doc "The CAs of the material, in DER."
  def roots, do: Enum.map(~w(ca ca_utf8 ca_printable), &cert/1)

  @doc "The file names of the generated messages."
  def messages, do: path("*.p7[sc]") |> Path.wildcard() |> Enum.map(&Path.basename/1)
end
