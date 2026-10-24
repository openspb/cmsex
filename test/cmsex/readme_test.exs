defmodule MyApp.TSA do
  @moduledoc false
  # In place of a time-stamping authority: a signed message over the
  # digest of what it is given, which is the shape of a token.
  def time_stamp(data) do
    signer = %{certificate: Cmsex.ReadmeTest.rfc9216("bob_sign.crt"), key: MyApp.KMS.key("bob")}
    Cmsex.sign!(:crypto.hash(:sha256, data), signer)
  end
end

defmodule MyApp.KMS do
  @moduledoc false
  # In place of a key management service: signs a SHA-256 digest with the
  # key of RFC 9216 of that name.
  def sign(name, digest), do: {:ok, :public_key.sign({:digest, digest}, :sha256, record(name))}

  def key(name), do: Cmsex.ReadmeTest.rfc9216("#{name}_sign.key")

  defp record(name), do: :public_key.der_decode(:PrivateKeyInfo, key(name))
end

defmodule Cmsex.ReadmeTest do
  # The examples of the README run here, in order, as one program, in a
  # directory with the files they read: the keys and certificates of
  # RFC 9216, a document, a .pfx file. MyApp.TSA and MyApp.KMS above stand
  # for the services of an application.
  #
  # Not async: the examples read files by relative paths, so the test
  # changes the working directory, which is the same for the whole VM.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  @moduletag :tmp_dir

  @readme Path.expand("../../README.md", __DIR__)
  @rfc9216 Path.expand("../fixtures/rfc9216", __DIR__)

  def rfc9216(name), do: File.read!(Path.join(@rfc9216, name))

  # The blocks of Elixir code with the line where each starts, but the one
  # of the installation, which is not a program.
  defp examples do
    readme = File.read!(@readme)

    ~r/^```elixir\n(.*?)^```$/ms
    |> Regex.scan(readme, return: :index, capture: :all_but_first)
    |> Enum.map(fn [{start, size}] ->
      line = readme |> binary_part(0, start) |> String.split("\n") |> length()
      {binary_part(readme, start, size), line}
    end)
    |> Enum.reject(fn {code, _line} -> code =~ "def deps" end)
  end

  defp stage(dir) do
    write = fn name, bytes -> File.write!(Path.join(dir, name), bytes) end
    pem = fn type, der -> :public_key.pem_encode([{type, der, :not_encrypted}]) end

    write.("alice.crt", rfc9216("alice_sign.crt"))
    write.("alice.key", rfc9216("alice_sign.key"))
    write.("alice.pem", pem.(:Certificate, rfc9216("alice_sign.crt")))
    write.("alice.key.pem", pem.(:PrivateKeyInfo, rfc9216("alice_sign.key")))
    write.("bob.crt", rfc9216("bob_sign.crt"))
    write.("bob.key", rfc9216("bob_sign.key"))
    write.("bob-encryption.crt", rfc9216("bob_encrypt.crt"))
    write.("bob-encryption.key", rfc9216("bob_encrypt.key"))
    write.("ca.crt", rfc9216("ca_rsa.crt"))

    pfx =
      PKCS12.encode!(
        %{
          private_key: rfc9216("alice_sign.key"),
          certificate: rfc9216("alice_sign.crt"),
          ca_certificates: [rfc9216("ca_rsa.crt")]
        },
        "password",
        iterations: 2048
      )

    write.("alice.pfx", pfx)
    write.("contract.pdf", "%PDF-1.7\n" <> :crypto.strong_rand_bytes(20_000))
    write.("backup.tar", :crypto.strong_rand_bytes(3 * 1_048_576 + 17))
  end

  test "the examples call the main functions" do
    code = Enum.map_join(examples(), "\n", &elem(&1, 0))

    for function <- ~w(sign verify encrypt decrypt digest verify_digest mac verify_mac certs_only
                       certificates add_signer countersign add_unsigned_attribute decode) do
      assert code =~ "Cmsex.#{function}(", "no example of Cmsex.#{function}"
    end
  end

  test "the examples of the README run, in order, without warnings", %{tmp_dir: dir} do
    stage(dir)

    warnings =
      capture_io(:stderr, fn ->
        File.cd!(dir, fn ->
          Enum.reduce(examples(), [], fn {code, line}, binding ->
            {_result, binding} = Code.eval_string(code, binding, file: @readme, line: line)
            binding
          end)
        end)
      end)

    assert warnings == ""
  end
end
