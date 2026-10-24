defmodule Cmsex.Interop do
  @moduledoc false
  # The other implementations of the interop tests, found on this system:
  #
  #   CMSEX_OPENSSL    an OpenSSL binary, 3.0 or later
  #   CMSEX_LIBRESSL   a LibreSSL binary (the openssl of macOS)
  #   CMSEX_CERTTOOL   the certtool of GnuTLS (gnutls-certtool on macOS, where
  #                    /usr/bin/certtool is another program)
  #   CMSEX_PYTHON     a Python 3 with the "cryptography" package, 42 or later
  #   CMSEX_JARSIGNER  the jarsigner of a JDK, 17 or later
  #
  # Without the variable, a few usual places are tried. A tool that is not
  # found is skipped, unless CMSEX_REQUIRE_INTEROP names it, as in
  # "openssl,certtool", or is "all": then its tests fail.

  @tools [:openssl, :libressl, :certtool, :python, :jarsigner]

  # The signing builder takes rsa_padding since cryptography 42; without
  # it, the probe fails and Python counts as not found.
  @python_probe """
  import inspect
  import cryptography
  from cryptography.hazmat.primitives.serialization import pkcs7
  pkcs7.load_der_pkcs7_certificates
  assert "rsa_padding" in inspect.signature(pkcs7.PKCS7SignatureBuilder.add_signer).parameters
  print("cryptography", cryptography.__version__)
  """

  def tools, do: @tools

  @doc "`{path, version text}` of a tool, or `nil`."
  def find(:openssl),
    do:
      openssl(
        "CMSEX_OPENSSL",
        ["/opt/homebrew/opt/openssl@3/bin/openssl", "openssl"],
        ~r/^OpenSSL [3-9]\./
      )

  def find(:libressl),
    do: openssl("CMSEX_LIBRESSL", ["/usr/bin/openssl", "openssl"], ~r/^LibreSSL /)

  def find(:certtool) do
    first_found("CMSEX_CERTTOOL", ["gnutls-certtool", "certtool"], fn path ->
      case System.cmd(path, ["--version"], stderr_to_stdout: true) do
        {"certtool " <> _ = output, 0} -> output |> String.split("\n") |> hd()
        _ -> nil
      end
    end)
  end

  def find(:python) do
    first_found("CMSEX_PYTHON", ["python3"], fn path ->
      case System.cmd(path, ["-I", "-c", @python_probe], stderr_to_stdout: true) do
        {version, 0} -> String.trim(version)
        _ -> nil
      end
    end)
  end

  def find(:jarsigner) do
    java_home = System.get_env("JAVA_HOME")
    candidates = ["/opt/homebrew/opt/openjdk/bin/jarsigner", "jarsigner"]

    candidates =
      if java_home,
        do: [Path.join([java_home, "bin", "jarsigner"]) | candidates],
        else: candidates

    first_found("CMSEX_JARSIGNER", candidates, fn path ->
      case System.cmd(path, ["-version"], stderr_to_stdout: true) do
        {"jarsigner " <> _ = version, 0} -> String.trim(version)
        _ -> nil
      end
    end)
  end

  def required?(tool) do
    names = System.get_env("CMSEX_REQUIRE_INTEROP", "") |> String.split(",", trim: true)
    "all" in names or Atom.to_string(tool) in names
  end

  @doc "Runs a tool, with its output and exit status."
  def run(path, args, opts \\ []) do
    System.cmd(path, args, [stderr_to_stdout: true] ++ opts)
  end

  @doc "Runs a Python script, given as text, with its arguments."
  def python(path, script, args) do
    run(path, ["-I", "-c", script | args])
  end

  defp openssl(variable, candidates, pattern) do
    first_found(variable, candidates, fn path ->
      with {version, 0} <- System.cmd(path, ["version"], stderr_to_stdout: true),
           true <- version =~ pattern do
        String.trim(version)
      else
        _ -> nil
      end
    end)
  end

  # With the variable set, only its value is tried.
  defp first_found(variable, candidates, probe) do
    candidates =
      case System.get_env(variable) do
        nil -> candidates
        path -> [path]
      end

    Enum.find_value(candidates, fn candidate ->
      with path when is_binary(path) <- System.find_executable(candidate),
           version when is_binary(version) <- probe.(path) do
        {path, version}
      end
    end)
  end
end
