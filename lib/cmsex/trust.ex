defmodule Cmsex.Trust do
  @moduledoc false
  # Validation of the certificate of a signer against trusted roots: a
  # path is built by name and key identifier from the certificates at hand,
  # never by their order in the message, and each candidate path goes to
  # `:public_key.pkix_path_validation/3`, which checks signatures, validity
  # periods (at the current time), basic constraints, key usage of the CAs,
  # name constraints and policies.

  alias Cmsex.Certificate

  @max_length 10

  @doc """
  The validated path from a root to `leaf`, as DER, root first. `pool` is
  the certificates that may be intermediates; `roots` the trusted ones.
  """
  @spec validate(Certificate.t(), [Certificate.t()], [Certificate.t()], keyword()) ::
          {:ok, [binary(), ...]} | {:error, term()}
  def validate(%Certificate{} = leaf, pool, roots, path_options) do
    with :ok <- usage(leaf) do
      if Enum.any?(roots, &(&1.der == leaf.der)) do
        {:ok, [leaf.der]}
      else
        search([leaf], pool, roots, path_options, {:error, :no_path})
      end
    end
  end

  # The key of a signer must be allowed to sign (RFC 5280, 4.2.1.3).
  defp usage(%Certificate{key_usage: nil}), do: :ok

  defp usage(%Certificate{key_usage: usage}) do
    if :digital_signature in usage or :non_repudiation in usage,
      do: :ok,
      else: {:error, :key_usage}
  end

  # `chain` goes from the last certificate found down to the leaf.
  defp search([top | _] = chain, pool, roots, path_options, failure) do
    failure =
      roots
      |> Enum.filter(&issued_by?(top, &1))
      |> Enum.reduce_while(failure, fn root, failure ->
        case validate_path(root, chain, path_options) do
          :ok -> {:halt, {:ok, [root.der | Enum.map(chain, & &1.der)]}}
          {:error, reason} -> {:cont, first_failure(failure, reason)}
        end
      end)

    case failure do
      {:ok, _} = found -> found
      failure when length(chain) >= @max_length -> failure
      failure -> extend(chain, pool, roots, path_options, failure)
    end
  end

  defp extend([top | _] = chain, pool, roots, path_options, failure) do
    pool
    |> Enum.filter(&(issued_by?(top, &1) and &1.der not in Enum.map(chain, fn c -> c.der end)))
    |> Enum.reduce_while(failure, fn issuer, failure ->
      case search([issuer | chain], pool, roots, path_options, failure) do
        {:ok, _} = found -> {:halt, found}
        failure -> {:cont, failure}
      end
    end)
  end

  # The first real validation failure says more than "no path".
  defp first_failure({:error, :no_path}, reason), do: {:error, reason}
  defp first_failure(failure, _reason), do: failure

  defp validate_path(root, chain, path_options) do
    case :public_key.pkix_path_validation(root.der, Enum.map(chain, & &1.der), path_options) do
      {:ok, _} -> :ok
      {:error, {:bad_cert, reason}} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  end

  @doc "Whether `issuer` may have issued `cert`: by name, and by key identifier when both have one."
  @spec issued_by?(Certificate.t(), Certificate.t()) :: boolean()
  def issued_by?(%Certificate{} = cert, %Certificate{} = issuer) do
    same_name?(cert.issuer, issuer.subject) and
      (cert.authority_key_identifier == nil or issuer.subject_key_identifier == nil or
         cert.authority_key_identifier == issuer.subject_key_identifier)
  end

  @doc "Whether two Names are the same: the same bytes, or the same after RFC 5280, 7.1."
  @spec same_name?(binary(), binary()) :: boolean()
  def same_name?(a, a), do: true

  def same_name?(a, b) do
    case Certificate.canonical_name(a) do
      nil -> false
      canonical -> canonical == Certificate.canonical_name(b)
    end
  end
end
