defmodule Cmsex.OID do
  @moduledoc_intro """
  The object identifiers this library knows by name.

  Everywhere in the API an OID is a tuple of integers, such as
  `{1, 2, 840, 113549, 1, 7, 1}`, and a known one may also be given and is
  returned as its name, such as `:data`. Names come only from this fixed
  table: an OID read from a message that is not in it stays a tuple, so no
  input can create atoms.

  | Name | OID |
  |---|---|
  """

  import Bitwise

  @table [
    # Content types (RFC 5652, RFC 5083, RFC 3161)
    data: {1, 2, 840, 113_549, 1, 7, 1},
    signed_data: {1, 2, 840, 113_549, 1, 7, 2},
    enveloped_data: {1, 2, 840, 113_549, 1, 7, 3},
    digested_data: {1, 2, 840, 113_549, 1, 7, 5},
    encrypted_data: {1, 2, 840, 113_549, 1, 7, 6},
    auth_data: {1, 2, 840, 113_549, 1, 9, 16, 1, 2},
    tst_info: {1, 2, 840, 113_549, 1, 9, 16, 1, 4},
    content_info: {1, 2, 840, 113_549, 1, 9, 16, 1, 6},
    auth_enveloped_data: {1, 2, 840, 113_549, 1, 9, 16, 1, 23},
    # Attributes (RFC 5652, RFC 6211, RFC 8551, RFC 2634, RFC 5035, RFC 3161, RFC 5126)
    content_type: {1, 2, 840, 113_549, 1, 9, 3},
    message_digest: {1, 2, 840, 113_549, 1, 9, 4},
    signing_time: {1, 2, 840, 113_549, 1, 9, 5},
    countersignature: {1, 2, 840, 113_549, 1, 9, 6},
    smime_capabilities: {1, 2, 840, 113_549, 1, 9, 15},
    cms_algorithm_protection: {1, 2, 840, 113_549, 1, 9, 52},
    content_hint: {1, 2, 840, 113_549, 1, 9, 16, 2, 4},
    signing_certificate: {1, 2, 840, 113_549, 1, 9, 16, 2, 12},
    time_stamp_token: {1, 2, 840, 113_549, 1, 9, 16, 2, 14},
    sig_policy_id: {1, 2, 840, 113_549, 1, 9, 16, 2, 15},
    signing_certificate_v2: {1, 2, 840, 113_549, 1, 9, 16, 2, 47},
    # Digests (RFC 3370, RFC 5754, RFC 8702)
    md5: {1, 2, 840, 113_549, 2, 5},
    sha1: {1, 3, 14, 3, 2, 26},
    sha224: {2, 16, 840, 1, 101, 3, 4, 2, 4},
    sha256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
    sha384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
    sha512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
    shake128: {2, 16, 840, 1, 101, 3, 4, 2, 11},
    shake256: {2, 16, 840, 1, 101, 3, 4, 2, 12},
    shake128_len: {2, 16, 840, 1, 101, 3, 4, 2, 17},
    shake256_len: {2, 16, 840, 1, 101, 3, 4, 2, 18},
    # RSA (RFC 3370, RFC 4055, RFC 4056, RFC 3560, RFC 5754)
    rsa_encryption: {1, 2, 840, 113_549, 1, 1, 1},
    md5_with_rsa_encryption: {1, 2, 840, 113_549, 1, 1, 4},
    sha1_with_rsa_encryption: {1, 2, 840, 113_549, 1, 1, 5},
    rsaes_oaep: {1, 2, 840, 113_549, 1, 1, 7},
    mgf1: {1, 2, 840, 113_549, 1, 1, 8},
    p_specified: {1, 2, 840, 113_549, 1, 1, 9},
    rsassa_pss: {1, 2, 840, 113_549, 1, 1, 10},
    sha256_with_rsa_encryption: {1, 2, 840, 113_549, 1, 1, 11},
    sha384_with_rsa_encryption: {1, 2, 840, 113_549, 1, 1, 12},
    sha512_with_rsa_encryption: {1, 2, 840, 113_549, 1, 1, 13},
    sha224_with_rsa_encryption: {1, 2, 840, 113_549, 1, 1, 14},
    # Elliptic curves (RFC 5480, RFC 5753, RFC 5754, RFC 8410, RFC 8418, RFC 8419)
    ec_public_key: {1, 2, 840, 10_045, 2, 1},
    ecdsa_with_sha1: {1, 2, 840, 10_045, 4, 1},
    ecdsa_with_sha224: {1, 2, 840, 10_045, 4, 3, 1},
    ecdsa_with_sha256: {1, 2, 840, 10_045, 4, 3, 2},
    ecdsa_with_sha384: {1, 2, 840, 10_045, 4, 3, 3},
    ecdsa_with_sha512: {1, 2, 840, 10_045, 4, 3, 4},
    secp256r1: {1, 2, 840, 10_045, 3, 1, 7},
    secp384r1: {1, 3, 132, 0, 34},
    secp521r1: {1, 3, 132, 0, 35},
    brainpool_p256r1: {1, 3, 36, 3, 3, 2, 8, 1, 1, 7},
    brainpool_p384r1: {1, 3, 36, 3, 3, 2, 8, 1, 1, 11},
    brainpool_p512r1: {1, 3, 36, 3, 3, 2, 8, 1, 1, 13},
    x25519: {1, 3, 101, 110},
    x448: {1, 3, 101, 111},
    ed25519: {1, 3, 101, 112},
    ed448: {1, 3, 101, 113},
    std_dh_sha1kdf: {1, 3, 133, 16, 840, 63, 0, 2},
    cofactor_dh_sha1kdf: {1, 3, 133, 16, 840, 63, 0, 3},
    std_dh_sha224kdf: {1, 3, 132, 1, 11, 0},
    std_dh_sha256kdf: {1, 3, 132, 1, 11, 1},
    std_dh_sha384kdf: {1, 3, 132, 1, 11, 2},
    std_dh_sha512kdf: {1, 3, 132, 1, 11, 3},
    cofactor_dh_sha224kdf: {1, 3, 132, 1, 14, 0},
    cofactor_dh_sha256kdf: {1, 3, 132, 1, 14, 1},
    cofactor_dh_sha384kdf: {1, 3, 132, 1, 14, 2},
    cofactor_dh_sha512kdf: {1, 3, 132, 1, 14, 3},
    std_dh_hkdf_sha256: {1, 2, 840, 113_549, 1, 9, 16, 3, 19},
    std_dh_hkdf_sha384: {1, 2, 840, 113_549, 1, 9, 16, 3, 20},
    std_dh_hkdf_sha512: {1, 2, 840, 113_549, 1, 9, 16, 3, 21},
    # DSA and Diffie-Hellman (RFC 3370, RFC 2631, RFC 5754)
    dsa: {1, 2, 840, 10_040, 4, 1},
    dsa_with_sha1: {1, 2, 840, 10_040, 4, 3},
    dsa_with_sha224: {2, 16, 840, 1, 101, 3, 4, 3, 1},
    dsa_with_sha256: {2, 16, 840, 1, 101, 3, 4, 3, 2},
    dh_public_number: {1, 2, 840, 10_046, 2, 1},
    esdh: {1, 2, 840, 113_549, 1, 9, 16, 3, 5},
    # Content encryption and key wrap (RFC 3565, RFC 5084, RFC 3394, RFC 5649,
    # RFC 3370, RFC 3217, RFC 8103)
    aes128_cbc: {2, 16, 840, 1, 101, 3, 4, 1, 2},
    aes192_cbc: {2, 16, 840, 1, 101, 3, 4, 1, 22},
    aes256_cbc: {2, 16, 840, 1, 101, 3, 4, 1, 42},
    aes128_gcm: {2, 16, 840, 1, 101, 3, 4, 1, 6},
    aes192_gcm: {2, 16, 840, 1, 101, 3, 4, 1, 26},
    aes256_gcm: {2, 16, 840, 1, 101, 3, 4, 1, 46},
    aes128_ccm: {2, 16, 840, 1, 101, 3, 4, 1, 7},
    aes192_ccm: {2, 16, 840, 1, 101, 3, 4, 1, 27},
    aes256_ccm: {2, 16, 840, 1, 101, 3, 4, 1, 47},
    aes128_wrap: {2, 16, 840, 1, 101, 3, 4, 1, 5},
    aes192_wrap: {2, 16, 840, 1, 101, 3, 4, 1, 25},
    aes256_wrap: {2, 16, 840, 1, 101, 3, 4, 1, 45},
    aes128_wrap_pad: {2, 16, 840, 1, 101, 3, 4, 1, 8},
    aes192_wrap_pad: {2, 16, 840, 1, 101, 3, 4, 1, 28},
    aes256_wrap_pad: {2, 16, 840, 1, 101, 3, 4, 1, 48},
    des_ede3_cbc: {1, 2, 840, 113_549, 3, 7},
    rc2_cbc: {1, 2, 840, 113_549, 3, 2},
    des_cbc: {1, 3, 14, 3, 2, 7},
    cms3des_wrap: {1, 2, 840, 113_549, 1, 9, 16, 3, 6},
    cmsrc2_wrap: {1, 2, 840, 113_549, 1, 9, 16, 3, 7},
    chacha20_poly1305: {1, 2, 840, 113_549, 1, 9, 16, 3, 18},
    # Passwords and MACs (RFC 3211, RFC 8018, RFC 4231, RFC 3370). HMAC with
    # SHA-1 has two: hMAC-SHA1, the MAC of RFC 3370, and hmacWithSHA1, the
    # pseudorandom function of PBKDF2 in RFC 8018.
    pwri_kek: {1, 2, 840, 113_549, 1, 9, 16, 3, 9},
    pbkdf2: {1, 2, 840, 113_549, 1, 5, 12},
    hmac_sha1: {1, 3, 6, 1, 5, 5, 8, 1, 2},
    hmac_with_sha1: {1, 2, 840, 113_549, 2, 7},
    hmac_sha224: {1, 2, 840, 113_549, 2, 8},
    hmac_sha256: {1, 2, 840, 113_549, 2, 9},
    hmac_sha384: {1, 2, 840, 113_549, 2, 10},
    hmac_sha512: {1, 2, 840, 113_549, 2, 11},
    # Certificates (RFC 5280)
    subject_key_identifier: {2, 5, 29, 14},
    key_usage: {2, 5, 29, 15},
    basic_constraints: {2, 5, 29, 19},
    authority_key_identifier: {2, 5, 29, 35},
    ext_key_usage: {2, 5, 29, 37},
    kp_time_stamping: {1, 3, 6, 1, 5, 5, 7, 3, 8}
  ]

  @moduledoc @moduledoc_intro <>
               Enum.map_join(@table, "\n", fn {name, oid} ->
                 "| `#{inspect(name)}` | #{oid |> Tuple.to_list() |> Enum.join(".")} |"
               end)

  @type name :: atom()
  @type t :: tuple()

  @doc """
  The OID of a name, or the OID itself.

      iex> Cmsex.OID.oid(:data)
      {1, 2, 840, 113549, 1, 7, 1}
      iex> Cmsex.OID.oid({1, 2, 3})
      {1, 2, 3}
  """
  @spec oid(name() | t()) :: t()
  for {name, oid} <- @table do
    def oid(unquote(name)), do: unquote(Macro.escape(oid))
  end

  def oid(oid) when is_tuple(oid) and tuple_size(oid) >= 2, do: oid
  def oid(other), do: raise(ArgumentError, "unknown OID name: #{inspect(other)}")

  @doc """
  The name of an OID, or the OID itself when it has none.

      iex> Cmsex.OID.name({1, 2, 840, 113549, 1, 7, 2})
      :signed_data
      iex> Cmsex.OID.name({1, 2, 3})
      {1, 2, 3}
  """
  @spec name(t()) :: name() | t()
  for {name, oid} <- @table do
    def name(unquote(Macro.escape(oid))), do: unquote(name)
  end

  def name(oid) when is_tuple(oid), do: oid
  def name(name) when is_atom(name), do: name

  @doc """
  The dotted form of an OID or of a name.

      iex> Cmsex.OID.dotted(:sha256)
      "2.16.840.1.101.3.4.2.1"
  """
  @spec dotted(name() | t()) :: String.t()
  def dotted(oid), do: oid |> oid() |> Tuple.to_list() |> Enum.join(".")

  @doc false
  # The content octets of an OBJECT IDENTIFIER (X.690 8.19).
  @spec encode(name() | t()) :: binary()
  def encode(oid) do
    [first, second | rest] = oid |> oid() |> Tuple.to_list()

    if first not in 0..2 or second < 0 or (first < 2 and second > 39) or
         Enum.any?(rest, &(&1 < 0)) do
      raise ArgumentError, "invalid OID: #{inspect(oid)}"
    end

    for arc <- [first * 40 + second | rest], into: <<>>, do: base128(arc)
  end

  defp base128(arc) when arc < 0x80, do: <<arc>>
  defp base128(arc), do: base128(arc >>> 7, <<arc &&& 0x7F>>)

  defp base128(0, acc), do: acc
  defp base128(arc, acc), do: base128(arc >>> 7, <<1::1, arc::7, acc::binary>>)

  @doc false
  # Reads the content octets of an OBJECT IDENTIFIER. A subidentifier must
  # not start with 0x80 (X.690 8.19.2).
  @spec decode(binary()) :: {:ok, t()} | :error
  def decode(<<_, _::binary>> = bin) do
    case arcs(bin, 0, false, []) do
      {:ok, [first | rest]} ->
        {a, b} = split_first(first)
        {:ok, List.to_tuple([a, b | rest])}

      :error ->
        :error
    end
  end

  def decode(_bin), do: :error

  defp arcs(<<>>, _n, false, acc), do: {:ok, Enum.reverse(acc)}
  defp arcs(<<>>, _n, true, _acc), do: :error
  defp arcs(<<0x80, _::binary>>, _n, false, _acc), do: :error

  defp arcs(<<1::1, bits::7, rest::binary>>, n, _open, acc),
    do: arcs(rest, n <<< 7 ||| bits, true, acc)

  defp arcs(<<0::1, bits::7, rest::binary>>, n, _open, acc),
    do: arcs(rest, 0, false, [n <<< 7 ||| bits | acc])

  defp split_first(n) when n < 40, do: {0, n}
  defp split_first(n) when n < 80, do: {1, n - 40}
  defp split_first(n), do: {2, n - 80}
end
