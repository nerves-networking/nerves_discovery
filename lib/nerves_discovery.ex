# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery do
  @moduledoc """
  Discover Nerves devices on the local network using mDNS.

  Supports macOS (dns-sd), Linux (avahi), and other platforms (generic OTP).
  """

  @typedoc """
  Options for `discover/1`
  """
  @type options() :: [timeout: non_neg_integer(), method: :auto | :macos | :avahi | :generic]

  @typedoc """
  Information about each found Nerves device

  * `:name` - name of the Nerves device
  * `:hostname` - hostname o the device (usually the name with `.local`)
  * `:ip` - the first IP address of the device
  * `:serial` - the device's serial number if included in the advertisement
  * `:version` - the device's firmware version if included in the advertisement
  * `:product` - the device's product if included in the advertisement
  * `:description` - the device's description if included in the advertisement
  * `:platform` - the device's platform if included in the advertisement
  * `:architecture` - the device's CPU architecture if included in the advertisement
  * `:author` - the device's firmware author if included in the advertisement
  * `:uuid` - the device's firmware UUID if included in the advertisement
  """
  @type result() :: %{
          name: String.t(),
          hostname: String.t(),
          ip: String.t(),
          serial: String.t() | nil,
          version: String.t() | nil,
          product: String.t() | nil,
          description: String.t() | nil,
          platform: String.t() | nil,
          architecture: String.t() | nil,
          author: String.t() | nil,
          uuid: String.t() | nil
        }

  @doc """
  Discover Nerves devices on the local network.

  Options:
  * `:timeout` - timeout in milliseconds to wait for replies (default 5000 ms)
  * `:method` - method to use for querying mDNS (`:auto`, `:macos`, `:avahi`, `:generic`)

  ## Examples

      iex> NervesDiscovery.discover()
      [%{name: "nerves-1234", hostname: "nerves-1234.local", ip: "192.168.1.100"}]
  """
  @spec discover(options()) :: [result()]
  def discover(opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5000)
    discover = discover_fun(Keyword.get(opts, :method, :auto))

    [
      Task.async(fn -> discover.("_ssh._tcp", timeout) |> filter_nerves() end),
      Task.async(fn -> discover.("_nerves-device._tcp", timeout) end)
    ]
    |> Task.await_many(timeout + 1000)
    |> then(fn [ssh, nerves] -> nerves ++ ssh end)
    |> Enum.uniq_by(fn device -> Map.get(device, :name) end)
  end

  defp filter_nerves(results) do
    Enum.filter(results, &String.starts_with?(&1.name, "nerves-"))
  end

  defp discover_fun(:auto) do
    cond do
      :os.type() == {:unix, :darwin} ->
        &NervesDiscovery.MacOS.discover_service/2

      System.find_executable("avahi-browse") ->
        &NervesDiscovery.Avahi.discover_service/2

      true ->
        &NervesDiscovery.Generic.discover_service/2
    end
  end

  defp discover_fun(:macos), do: &NervesDiscovery.MacOS.discover_service/2
  defp discover_fun(:avahi), do: &NervesDiscovery.Avahi.discover_service/2
  defp discover_fun(:generic), do: &NervesDiscovery.Generic.discover_service/2
end
