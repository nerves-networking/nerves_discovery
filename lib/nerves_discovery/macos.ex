# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.MacOS do
  @moduledoc false

  @doc """
  Discover devices advertising a specific mDNS service
  """
  @spec discover_service(String.t(), non_neg_integer()) :: [map()]
  def discover_service(service, timeout) do
    timeout_secs = min(div(timeout, 1000), 1)

    {output, _} =
      System.cmd("timeout", [to_string(timeout_secs), "dns-sd", "-B", service],
        stderr_to_stdout: true
      )

    output
    |> String.split("\n")
    |> Enum.flat_map(fn line ->
      case Regex.run(~r/Add\s+\d+\s+\d+\s+\S+\s+#{Regex.escape(service)}\.\s+(\S+)/, line) do
        [_, name] -> [String.trim_trailing(name, ".")]
        _ -> []
      end
    end)
    |> Task.async_stream(&resolve_device(&1, service),
      max_concurrency: 10,
      timeout: div(timeout, 1000) * 1000,
      on_timeout: :kill_task
    )
    |> Enum.flat_map(fn
      {:ok, device} -> [device]
      _ -> []
    end)
  end

  defp resolve_device(name, service) do
    {output, _} =
      System.cmd("timeout", ["0.2", "dns-sd", "-L", name, service], stderr_to_stdout: true)

    device = build_device(name, output)

    if service == "_nerves-device._tcp", do: parse_txt_records(output, device), else: device
  end

  defp build_device(name, output) do
    case Regex.run(~r/can be reached at ([^\s:]+):/, output) do
      [_, hostname] ->
        hostname = String.trim_trailing(hostname, ".")
        addresses = resolve_addresses(hostname)
        %{name: name, hostname: hostname, addresses: addresses}

      _ ->
        %{name: name}
    end
  end

  defp resolve_addresses(hostname) do
    {ip_output, _} =
      System.cmd("timeout", ["1.0", "dns-sd", "-G", "v4", hostname], stderr_to_stdout: true)

    ip_output
    |> String.split("\n")
    |> Enum.flat_map(fn line ->
      case Regex.run(~r/Add\s+\S+\s+\d+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)/, line) do
        [_, addr] -> [parse_address!(addr)]
        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  defp parse_address!(string) do
    {:ok, ip} = string |> String.to_charlist() |> :inet.parse_address()
    ip
  end

  defp parse_txt_records(output, device) do
    [:serial, :version, :product, :description, :platform, :architecture, :author, :uuid]
    |> Enum.reduce(device, fn field, dev ->
      case String.split(output, "#{field}=", parts: 2) do
        [_, rest] ->
          [value | _] = String.split(rest, ~r/\s+(?=\w+=)|\n/, parts: 2)
          Map.put(dev, field, String.replace(value, "\\ ", " "))

        _ ->
          dev
      end
    end)
  end
end
