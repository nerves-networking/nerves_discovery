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
    {output, _} = System.shell("timeout #{timeout_secs} dns-sd -B #{service} 2>&1 || true")

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
    {output, _} = System.shell("timeout 0.2 dns-sd -L #{name} #{service} 2>&1 || true")

    device =
      case Regex.run(~r/can be reached at ([^\s:]+):/, output) do
        [_, hostname] ->
          hostname = String.trim_trailing(hostname, ".")
          {ip_output, _} = System.shell("timeout 0.2 dns-sd -G v4 #{hostname} 2>&1 || true")

          ip =
            case Regex.run(~r/Add\s+\S+\s+\d+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)/, ip_output) do
              [_, addr] -> addr
              _ -> nil
            end

          %{name: name, hostname: hostname, ip: ip}

        _ ->
          %{name: name}
      end

    if service == "_nerves-device._tcp", do: parse_txt_records(output, device), else: device
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
