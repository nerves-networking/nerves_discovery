# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.MacOS do
  @moduledoc false

  defmodule Browser do
    @moduledoc false

    @idle_timeout 500

    @spec start(String.t(), non_neg_integer()) :: {reference(), reference()}
    def start(service, timeout) do
      receiver = self()
      tag = make_ref()

      {:ok, pid} = Task.start(fn -> run(receiver, tag, service, timeout) end)
      {Process.monitor(pid), tag}
    end

    @doc false
    @spec open(String.t(), non_neg_integer()) :: port()
    def open(service, timeout) do
      timeout_executable =
        System.find_executable("timeout") || raise "timeout executable not found"

      Port.open(
        {:spawn_executable, timeout_executable},
        [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          {:args, [timeout_arg(timeout), "dns-sd", "-B", service]},
          {:line, 16_384}
        ]
      )
    end

    defp run(receiver, tag, service, timeout) do
      port = __MODULE__.open(service, timeout)
      deadline = System.monotonic_time(:millisecond) + timeout

      try do
        collect_reports(port, receiver, tag, service, deadline, nil, "")
      after
        close(port)
      end
    end

    defp collect_reports(port, receiver, tag, service, deadline, idle_deadline, buffer) do
      next_deadline = min(deadline, idle_deadline || deadline)
      wait = max(next_deadline - System.monotonic_time(:millisecond), 0)

      if wait > 0 do
        receive do
          {^port, {:data, {:eol, line}}} ->
            idle_deadline = handle_report(buffer <> line, receiver, tag, service, idle_deadline)
            collect_reports(port, receiver, tag, service, deadline, idle_deadline, "")

          {^port, {:data, {:noeol, fragment}}} ->
            collect_reports(
              port,
              receiver,
              tag,
              service,
              deadline,
              idle_deadline,
              buffer <> fragment
            )

          {^port, {:exit_status, _status}} ->
            :ok
        after
          wait -> :ok
        end
      end
    end

    defp handle_report(line, receiver, tag, service, idle_deadline) do
      regex = ~r/Add\s+\d+\s+\d+\s+\S+\s+#{Regex.escape(service)}\.\s+(.+)$/

      case Regex.run(regex, line) do
        [_, name] ->
          send(receiver, {tag, {:report, String.trim(name)}})
          System.monotonic_time(:millisecond) + @idle_timeout

        _ ->
          idle_deadline
      end
    end

    defp close(port) do
      if is_port(port) && Port.info(port), do: Port.close(port)
      :ok
    end

    defp timeout_arg(timeout), do: to_string(max(timeout, 1) / 1000)
  end

  @doc """
  Discover devices advertising a specific mDNS service
  """
  @spec discover_service(String.t(), non_neg_integer()) :: [map()]
  def discover_service(service, timeout) do
    {monitor, tag} = Browser.start(service, timeout)

    monitor
    |> collect_resolutions(tag, service, [])
    |> Enum.reverse()
    |> Task.await_many(:infinity)
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
        new_device(name, hostname, addresses)

      _ ->
        new_device(name, name, [])
    end
  end

  defp collect_resolutions(monitor, tag, service, tasks) do
    receive do
      {^tag, {:report, name}} ->
        task = Task.async(fn -> resolve_device(name, service) end)
        collect_resolutions(monitor, tag, service, [task | tasks])

      {:DOWN, ^monitor, :process, _pid, :normal} ->
        tasks

      {:DOWN, ^monitor, :process, _pid, reason} ->
        exit(reason)
    end
  end

  defp new_device(name, hostname, addresses) do
    %{
      name: name,
      hostname: hostname,
      addresses: addresses,
      serial: nil,
      version: nil,
      product: nil,
      description: nil,
      platform: nil,
      architecture: nil,
      author: nil,
      uuid: nil
    }
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
