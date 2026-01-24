# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.Avahi do
  @moduledoc false

  @doc """
  Discover devices advertising a specific mDNS service.
  """
  @spec discover_service(String.t(), non_neg_integer()) :: [map()]
  def discover_service(service, timeout) do
    timeout_secs = max(div(timeout, 1000), 1)

    {output, _} =
      System.cmd("timeout", [to_string(timeout_secs), "avahi-browse", "-rtp", service],
        stderr_to_stdout: true
      )

    output
    |> String.split("\n")
    |> Enum.flat_map(fn line ->
      # Format with -p flag: "=;interface;IPv4;name;type;local;hostname;ip;port;txt..."
      case String.split(line, ";") do
        ["=", _interface, "IPv4", name, _type, "local", hostname, ip, _port | txt_parts] ->
          device = %{name: name, hostname: hostname, ip: ip}
          # TXT records come as space-separated quoted strings in one field
          txt_string = List.first(txt_parts, "")
          txt_records = parse_txt_string(txt_string)
          [parse_txt_records(device, txt_records)]

        _ ->
          []
      end
    end)
  end

  defp parse_txt_string(""), do: []

  defp parse_txt_string(txt_string) do
    # Split by spaces but keep quoted strings together
    # Format: "key1=value1" "key2=value2" ...
    Regex.scan(~r/"([^"]*)"/, txt_string)
    |> Enum.map(fn [_, txt] -> txt end)
  end

  defp parse_txt_records(device, txt_parts) do
    txt_fields = [
      :serial,
      :version,
      :product,
      :description,
      :platform,
      :architecture,
      :author,
      :uuid
    ]

    Enum.reduce(txt_fields, device, fn field, dev ->
      value = extract_txt_value(txt_parts, field)
      Map.put(dev, field, value)
    end)
  end

  defp extract_txt_value(txt_parts, field) do
    field_str = Atom.to_string(field)

    Enum.find_value(txt_parts, fn part ->
      # Format: field=value (no quotes after extraction)
      if String.starts_with?(part, "#{field_str}=") do
        String.trim_leading(part, "#{field_str}=")
      end
    end)
  end
end
