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
    |> Enum.reduce(%{}, fn line, acc ->
      case parse_line(line) do
        nil -> acc
        device -> Map.update(acc, device.name, device, &merge_devices(&1, device))
      end
    end)
    |> Map.values()
  end

  defp parse_line(line) do
    # Format with -p flag: "=;interface;IPv4;name;type;local;hostname;ip;port;txt..."
    case String.split(line, ";") do
      ["=", _interface, "IPv4", name, _type, "local", hostname, ip_string, _port | txt_parts] ->
        {:ok, ip} = ip_string |> String.to_charlist() |> :inet.parse_address()
        device = %{name: name, hostname: hostname, addresses: [ip]}
        # TXT records come as space-separated quoted strings in one field
        txt_string = List.first(txt_parts, "")
        txt_records = parse_txt_string(txt_string)
        parse_txt_records(device, txt_records)

      _ ->
        nil
    end
  end

  defp merge_devices(existing, incoming) do
    merged_addresses = Enum.uniq(existing.addresses ++ incoming.addresses)

    existing
    |> Map.put(:addresses, merged_addresses)
    |> merge_txt_fields(incoming)
  end

  defp merge_txt_fields(existing, incoming) do
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

    Enum.reduce(txt_fields, existing, fn field, acc ->
      case {Map.get(acc, field), Map.get(incoming, field)} do
        {nil, val} when not is_nil(val) -> Map.put(acc, field, val)
        {"", val} when val not in [nil, ""] -> Map.put(acc, field, val)
        _ -> acc
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
