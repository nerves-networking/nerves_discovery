# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.Generic.Protocol do
  @moduledoc false

  # This module handles encoding/decoding mDNS packets and processing responses
  # without any I/O operations.

  @doc """
  Create an mDNS PTR query packet for the given service.
  """
  @spec create_query(String.t()) :: binary()
  def create_query(service) do
    qd = :inet_dns.make_dns_query(domain: to_charlist(service), type: :ptr, class: :in)
    message = :inet_dns.make_msg(header: :inet_dns.make_header(opcode: :query), qdlist: [qd])
    :inet_dns.encode(message)
  end

  @doc """
  Process an mDNS response packet and update the accumulator.
  """
  @spec process_response(binary(), map(), String.t()) :: map()
  def process_response(packet, acc, service) when is_binary(packet) do
    {:ok, msg} = :inet_dns.decode(packet)
    anlist = :inet_dns.msg(msg, :anlist) || []
    nslist = :inet_dns.msg(msg, :nslist) || []
    arlist = :inet_dns.msg(msg, :arlist) || []

    all_rrs = anlist ++ nslist ++ arlist
    fold_rrs(all_rrs, acc, service)
  rescue
    _ -> acc
  end

  @doc """
  Create an empty accumulator for storing mDNS responses.
  """
  @spec new_accumulator() :: %{instances: %{}, addrs_v4: %{}, srvs: %{}, txts: %{}}
  def new_accumulator() do
    %{instances: %{}, addrs_v4: %{}, srvs: %{}, txts: %{}}
  end

  @doc """
  Assemble the final device list from the accumulator.
  """
  @spec assemble_results(map()) :: [map()]
  def assemble_results(acc) do
    acc.instances
    |> Enum.flat_map(fn {name, _} ->
      {host, _port} = Map.get(acc.srvs, name, {nil, nil})
      addrs = find_addresses(host, acc)
      txt = Map.get(acc.txts, name, %{})

      # Only include if we have addresses
      if addrs != [] do
        [
          %{
            name: name,
            hostname: host || "#{name}.local",
            ip: List.first(addrs),
            serial: Map.get(txt, "serial"),
            version: Map.get(txt, "version"),
            product: Map.get(txt, "product"),
            description: Map.get(txt, "description"),
            platform: Map.get(txt, "platform"),
            architecture: Map.get(txt, "architecture"),
            author: Map.get(txt, "author"),
            uuid: Map.get(txt, "uuid")
          }
        ]
      else
        []
      end
    end)
  end

  defp fold_rrs(rrs, acc, service) do
    {final_acc, _} =
      Enum.reduce(rrs, {acc, %{ptr: nil, srv: nil}}, fn rr, {acc0, context} ->
        type = :inet_dns.rr(rr, :type)
        domain = :inet_dns.rr(rr, :domain) |> :binary.list_to_bin()
        data = :inet_dns.rr(rr, :data)

        case type do
          :ptr -> process_ptr(data, domain, service, acc0, context)
          :srv -> process_srv(data, domain, acc0, context)
          :txt -> process_txt(data, domain, acc0, context)
          :a -> process_a(data, domain, acc0, context)
          _ -> {acc0, context}
        end
      end)

    final_acc
  end

  defp process_ptr(data, domain, service, acc, context) do
    # Only process PTR records for the service we're querying
    if domain == service do
      ptr_target = :binary.list_to_bin(data)
      instance_name = String.split(ptr_target, ".", parts: 2) |> List.first()

      new_acc =
        Map.update!(acc, :instances, fn instances ->
          Map.update(instances, instance_name, [instance_name], fn existing ->
            [instance_name | existing] |> Enum.uniq()
          end)
        end)

      {new_acc, %{context | ptr: ptr_target}}
    else
      {acc, context}
    end
  end

  defp process_srv(data, domain, acc, context) do
    {_priority, _weight, port, target} = data
    target_str = :binary.list_to_bin(target)

    srv_key = get_record_key(domain, context.ptr)

    new_acc =
      Map.update!(acc, :srvs, fn srvs ->
        Map.put(srvs, srv_key, {target_str, port})
      end)

    {new_acc, %{context | srv: target_str}}
  end

  defp process_txt(data, domain, acc, context) do
    txt_data = parse_txt_from_inet_dns(data)
    txt_key = get_record_key(domain, context.ptr)

    new_acc =
      Map.update!(acc, :txts, fn txts ->
        Map.update(txts, txt_key, txt_data, &Map.merge(&1, txt_data))
      end)

    {new_acc, context}
  end

  defp process_a(data, domain, acc, context) do
    ip = :inet.ntoa(data) |> to_string()
    hostname = if domain == "" and context.srv, do: context.srv, else: domain

    new_acc =
      Map.update!(acc, :addrs_v4, fn addrs ->
        Map.update(addrs, hostname, MapSet.new([ip]), &MapSet.put(&1, ip))
      end)

    {new_acc, context}
  end

  defp get_record_key(domain, ptr) do
    if ptr && domain == ptr do
      String.split(ptr, ".", parts: 2) |> List.first()
    else
      domain
    end
  end

  defp parse_txt_from_inet_dns(data) when is_list(data) do
    data
    |> Enum.reduce(%{}, fn item, acc ->
      case item do
        s when is_list(s) ->
          parse_txt_entry(:binary.list_to_bin(s), acc)

        s when is_binary(s) ->
          parse_txt_entry(s, acc)

        _ ->
          acc
      end
    end)
  end

  defp parse_txt_entry(entry, acc) do
    case String.split(entry, "=", parts: 2) do
      [k, v] -> Map.put(acc, k, v)
      [k] -> Map.put(acc, k, "")
      _ -> acc
    end
  end

  defp find_addresses(host, acc) do
    case Map.get(acc.addrs_v4, host) do
      addr_set when is_struct(addr_set, MapSet) ->
        MapSet.to_list(addr_set)

      _ ->
        []
    end
  end
end
