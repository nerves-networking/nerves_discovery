# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.Generic do
  @moduledoc false

  # This implementation works across platforms without requiring external tools
  # like dns-sd or avahi. It uses UDP multicast to query mDNS directly.

  alias NervesDiscovery.Generic.Protocol

  @mcast_ip {224, 0, 0, 251}
  @mdns_port 5353

  @doc """
  Discover Nerves devices by querying mDNS services.
  """
  @spec discover_service(String.t(), non_neg_integer()) :: [map()]
  def discover_service(service, timeout) do
    service_name = service <> ".local"

    {:ok, sock} = open_socket()

    try do
      packet = Protocol.create_query(service_name)
      :ok = :gen_udp.send(sock, @mcast_ip, @mdns_port, packet)

      acc = collect_results(sock, timeout, service_name)
      Protocol.assemble_results(acc)
    after
      :gen_udp.close(sock)
    end
  end

  defp open_socket() do
    {:ok, sock} =
      :gen_udp.open(@mdns_port, [
        :binary,
        {:reuseaddr, true},
        {:reuseport, true},
        {:active, true}
      ])

    # Join IPv4 mDNS multicast
    :ok = :inet.setopts(sock, [{:add_membership, {@mcast_ip, {0, 0, 0, 0}}}])
    :ok = :inet.setopts(sock, [{:multicast_loop, true}, {:multicast_ttl, 1}])
    {:ok, sock}
  end

  defp collect_results(sock, timeout_ms, service) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    acc = Protocol.new_accumulator()
    receive_loop(sock, deadline, acc, service)
  end

  defp receive_loop(sock, deadline, acc, service) do
    now = System.monotonic_time(:millisecond)
    remaining = max(deadline - now, 0)

    receive do
      {:udp, ^sock, _ip, @mdns_port, bin} ->
        acc = Protocol.process_response(bin, acc, service)
        receive_loop(sock, deadline, acc, service)
    after
      remaining -> acc
    end
  end
end
