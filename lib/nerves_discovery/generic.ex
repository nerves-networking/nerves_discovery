# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.Generic do
  @moduledoc false

  # This implementation works across platforms without requiring external tools
  # like dns-sd or avahi. It uses UDP multicast to query mDNS directly.

  import Bitwise

  alias NervesDiscovery.Generic.Protocol

  @mcast_ip {224, 0, 0, 251}
  @mdns_port 5353

  @doc """
  Discover Nerves devices by querying mDNS services.
  """
  @spec discover_service(String.t(), non_neg_integer()) :: [map()]
  def discover_service(service, timeout) do
    service_name = service <> ".local"

    {:ok, sock} = :socket.open(:inet, :dgram, :udp)

    try do
      :ok = configure_socket(sock)
      packet = Protocol.create_query(service_name)
      destination = %{family: :inet, addr: @mcast_ip, port: @mdns_port}

      case :socket.sendto(sock, packet, destination) do
        :ok ->
          acc = collect_results(sock, timeout, service_name)
          Protocol.assemble_results(acc)

        {:error, :enetunreach} ->
          []
      end
    after
      :ok = :socket.close(sock)
    end
  end

  defp configure_socket(sock) do
    :ok = :socket.setopt(sock, :socket, :reuseaddr, true)
    :ok = :socket.setopt(sock, :socket, :reuseport, true)

    case :socket.setopt(sock, :ip, :pktinfo, true) do
      :ok -> :ok
      {:error, reason} -> raise "mDNS requires IPv4 packet information: #{inspect(reason)}"
    end

    :ok = :socket.bind(sock, %{family: :inet, port: @mdns_port})

    :ok =
      :socket.setopt(sock, :ip, :add_membership, %{multiaddr: @mcast_ip, interface: {0, 0, 0, 0}})

    :ok = :socket.setopt(sock, :ip, :multicast_loop, true)
    :socket.setopt(sock, :ip, :multicast_ttl, 1)
  end

  defp collect_results(sock, timeout_ms, service) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    acc = Protocol.new_accumulator()
    receive_loop(sock, deadline, acc, service)
  end

  defp receive_loop(sock, deadline, acc, service) do
    now = System.monotonic_time(:millisecond)
    remaining = deadline - now

    if remaining <= 0 do
      acc
    else
      case :socket.recvmsg(sock, 65535, 1024, [], remaining) do
        {:ok, message} ->
          acc = process_message(message, acc, service)
          receive_loop(sock, deadline, acc, service)

        {:error, :timeout} ->
          acc

        {:error, reason} ->
          raise "mDNS receive failed: #{inspect(reason)}"
      end
    end
  end

  defp process_message(message, acc, service) do
    if local_response?(message) do
      Protocol.process_response(IO.iodata_to_binary(message.iov), acc, service)
    else
      acc
    end
  end

  defp local_response?(%{
         addr: %{family: :inet, addr: source, port: @mdns_port},
         ctrl: ctrl,
         flags: flags
       }) do
    if :trunc in flags or :ctrunc in flags do
      false
    else
      Enum.any?(ctrl, fn
        %{level: :ip, type: :pktinfo, value: %{addr: destination, ifindex: index}}
        when index > 0 ->
          local_source?(source, destination, index)

        _ ->
          false
      end)
    end
  end

  defp local_response?(_message), do: false

  defp local_source?(source, destination, index) do
    {:ok, names} = :net.if_names()
    {:ok, interfaces} = :net.getifaddrs()

    case List.keyfind(names, index, 0) do
      {^index, name} ->
        Enum.any?(interfaces, fn
          %{
            name: ^name,
            flags: flags,
            addr: %{family: :inet, addr: address},
            netmask: %{addr: mask}
          } ->
            # RFC 6762 Section 11 permits multicast peers on overlaid logical subnets.
            :up in flags and
              (destination == @mcast_ip or same_subnet?(source, address, mask))

          _ ->
            false
        end)

      nil ->
        false
    end
  end

  defp same_subnet?(source, address, mask) do
    (ipv4_integer(source) &&& ipv4_integer(mask)) ==
      (ipv4_integer(address) &&& ipv4_integer(mask))
  end

  defp ipv4_integer({a, b, c, d}), do: a <<< 24 ||| b <<< 16 ||| c <<< 8 ||| d
end
