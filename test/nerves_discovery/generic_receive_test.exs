# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.GenericReceiveTest do
  use ExUnit.Case
  use Mimic

  alias NervesDiscovery.Generic

  @service "_nerves-device._tcp"
  @multicast {224, 0, 0, 251}
  @local {192, 168, 1, 10}
  @peer {192, 168, 1, 20}
  @remote {203, 0, 113, 66}

  setup do
    sock = make_ref()
    stub(:socket, :open, fn :inet, :dgram, :udp -> {:ok, sock} end)
    stub(:socket, :setopt, fn ^sock, _level, _option, _value -> :ok end)
    stub(:socket, :bind, fn ^sock, %{family: :inet, port: 5353} -> :ok end)
    stub(:socket, :sendto, fn ^sock, _packet, %{addr: @multicast, port: 5353} -> :ok end)
    expect(:socket, :close, fn ^sock -> :ok end)
    stub(:net, :if_names, fn -> {:ok, [{1, ~c"eth0"}, {2, ~c"eth1"}]} end)
    stub(:net, :getifaddrs, fn -> {:ok, [interface(~c"eth0", @local)]} end)
    {:ok, sock: sock}
  end

  test "rejects an off-subnet unicast response" do
    assert discover_with(packet(@remote, @local)) == []
  end

  test "accepts same-subnet unicast with unsolicited records" do
    assert [%{hostname: "nerves-test.local", addresses: [@remote]}] =
             discover_with(packet(@peer, @local))
  end

  test "accepts multicast from a different logical subnet on the same link" do
    assert [%{hostname: "nerves-test.local"}] =
             discover_with(packet(@remote, @multicast))
  end

  test "does not use another interface's subnet to validate a unicast response" do
    stub(:net, :getifaddrs, fn ->
      {:ok,
       [
         interface(~c"eth0", @local),
         interface(~c"eth1", {203, 0, 113, 10})
       ]}
    end)

    assert discover_with(packet(@remote, @local)) == []
  end

  test "accepts any subnet configured on the receiving interface" do
    stub(:net, :getifaddrs, fn ->
      {:ok,
       [
         interface(~c"eth0", @local),
         interface(~c"eth0", {203, 0, 113, 10})
       ]}
    end)

    assert [_device] = discover_with(packet(@remote, @local))
  end

  test "uses the configured netmask rather than assuming a /24 subnet" do
    stub(:net, :getifaddrs, fn ->
      {:ok,
       [
         put_in(interface(~c"eth0", @local).netmask.addr, {255, 255, 254, 0})
       ]}
    end)

    assert [_device] = discover_with(packet({192, 168, 0, 20}, @local))
  end

  test "rejects responses with missing packet information" do
    assert discover_with(%{packet(@peer, @local) | ctrl: []}) == []
  end

  test "rejects unknown receiving interfaces, even for multicast" do
    message = packet(@peer, @multicast)
    [info] = message.ctrl
    message = %{message | ctrl: [%{info | value: %{info.value | ifindex: 3}}]}
    assert discover_with(message) == []
  end

  test "rejects responses received on a down interface" do
    stub(:net, :getifaddrs, fn ->
      {:ok, [%{interface(~c"eth0", @local) | flags: []}]}
    end)

    assert discover_with(packet(@peer, @multicast)) == []
  end

  for flag <- [:trunc, :ctrunc] do
    test "rejects packets flagged #{flag}" do
      flag = unquote(flag)
      assert discover_with(%{packet(@peer, @local) | flags: [flag]}) == []
    end
  end

  test "rejects responses not sent from the mDNS port" do
    message = packet(@peer, @local)
    assert discover_with(%{message | addr: %{message.addr | port: 1234}}) == []
  end

  test "refreshes subnet information during discovery", %{sock: sock} do
    message = packet(@peer, @local)

    expect(:net, :getifaddrs, fn -> {:ok, [interface(~c"eth0", @local)]} end)

    expect(:net, :getifaddrs, fn ->
      {:ok, [interface(~c"eth0", {10, 0, 0, 1})]}
    end)

    expect(:socket, :recvmsg, fn ^sock, 65535, 1024, [], _ -> {:ok, message} end)
    changed_packet = put_in(message.iov, [response("nerves-changed")])
    expect(:socket, :recvmsg, fn ^sock, 65535, 1024, [], _ -> {:ok, changed_packet} end)
    expect(:socket, :recvmsg, fn ^sock, 65535, 1024, [], _ -> {:error, :timeout} end)

    assert [%{name: "nerves-test"}] = Generic.discover_service(@service, 1000)
  end

  test "does not wait for packets when the timeout is zero" do
    reject(:socket, :recvmsg, 5)
    assert Generic.discover_service(@service, 0) == []
  end

  test "a stream of rejected packets cannot extend the deadline", %{sock: sock} do
    stub(:socket, :recvmsg, fn ^sock, 65535, 1024, [], _ ->
      Process.sleep(5)
      {:ok, packet(@remote, @local)}
    end)

    started = System.monotonic_time(:millisecond)
    assert Generic.discover_service(@service, 20) == []
    assert System.monotonic_time(:millisecond) - started < 500
  end

  test "reports receive errors instead of returning successful empty results", %{sock: sock} do
    expect(:socket, :recvmsg, fn ^sock, 65535, 1024, [], _ -> {:error, :eio} end)

    assert_raise RuntimeError, "mDNS receive failed: :eio", fn ->
      Generic.discover_service(@service, 1000)
    end
  end

  test "reports errors reading interface configuration" do
    stub(:net, :getifaddrs, fn -> {:error, :eio} end)

    expect(:socket, :recvmsg, fn _, 65535, 1024, [], _ ->
      {:ok, packet(@peer, @local)}
    end)

    assert_raise MatchError, fn -> Generic.discover_service(@service, 1000) end
  end

  test "requires packet information and closes the socket if unavailable", %{sock: sock} do
    expect(:socket, :setopt, fn ^sock, :socket, :reuseaddr, true -> :ok end)
    expect(:socket, :setopt, fn ^sock, :socket, :reuseport, true -> :ok end)
    expect(:socket, :setopt, fn ^sock, :ip, :pktinfo, true -> {:error, :enoprotoopt} end)

    assert_raise RuntimeError, "mDNS requires IPv4 packet information: :enoprotoopt", fn ->
      Generic.discover_service(@service, 1000)
    end
  end

  defp discover_with(message) do
    expect(:socket, :recvmsg, fn _, 65535, 1024, [], _ -> {:ok, message} end)
    expect(:socket, :recvmsg, fn _, 65535, 1024, [], _ -> {:error, :timeout} end)
    Generic.discover_service(@service, 1000)
  end

  defp packet(source, destination) do
    %{
      addr: %{family: :inet, addr: source, port: 5353},
      iov: [response("nerves-test")],
      flags: [],
      ctrl: [
        %{level: :ip, type: :pktinfo, value: %{addr: destination, ifindex: 1}}
      ]
    }
  end

  defp interface(name, address) do
    %{
      name: name,
      flags: [:up],
      addr: %{family: :inet, addr: address},
      netmask: %{family: :inet, addr: {255, 255, 255, 0}}
    }
  end

  defp response(name) do
    instance = String.to_charlist("#{name}.#{@service}.local")
    host = String.to_charlist("#{name}.local")

    records = [
      :inet_dns.make_rr(
        domain: String.to_charlist(@service <> ".local"),
        type: :ptr,
        class: :in,
        ttl: 120,
        data: instance
      ),
      :inet_dns.make_rr(
        domain: instance,
        type: :srv,
        class: :in,
        ttl: 120,
        data: {0, 0, 22, host}
      ),
      :inet_dns.make_rr(domain: host, type: :a, class: :in, ttl: 120, data: @remote)
    ]

    :inet_dns.encode(:inet_dns.make_msg(header: :inet_dns.make_header(qr: true), anlist: records))
  end
end
