# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.GenericTest do
  use ExUnit.Case

  alias NervesDiscovery.Generic.Protocol

  describe "Protocol.create_query/1" do
    test "creates a valid mDNS PTR query packet" do
      packet = Protocol.create_query("_nerves-device._tcp.local")

      assert is_binary(packet)
      # Verify it's a valid DNS packet by decoding it
      {:ok, msg} = :inet_dns.decode(packet)
      [qd] = :inet_dns.msg(msg, :qdlist)
      assert :inet_dns.dns_query(qd, :type) == :ptr
      assert :inet_dns.dns_query(qd, :domain) == ~c"_nerves-device._tcp.local"
    end
  end

  describe "Protocol.process_response/3" do
    test "processes mDNS response with PTR, SRV, A, and TXT records" do
      # Build mDNS response packet
      ptr_rr =
        :inet_dns.make_rr(
          domain: ~c"_nerves-device._tcp.local",
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"nerves-1234._nerves-device._tcp.local"
        )

      srv_rr =
        :inet_dns.make_rr(
          domain: ~c"nerves-1234._nerves-device._tcp.local",
          type: :srv,
          class: :in,
          ttl: 120,
          data: {0, 0, 4000, ~c"nerves-1234.local"}
        )

      txt_rr =
        :inet_dns.make_rr(
          domain: ~c"nerves-1234._nerves-device._tcp.local",
          type: :txt,
          class: :in,
          ttl: 120,
          data: [~c"serial=ABC123", ~c"version=1.0.0", ~c"product=rpi4"]
        )

      a_rr =
        :inet_dns.make_rr(
          domain: ~c"nerves-1234.local",
          type: :a,
          class: :in,
          ttl: 120,
          data: {192, 168, 1, 100}
        )

      response =
        :inet_dns.make_msg(
          header: :inet_dns.make_header(qr: true),
          anlist: [ptr_rr, srv_rr, a_rr, txt_rr]
        )

      encoded_response = :inet_dns.encode(response)

      acc = Protocol.new_accumulator()
      acc = Protocol.process_response(encoded_response, acc, "_nerves-device._tcp.local")

      assert acc.instances["nerves-1234"] == ["nerves-1234"]
      assert acc.srvs["nerves-1234"] == {"nerves-1234.local", 4000}
      assert MapSet.member?(acc.addrs_v4["nerves-1234.local"], "192.168.1.100")

      assert acc.txts["nerves-1234"] == %{
               "serial" => "ABC123",
               "version" => "1.0.0",
               "product" => "rpi4"
             }
    end

    test "filters out PTR records for other services" do
      # SSH service PTR record (should be ignored)
      ssh_ptr_rr =
        :inet_dns.make_rr(
          domain: ~c"_ssh._tcp.local",
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"GL-RM1-bfb._ssh._tcp.local"
        )

      # Nerves service PTR record (should be processed)
      nerves_ptr_rr =
        :inet_dns.make_rr(
          domain: ~c"_nerves-device._tcp.local",
          type: :ptr,
          class: :in,
          ttl: 120,
          data: ~c"nerves-1234._nerves-device._tcp.local"
        )

      response =
        :inet_dns.make_msg(
          header: :inet_dns.make_header(qr: true),
          anlist: [ssh_ptr_rr, nerves_ptr_rr]
        )

      encoded_response = :inet_dns.encode(response)

      acc = Protocol.new_accumulator()
      acc = Protocol.process_response(encoded_response, acc, "_nerves-device._tcp.local")

      # Only nerves-1234 should be in instances, not GL-RM1-bfb
      assert acc.instances == %{"nerves-1234" => ["nerves-1234"]}
      assert Map.has_key?(acc.instances, "GL-RM1-bfb") == false
    end
  end

  describe "Protocol.assemble_results/1" do
    test "assembles device info from accumulated records" do
      acc = %{
        instances: %{"nerves-1234" => ["nerves-1234"]},
        srvs: %{"nerves-1234" => {"nerves-1234.local", 4000}},
        addrs_v4: %{"nerves-1234.local" => MapSet.new(["192.168.1.100"])},
        txts: %{
          "nerves-1234" => %{
            "serial" => "ABC123",
            "version" => "1.0.0",
            "product" => "rpi4",
            "platform" => "linux"
          }
        }
      }

      [device] = Protocol.assemble_results(acc)

      assert device.name == "nerves-1234"
      assert device.hostname == "nerves-1234.local"
      assert device.ip == "192.168.1.100"
      assert device.serial == "ABC123"
      assert device.version == "1.0.0"
      assert device.product == "rpi4"
      assert device.platform == "linux"
    end

    test "filters out devices without addresses" do
      acc = %{
        instances: %{
          "nerves-1234" => ["nerves-1234"],
          "nerves-5678" => ["nerves-5678"]
        },
        srvs: %{
          "nerves-1234" => {"nerves-1234.local", 4000},
          "nerves-5678" => {"nerves-5678.local", 4000}
        },
        addrs_v4: %{
          "nerves-1234.local" => MapSet.new(["192.168.1.100"])
          # nerves-5678 has no address
        },
        txts: %{}
      }

      devices = Protocol.assemble_results(acc)

      assert length(devices) == 1
      assert hd(devices).name == "nerves-1234"
    end
  end
end
