# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscoveryTest do
  use ExUnit.Case
  use Mimic

  describe "discover/1" do
    test "merges results from SSH and nerves-device services" do
      ssh_browse = """
      Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
      12:30:45.456  Add        2   4 local.               _ssh._tcp.           nerves-1234
      """

      ssh_lookup = """
      nerves-1234._ssh._tcp.local. can be reached at nerves-1234.local.:22
      """

      ssh_getaddr = """
      Timestamp     A/R Flags if Hostname                               Address                                      TTL
      12:30:46.456  Add     2  4 nerves-1234.local.                     192.168.1.100                                120
      """

      nerves_browse = """
      Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
      12:30:45.456  Add        2   4 local.               _nerves-device._tcp. nerves-1234
      """

      nerves_lookup = """
      nerves-1234._nerves-device._tcp.local. can be reached at nerves-1234.local.:4000
      serial=ABC123
      version=1.2.3
      uuid=182c7114-4fa2-5faf-904b-cdc94e6845bb
      architecture=aarch64
      product=Product
      description=A Description
      platform=rpi5
      something_extra=1248
      """

      nerves_getaddr = ssh_getaddr

      stub(System, :cmd, fn cmd, args, _opts ->
        case {cmd, args} do
          {"timeout", [_, "dns-sd", "-B", "_ssh._tcp"]} ->
            {ssh_browse, 0}

          {"timeout", [_, "dns-sd", "-B", "_nerves-device._tcp"]} ->
            {nerves_browse, 0}

          {"timeout", [_, "dns-sd", "-L", "nerves-1234", "_ssh._tcp"]} ->
            {ssh_lookup, 0}

          {"timeout", [_, "dns-sd", "-L", "nerves-1234", "_nerves-device._tcp"]} ->
            {nerves_lookup, 0}

          {"timeout", [_, "dns-sd", "-G", "v4", "nerves-1234.local"]} ->
            {nerves_getaddr, 0}
        end
      end)

      results = NervesDiscovery.discover(method: :macos)

      assert results == [
               %{
                 addresses: [{192, 168, 1, 100}],
                 architecture: "aarch64",
                 author: nil,
                 description: "A Description",
                 hostname: "nerves-1234.local",
                 ip: "192.168.1.100",
                 name: "nerves-1234",
                 platform: "rpi5",
                 product: "Product",
                 serial: "ABC123",
                 uuid: "182c7114-4fa2-5faf-904b-cdc94e6845bb",
                 version: "1.2.3"
               }
             ]
    end

    test "merges and deduplicates addresses from different services" do
      ssh_browse = """
      Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
      12:30:45.456  Add        2   4 local.               _ssh._tcp.           nerves-5678
      """

      ssh_lookup = """
      nerves-5678._ssh._tcp.local. can be reached at nerves-5678.local.:22
      """

      ssh_getaddr = """
      Timestamp     A/R Flags if Hostname                               Address                                      TTL
      12:30:46.456  Add     2  4 nerves-5678.local.                     192.168.1.101                                120
      """

      nerves_browse = """
      Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
      12:30:45.456  Add        2   4 local.               _nerves-device._tcp. nerves-5678
      """

      nerves_lookup = """
      nerves-5678._nerves-device._tcp.local. can be reached at nerves-5678.local.:4000
      serial=DEF456
      version=2.0.0
      """

      nerves_getaddr = """
      Timestamp     A/R Flags if Hostname                               Address                                      TTL
      12:30:46.456  Add     2  4 nerves-5678.local.                     192.168.1.102                                120
      """

      # Counter to track calls and return different addresses for SSH vs nerves-device service
      getaddr_count = :counters.new(1, [:atomics])

      stub(System, :cmd, fn cmd, args, _opts ->
        case {cmd, args} do
          {"timeout", [_, "dns-sd", "-B", "_ssh._tcp"]} ->
            {ssh_browse, 0}

          {"timeout", [_, "dns-sd", "-B", "_nerves-device._tcp"]} ->
            {nerves_browse, 0}

          {"timeout", [_, "dns-sd", "-L", "nerves-5678", "_ssh._tcp"]} ->
            {ssh_lookup, 0}

          {"timeout", [_, "dns-sd", "-L", "nerves-5678", "_nerves-device._tcp"]} ->
            {nerves_lookup, 0}

          {"timeout", [_, "dns-sd", "-G", "v4", "nerves-5678.local"]} ->
            # First call (SSH service) returns 192.168.1.101
            # Second call (nerves-device service) returns 192.168.1.102
            count = :counters.get(getaddr_count, 1)
            :counters.add(getaddr_count, 1, 1)

            if count == 0 do
              {ssh_getaddr, 0}
            else
              {nerves_getaddr, 0}
            end
        end
      end)

      results = NervesDiscovery.discover(method: :macos)

      # Should have both addresses from SSH and nerves-device services
      assert [device] = results
      assert device.name == "nerves-5678"
      assert device.hostname == "nerves-5678.local"
      # Addresses should be merged and deduplicated
      assert Enum.sort(device.addresses) == [{192, 168, 1, 101}, {192, 168, 1, 102}]
      assert device.serial == "DEF456"
      assert device.version == "2.0.0"
    end

    test "deduplicates identical addresses from different services" do
      ssh_browse = """
      Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
      12:30:45.456  Add        2   4 local.               _ssh._tcp.           nerves-9999
      """

      ssh_lookup = """
      nerves-9999._ssh._tcp.local. can be reached at nerves-9999.local.:22
      """

      nerves_browse = """
      Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
      12:30:45.456  Add        2   4 local.               _nerves-device._tcp. nerves-9999
      """

      nerves_lookup = """
      nerves-9999._nerves-device._tcp.local. can be reached at nerves-9999.local.:4000
      serial=GHI789
      """

      # Both services return the same address
      same_getaddr = """
      Timestamp     A/R Flags if Hostname                               Address                                      TTL
      12:30:46.456  Add     2  4 nerves-9999.local.                     10.0.0.50                                    120
      """

      stub(System, :cmd, fn cmd, args, _opts ->
        case {cmd, args} do
          {"timeout", [_, "dns-sd", "-B", "_ssh._tcp"]} ->
            {ssh_browse, 0}

          {"timeout", [_, "dns-sd", "-B", "_nerves-device._tcp"]} ->
            {nerves_browse, 0}

          {"timeout", [_, "dns-sd", "-L", "nerves-9999", "_ssh._tcp"]} ->
            {ssh_lookup, 0}

          {"timeout", [_, "dns-sd", "-L", "nerves-9999", "_nerves-device._tcp"]} ->
            {nerves_lookup, 0}

          {"timeout", [_, "dns-sd", "-G", "v4", "nerves-9999.local"]} ->
            {same_getaddr, 0}
        end
      end)

      results = NervesDiscovery.discover(method: :macos)

      # Should deduplicate the address
      assert [device] = results
      assert device.name == "nerves-9999"
      assert device.addresses == [{10, 0, 0, 50}]
      assert device.serial == "GHI789"
    end
  end
end
