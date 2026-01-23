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
  end
end
