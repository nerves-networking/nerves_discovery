# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.MacOSTest do
  use ExUnit.Case
  use Mimic

  test "parses dns-sd browse output correctly" do
    browse_output = """
    Browsing for _ssh._tcp
    DATE: ---Sat 09 Jan 2026---
    12:30:45.123  ...STARTING...
    Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
    12:30:45.456  Add        2   4 local.               _ssh._tcp.           nerves-1234
    12:30:45.789  Add        2   4 local.               _ssh._tcp.           nerves-5678
    """

    lookup_output_1234 = """
    nerves-1234._ssh._tcp.local. can be reached at nerves-1234.local.:22
    serial=ABC123 version=1.0.0 product=rpi4
    """

    getaddr_output_1234 = """
    DATE: ---Sat 09 Jan 2026---
    12:30:46.123  ...STARTING...
    Timestamp     A/R Flags if Hostname                               Address                                      TTL
    12:30:46.456  Add     2  4 nerves-1234.local.                     192.168.1.100                                120
    """

    lookup_output_5678 = """
    nerves-5678._ssh._tcp.local. can be reached at nerves-5678.local.:22
    """

    getaddr_output_5678 = """
    DATE: ---Sat 09 Jan 2026---
    12:30:47.123  ...STARTING...
    Timestamp     A/R Flags if Hostname                               Address                                      TTL
    12:30:47.456  Add     2  4 nerves-5678.local.                     192.168.1.101                                120
    """

    stub(System, :cmd, fn cmd, args, _opts ->
      case {cmd, args} do
        {"timeout", [_, "dns-sd", "-B", "_ssh._tcp"]} ->
          {browse_output, 0}

        {"timeout", [_, "dns-sd", "-L", "nerves-1234", "_ssh._tcp"]} ->
          {lookup_output_1234, 0}

        {"timeout", [_, "dns-sd", "-L", "nerves-5678", "_ssh._tcp"]} ->
          {lookup_output_5678, 0}

        {"timeout", [_, "dns-sd", "-G", "v4", "nerves-1234.local"]} ->
          {getaddr_output_1234, 0}

        {"timeout", [_, "dns-sd", "-G", "v4", "nerves-5678.local"]} ->
          {getaddr_output_5678, 0}
      end
    end)

    results = NervesDiscovery.MacOS.discover_service("_ssh._tcp", 5000)

    assert length(results) == 2
    assert Enum.any?(results, &(&1.name == "nerves-1234"))
    device = Enum.find(results, &(&1.name == "nerves-1234"))
    assert device.addresses == [{192, 168, 1, 100}]
    assert Enum.any?(results, &(&1.hostname == "nerves-1234.local"))
  end
end
