# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule NervesDiscovery.AvahiTest do
  use ExUnit.Case
  use Mimic

  test "parses avahi-browse output with TXT records" do
    avahi_output = """
    =;eth0;IPv4;nerves-abcd;_nerves-device._tcp;local;nerves-abcd.local;192.168.1.50;4000;"serial=XYZ789" "version=2.1.0" "product=bbb" "platform=linux"
    =;eth0;IPv4;nerves-efgh;_nerves-device._tcp;local;nerves-efgh.local;192.168.1.51;4000;"serial=DEF456" "version=2.0.0"
    """

    stub(System, :cmd, fn "timeout",
                          [_timeout, "avahi-browse", "-rtp", "_nerves-device._tcp"],
                          _opts ->
      {avahi_output, 0}
    end)

    results = NervesDiscovery.Avahi.discover_service("_nerves-device._tcp", 5000)

    assert length(results) == 2

    device1 = Enum.find(results, &(&1.name == "nerves-abcd"))
    assert device1.hostname == "nerves-abcd.local"
    assert device1.ip == "192.168.1.50"
    assert device1.serial == "XYZ789"
    assert device1.version == "2.1.0"
    assert device1.product == "bbb"
    assert device1.platform == "linux"

    device2 = Enum.find(results, &(&1.name == "nerves-efgh"))
    assert device2.serial == "DEF456"
    assert device2.version == "2.0.0"
  end

  test "handles empty output gracefully" do
    stub(System, :cmd, fn "timeout", [_timeout, "avahi-browse", "-rtp", "_ssh._tcp"], _opts ->
      {"", 0}
    end)

    results = NervesDiscovery.Avahi.discover_service("_ssh._tcp", 5000)

    assert results == []
  end
end
