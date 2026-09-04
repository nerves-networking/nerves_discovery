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
    12:30:45.789  Add        2   4 local.               _ssh._tcp.           nerves spaces
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
    nerves spaces._ssh._tcp.local. can be reached at nerves-5678.local.:22
    """

    getaddr_output_5678 = """
    DATE: ---Sat 09 Jan 2026---
    12:30:47.123  ...STARTING...
    Timestamp     A/R Flags if Hostname                               Address                                      TTL
    12:30:47.456  Add     2  4 nerves-5678.local.                     192.168.1.101                                120
    """

    stub_browser("_ssh._tcp", browse_output)

    stub(System, :cmd, fn cmd, args, _opts ->
      case {cmd, args} do
        {"timeout", [_, "dns-sd", "-L", "nerves-1234", "_ssh._tcp"]} ->
          {lookup_output_1234, 0}

        {"timeout", [_, "dns-sd", "-L", "nerves spaces", "_ssh._tcp"]} ->
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
    assert device.hostname == "nerves-1234.local"
    assert device.serial == nil
    assert device.version == nil
    assert device.description == nil
    assert device.author == nil
    assert device.product == nil
    assert device.platform == nil
    assert device.architecture == nil
    assert device.uuid == nil
  end

  test "stops browsing after 500 ms without a report and waits for resolutions" do
    test_process = self()
    browser = make_ref()

    stub(NervesDiscovery.MacOS.Browser, :open, fn "_ssh._tcp", 5000 ->
      send(
        self(),
        {browser, {:data, {:eol, "12:30:45.456 Add 2 4 local. _ssh._tcp. nerves-1234"}}}
      )

      Process.send_after(
        self(),
        {browser, {:data, {:eol, "12:30:45.789 Add 2 4 local. _ssh._tcp. nerves-5678"}}},
        250
      )

      browser
    end)

    stub(System, :cmd, fn cmd, args, _opts ->
      case {cmd, args} do
        {"timeout", [_, "dns-sd", "-L", "nerves-1234", "_ssh._tcp"]} ->
          {"nerves-1234._ssh._tcp.local. can be reached at nerves-1234.local.:22", 0}

        {"timeout", [_, "dns-sd", "-L", "nerves-5678", "_ssh._tcp"]} ->
          Process.sleep(800)
          send(test_process, :last_resolution_finished)
          {"nerves-5678._ssh._tcp.local. can be reached at nerves-5678.local.:22", 0}

        {"timeout", [_, "dns-sd", "-G", "v4", hostname]} ->
          {"12:30:46.456 Add 2 4 #{hostname}. 192.168.1.100 120", 0}
      end
    end)

    started_at = System.monotonic_time(:millisecond)
    results = NervesDiscovery.MacOS.discover_service("_ssh._tcp", 5000)
    elapsed = System.monotonic_time(:millisecond) - started_at

    assert elapsed >= 800
    assert elapsed < 1500
    assert_receive :last_resolution_finished
    assert Enum.map(results, & &1.name) == ["nerves-1234", "nerves-5678"]
  end

  test "stops browsing at the maximum timeout when there are no reports" do
    stub(NervesDiscovery.MacOS.Browser, :open, fn "_ssh._tcp", 50 -> make_ref() end)

    started_at = System.monotonic_time(:millisecond)
    assert NervesDiscovery.MacOS.discover_service("_ssh._tcp", 50) == []
    elapsed = System.monotonic_time(:millisecond) - started_at

    assert elapsed >= 50
    assert elapsed < 500
  end

  defp stub_browser(service, output) do
    stub(NervesDiscovery.MacOS.Browser, :open, fn ^service, _timeout ->
      browser = make_ref()

      output
      |> String.split("\n", trim: true)
      |> Enum.each(&send(self(), {browser, {:data, {:eol, &1}}}))

      send(self(), {browser, {:exit_status, 0}})
      browser
    end)
  end
end
