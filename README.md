<!--
  SPDX-FileCopyrightText: 2025 Frank Hunleth
  SPDX-License-Identifier: CC-BY-4.0
-->

# NervesDiscovery

[![Hex version](https://img.shields.io/hexpm/v/nerves_discovery.svg "Hex version")](https://hex.pm/packages/nerves_discovery)
[![API docs](https://img.shields.io/hexpm/v/nerves_discovery.svg?label=hexdocs "API docs")](https://hexdocs.pm/nerves_discovery/NervesDiscovery.html)
[![CircleCI](https://dl.circleci.com/status-badge/img/gh/nerves-networking/nerves_discovery/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/nerves-networking/nerves_discovery/tree/main)
[![REUSE status](https://api.reuse.software/badge/github.com/nerves-networking/nerves_discovery)](https://api.reuse.software/info/github.com/nerves-networking/nerves_discovery)

Discover Nerves devices on your local network using mDNS service discovery

This library provides a simple way to find Nerves devices on your network
without needing to know their IP addresses. Devices that advertise the
`_nerves-device._tcp` mDNS service report additional information like serial
number and firmware information. It uses a heuristic to find Nerves devices that
don't support this service by also looking at SSH advertisements.

## Installation

This library uses native mDNS programs when available and backs off to a generic
pure-Elixir implementation. The pure-Elixir method has limitations such as not
being able to consult a cache, so the platform-specific methods should perform
better.

MacOS and Windows users don't need to do anything. Desktop Linux users should
install the Avahi tools:

```bash
# Debian/Ubuntu
sudo apt-get install avahi-utils

# Fedora/RHEL
sudo dnf install avahi-tools
```

## Usage

Calling `NervesDiscovery.discover/1` with no options should result in a good
list of what's available. See the options to change the wait time.

```elixir
iex> NervesDiscovery.discover()
[
  %{
    name: "nerves-8465",
    serial: "55e77bfdd5030316",
    version: "0.2.1",
    ip: "192.168.7.48",
    description: "",
    author: "The Nerves Team",
    product: "kiosk_demo",
    hostname: "nerves-8465.local",
    platform: "rpi4",
    architecture: "arm",
    uuid: "28a2e0e8-2166-5ff2-f24e-a42564cf9bc4"
  },
  %{
    name: "nerves-0316",
    ip: "192.168.7.128",
    hostname: "nerves-0316.local",
  }
]
```

If you want the serial number and firmware information from your Nerves device,
it should advertise the `_nerves-device._tcp` mDNS service. Include this code
snippet in your firmware (or pasted it on the Nerves device's IEx prompt to
test):

```elixir
MdnsLite.add_mdns_service(%{
    id: :nerves_device,
    protocol: "nerves-device",
    transport: "tcp",
    port: 0,
    txt_payload: [
      "serial=#{Nerves.Runtime.serial_number()}",
      "product=#{Nerves.Runtime.KV.get_active("nerves_fw_product")}",
      "description=#{Nerves.Runtime.KV.get_active("nerves_fw_description")}",
      "version=#{Nerves.Runtime.KV.get_active("nerves_fw_version")}",
      "platform=#{Nerves.Runtime.KV.get_active("nerves_fw_platform")}",
      "architecture=#{Nerves.Runtime.KV.get_active("nerves_fw_architecture")}",
      "author=#{Nerves.Runtime.KV.get_active("nerves_fw_author")}",
      "uuid=#{Nerves.Runtime.KV.get_active("nerves_fw_uuid")}"
    ]
  })
```

## mDNS Service specification

This section formally specifies the `_nerves-device._tcp` mDNS service for
enabling automatic discovery of devices and information about them.

### Service Name

```txt
_nerves-device._tcp.local
```

### Port Number

The port number MUST be 0.

### TXT Records

Devices advertising this service SHOULD include the following TXT records:

#### Required Fields

- **`serial`**: Device serial number or unique identifier
- **`version`**: The application or firmware version string

#### Optional Fields

Additional TXT records MAY be included as needed by specific applications:

- **`architecture`**: The CPU architecture (e.g., `aarch64`, `riscv`, `x86_64`) - **`author`**: Author field in the firmware metadata
- **`description`**: Human-readable device description
- **`platform`**: The hardware model or platform identifier (e.g., `rpi4`, `bbb`, `imx6ull`)
- **`product`**: The application or product name running on the device
- **`uuid`**: Firmware UUID

### Example

```txt
Service Name: my-thermostat._nerves-device._tcp.local
Port: 0
TXT Records:
  serial=ABC123456
  version=1.2.3
  product=smart_thermostat
```
