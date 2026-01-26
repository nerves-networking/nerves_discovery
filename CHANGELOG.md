<!--
  SPDX-FileCopyrightText: None
  SPDX-License-Identifier: CC0-1.0
-->

# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.1

* New features
  * Add `:addresses` field to return devices that contain all of the IPv4
    addresses for a device. This adds support for multi-homed devices.
    Consequently, the `:ip` field is now redundant and is marked as deprecated.

* Improvements
  * Replace all `System.shell` calls with `System.cmd`
  * Small documentation updates per feedback

## v0.1.0

Initial release

