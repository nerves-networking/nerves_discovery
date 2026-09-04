<!--
  SPDX-FileCopyrightText: None
  SPDX-License-Identifier: CC0-1.0
-->

# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.5

* Fixes
  * Fix regression introduced by the timeout fix in v0.1.4 on macOS

## v0.1.4

* Fixes
  * Fix wait calculation on macOS. Previously waits <1 second would result in
    timeout of 0 which was infinite.

## v0.1.3

* Fixes
  * Fix crash when no network available (@gworkman)

## v0.1.2

* Fixes
  * Handle spaces in instance names on MacOS and Avahi
  * Always return maps with all fields on MacOS so that it behaves the same as
    the generic and Avahi resolvers

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

