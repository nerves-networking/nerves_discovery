# SPDX-FileCopyrightText: 2026 Frank Hunleth
#
# SPDX-License-Identifier: Apache-2.0
#
Mimic.copy(System)
:code.unstick_mod(:socket)
:code.unstick_mod(:net)
Mimic.copy(:socket)
Mimic.copy(:net)
ExUnit.start()
