#!/bin/sh
# Copyright (c) 2025-2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Routes to either:
#   acpi mode (default): patched QEMU that writes ACPI tables to /output and exits
#   nvram mode:          unpatched QEMU + OVMF that boots long enough to populate NVRAM
#
# Both binaries are built from the same pinned QEMU source version.
#
# nvram mode usage: /entrypoint.sh nvram [qemu-args...]
# The unpatched QEMU is given 120 seconds; timeout is expected and exits cleanly.
if [ "$1" = "nvram" ]; then
    shift
    # For indirect boot, Rust does not pre-stage OVMF_VARS.fd, so copy the
    # apt template as the starting state.  For direct boot, Rust pre-stages
    # the user's actual VARS region so OVMF boots with the right initial state;
    # do NOT overwrite it in that case.
    if [ ! -f /output/OVMF_VARS.fd ]; then
        cp /usr/share/OVMF/OVMF_VARS.fd /output/OVMF_VARS.fd
    fi
    timeout 120 /qemu-source/build/qemu-system-x86_64-unpatched "$@"
    exit 0
else
    exec /qemu-source/build/qemu-system-x86_64 "$@"
fi
