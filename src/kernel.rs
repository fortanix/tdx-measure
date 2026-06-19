/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::{measure_log, measure_sha384, util::debug_print_log, util::authenticode_sha384_hash};
use anyhow::{Context, Result};
use fs_err as fs;

/// Measures a QEMU-patched TDX kernel image from file paths (for direct boot).
pub(crate) fn measure_rtmr1_direct(
    kernel_path: &str,
    _initrd_path: &str,
    _mem_size: u64,
    _acpi_data_size: u32,
) -> Result<Vec<u8>> {

    // OVMF measures the kernel from FW_CFG before QEMU patches the setup header
    // in guest RAM, so hash the original image.
    let kernel_data = fs::read(kernel_path).context("Failed to read kernel file")?;
    let kernel_hash = authenticode_sha384_hash(&kernel_data).context("Failed to compute kernel hash")?;

    // Compute RTMR1 log
    let rtmr1_log = vec![
        kernel_hash,
        measure_sha384(b"Calling EFI Application from Boot Option"),
        measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
        measure_sha384(b"Exit Boot Services Invocation"),
        measure_sha384(b"Exit Boot Services Returned with Success"),
    ];

    debug_print_log("RTMR1", &rtmr1_log);
    Ok(measure_log(&rtmr1_log))
}

/// Measures RTMR2 for direct boot from file paths.
pub(crate) fn measure_rtmr2_direct(
    initrd_path: &str,
    kernel_cmdline: &str,
) -> Result<Vec<u8>> {

    // Reads our initrd file
    let initrd_data = fs::read(initrd_path).context("Failed to read initrd file")?;

    // OVMF prepends `initrd=initrd ` to the kernel command line so the EFI stub
    // loads the fw_cfg initrd; this matches the guest's /proc/cmdline ordering.
    let cmdline = format!("initrd=initrd {kernel_cmdline}");

    // Compute RTMR2 log
    let rtmr2_log = vec![
        crate::util::measure_cmdline(&cmdline),
        measure_sha384(&initrd_data),
    ];

    debug_print_log("RTMR2", &rtmr2_log);
    Ok(measure_log(&rtmr2_log))
}
