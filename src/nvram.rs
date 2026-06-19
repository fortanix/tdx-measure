/*
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Parse OVMF EFI Variable Store (OVMF_VARS.fd) to extract Boot variables.
//!
//! OVMF stores EFI variables in an EFI Firmware Volume whose first payload is an
//! EFI_VARIABLE_STORE (GUID aaf32c78-…).  Two variable header layouts exist:
//!   - Plain    (non-authenticated): 32-byte header
//!   - Auth     (authenticated, OVMF default): 60-byte header
//! We auto-detect the format from the first valid variable found.

use anyhow::{bail, Context, Result};
use log::debug;
use std::collections::HashMap;
use fs_err as fs;

/// EFI_VARIABLE_STORE_HEADER signature GUID: aaf32c78-947b-439a-a180-2e144ec37792
/// Encoded in mixed-endian EFI binary form.
const VAR_STORE_GUID: [u8; 16] = [
    0x78, 0x2c, 0xf3, 0xaa, // Data1  aaf32c78 → LE
    0x7b, 0x94,             // Data2  947b     → LE
    0x9a, 0x43,             // Data3  439a     → LE
    0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92, // Data4 big-endian
];

/// EFI Global Variable GUID: 8be4df61-93ca-11d2-aa0d-00e098032b8c
/// Used by Boot0000, BootOrder, etc.
pub const GLOBAL_VAR_GUID: [u8; 16] = [
    0x61, 0xdf, 0xe4, 0x8b, // Data1  8be4df61 → LE
    0xca, 0x93,             // Data2  93ca     → LE
    0xd2, 0x11,             // Data3  11d2     → LE
    0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c, // Data4
];

// Variable states
const VAR_ADDED: u8 = 0x3F; // fully written and valid

// Variable start marker (0x55AA in little-endian → bytes [0xAA, 0x55])
const START_ID: [u8; 2] = [0xAA, 0x55];

// EFI_VARIABLE_STORE_HEADER size (GUID + Size + Format + State + Reserved*2)
const STORE_HDR: usize = 28;

// Variable header sizes
const PLAIN_HDR: usize = 32; // non-authenticated
const AUTH_HDR: usize  = 60; // authenticated (OVMF default)

fn align4(n: usize) -> usize { (n + 3) & !3 }

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)?.try_into().ok().map(u32::from_le_bytes)
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 { return None; }
    let u16s: Vec<u16> = bytes.chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // strip null terminator
    let u16s: Vec<u16> = u16s.into_iter().take_while(|&c| c != 0).collect();
    char::decode_utf16(u16s).collect::<std::result::Result<String, _>>().ok()
}

/// Locate the byte offset of EFI_VARIABLE_STORE_HEADER within `data`.
fn find_store(data: &[u8]) -> Option<usize> {
    data.windows(16).position(|w| w == VAR_STORE_GUID)
}

/// Return (name_size_offset, data_size_offset, guid_offset, header_size) for
/// the detected format.
fn var_layout(auth: bool) -> (usize, usize, usize, usize) {
    if auth {
        (36, 40, 44, AUTH_HDR)
    } else {
        (8, 12, 16, PLAIN_HDR)
    }
}

/// Detect whether the variable store uses authenticated (60-byte) headers by
/// peeking at the first valid-looking variable.
fn detect_auth(vars: &[u8]) -> bool {
    let mut i = 0;
    while i + 4 <= vars.len() {
        if vars[i] == 0xFF { break; }
        if vars[i..i + 2] != START_ID { i += 1; continue; }
        if vars[i + 2] != VAR_ADDED  { i += 2; continue; }

        // Auth candidate: NameSize at i+36, DataSize at i+40
        if i + AUTH_HDR <= vars.len() {
            if let (Some(ns), Some(ds)) = (u32_at(vars, i + 36), u32_at(vars, i + 40)) {
                let ns = ns as usize;
                let ds = ds as usize;
                if ns > 0 && ns <= 512 && ns % 2 == 0 && ds < 256 * 1024 {
                    let ne = i + AUTH_HDR + ns;
                    if ne <= vars.len() {
                        if decode_utf16(&vars[i + AUTH_HDR..ne]).is_some() {
                            return true;
                        }
                    }
                }
            }
        }

        // Plain candidate: NameSize at i+8, DataSize at i+12
        if i + PLAIN_HDR <= vars.len() {
            if let (Some(ns), Some(ds)) = (u32_at(vars, i + 8), u32_at(vars, i + 12)) {
                let ns = ns as usize;
                let ds = ds as usize;
                if ns > 0 && ns <= 512 && ns % 2 == 0 && ds < 256 * 1024 {
                    let ne = i + PLAIN_HDR + ns;
                    if ne <= vars.len() {
                        if decode_utf16(&vars[i + PLAIN_HDR..ne]).is_some() {
                            return false;
                        }
                    }
                }
            }
        }
        break;
    }
    true // default: auth (OVMF standard)
}

/// Walk a variable store region and return all fully-added variables.
fn parse_vars(vars: &[u8], auth: bool) -> Vec<([u8; 16], String, Vec<u8>)> {
    let (ns_off, ds_off, guid_off, hdr) = var_layout(auth);
    let mut out = Vec::new();
    let mut i = 0;

    while i < vars.len() {
        if vars[i] == 0xFF { break; }

        if i + 2 > vars.len() || vars[i..i + 2] != START_ID {
            i += 1;
            continue;
        }

        if i + hdr > vars.len() { break; }

        let state = vars[i + 2];
        let ns = match u32_at(vars, i + ns_off) { Some(v) => v as usize, None => break };
        let ds = match u32_at(vars, i + ds_off) { Some(v) => v as usize, None => break };

        // Sanity guard
        if ns == 0 || ns > 4096 || ns % 2 != 0 || ds > 1024 * 1024 {
            i += 1;
            continue;
        }

        let total = hdr + ns + ds;
        let next = i + align4(total);

        if state == VAR_ADDED && i + total <= vars.len() {
            if let Ok(guid) = vars[i + guid_off..i + guid_off + 16].try_into() {
                let name_slice = &vars[i + hdr..i + hdr + ns];
                if let Some(name) = decode_utf16(name_slice) {
                    let data = vars[i + hdr + ns..i + hdr + ns + ds].to_vec();
                    debug!("nvram: var '{}' data_len={}", name, ds);
                    out.push((guid, name, data));
                }
            }
        }

        i = next;
    }

    out
}

/// Read all EFI variables from an OVMF NVRAM (OVMF_VARS.fd) file.
///
/// Returns a map of `(vendor_guid_bytes, variable_name) → data`.
pub fn read_efi_variables(nvram_path: &str) -> Result<HashMap<([u8; 16], String), Vec<u8>>> {
    let raw = fs::read(nvram_path)
        .with_context(|| format!("Failed to read NVRAM: {nvram_path}"))?;

    let store_off = find_store(&raw)
        .with_context(|| format!(
            "EFI variable store GUID not found in {nvram_path} — \
             supply an OVMF_VARS.fd (writable pflash image), not the combined OVMF.fd"
        ))?;

    // EFI_VARIABLE_STORE_HEADER layout:
    //   offset  0: GUID (16 bytes)  ← store_off
    //   offset 16: Size (u32)
    //   offset 20: Format (u8)  — 0x5A = formatted
    //   offset 21: State  (u8)  — 0xFE = healthy
    let fmt   = raw.get(store_off + 20).copied().unwrap_or(0);
    let state = raw.get(store_off + 21).copied().unwrap_or(0);

    if fmt != 0x5A {
        bail!("NVRAM variable store not formatted (Format=0x{fmt:02X}, want 0x5A)");
    }
    if state != 0xFE {
        bail!("NVRAM variable store not healthy (State=0x{state:02X}, want 0xFE)");
    }

    let size = u32_at(&raw, store_off + 16)
        .context("Cannot read variable store Size field")? as usize;

    let vars_start = store_off + STORE_HDR;
    let vars_end   = (store_off + size).min(raw.len());

    if vars_start >= vars_end {
        bail!("Variable store has zero usable space");
    }

    let vars_region = &raw[vars_start..vars_end];
    let auth = detect_auth(vars_region);
    debug!("nvram: using {} variable header format", if auth { "authenticated (60B)" } else { "plain (32B)" });

    let entries = parse_vars(vars_region, auth);
    if entries.is_empty() {
        bail!("No valid EFI variables in NVRAM — the file may be an unbooted template");
    }

    let mut map = HashMap::new();
    for (guid, name, data) in entries {
        map.insert((guid, name), data);
    }
    Ok(map)
}

/// Read BootOrder and all referenced Boot{XXXX} entries from an OVMF NVRAM file.
///
/// Returns `(boot_order_bytes, map_of_entry_num → EFI_LOAD_OPTION_bytes)`.
/// The boot_order_bytes is the raw BootOrder EFI variable value (a sequence of
/// UINT16 boot-entry numbers in little-endian order).
pub fn read_boot_variables(nvram_path: &str) -> Result<(Vec<u8>, HashMap<u16, Vec<u8>>)> {
    let vars = read_efi_variables(nvram_path)?;

    let boot_order = vars
        .get(&(GLOBAL_VAR_GUID, "BootOrder".to_string()))
        .cloned()
        .context("BootOrder variable not found in NVRAM — \
                  ensure the VM has booted at least once with this NVRAM file")?;

    if boot_order.len() % 2 != 0 {
        bail!("BootOrder has odd byte count ({})", boot_order.len());
    }

    let mut boot_entries: HashMap<u16, Vec<u8>> = HashMap::new();
    for chunk in boot_order.chunks(2) {
        let num = u16::from_le_bytes([chunk[0], chunk[1]]);
        let var_name = format!("Boot{num:04X}");
        if let Some(data) = vars.get(&(GLOBAL_VAR_GUID, var_name)) {
            boot_entries.insert(num, data.clone());
        }
    }

    Ok((boot_order, boot_entries))
}
