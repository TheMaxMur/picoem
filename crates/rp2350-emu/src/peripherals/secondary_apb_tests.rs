// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::{i2c, spi, uart};
use crate::Bus;
use crate::bus::{RESET_I2C1, RESET_SPI1, RESET_UART1};

const RESETS: u32 = 0x4002_0000;
const XOR: u32 = 0x1000;
const SET: u32 = 0x2000;
const CLEAR: u32 = 0x3000;

#[test]
fn secondary_bases_match_the_rp2350_address_map() {
    assert_eq!(uart::UART1_BASE, 0x4007_8000);
    assert_eq!(spi::SPI1_BASE, 0x4008_8000);
    assert_eq!(i2c::I2C1_BASE, 0x4009_8000);
}

#[test]
fn silicon_addresses_route_to_independent_reset_gated_peripherals() {
    // Addresses and reset status values come from RP2350 addressmap.h/registers.
    for (primary, secondary, reset, control, status, reset_status) in [
        (0x4007_0000, 0x4007_8000, RESET_UART1, 0x24, 0x18, 0x90),
        (0x4008_0000, 0x4008_8000, RESET_SPI1, 0x00, 0x0c, 0x03),
        (0x4009_0000, 0x4009_8000, RESET_I2C1, 0x14, 0x00, 0x65),
    ] {
        let mut bus = Bus::new();
        assert_eq!(bus.read32(secondary + status, 0), 0, "held in reset");
        bus.write32(RESETS + CLEAR, 1 << reset, 0);
        assert_eq!(
            bus.read32(secondary + status, 0),
            reset_status,
            "real peripheral, not an unmapped register"
        );
        bus.write32(primary + control, 0x55, 0);
        bus.write32(secondary + control, 0xaa, 0);
        assert_eq!(bus.read32(primary + control, 0), 0x55);
        assert_eq!(bus.read32(secondary + control, 0), 0xaa);
        bus.write32(secondary + control + SET, 0x11, 0);
        assert_eq!(bus.read32(secondary + control, 0), 0xbb);
        bus.write32(secondary + control + XOR, 0x33, 0);
        assert_eq!(bus.read32(secondary + control, 0), 0x88);
        bus.write32(secondary + control + CLEAR, 0x80, 0);
        assert_eq!(bus.read32(secondary + control, 0), 0x08);
        assert_eq!(bus.read32(primary + control, 0), 0x55);
        assert!(!bus.atomics.is_bus_fault(0));
        bus.write32(RESETS + SET, 1 << reset, 0);
        bus.write32(secondary + control, 0xff, 0);
        assert_eq!(bus.read32(secondary + status, 0), 0);
        bus.write32(RESETS + CLEAR, 1 << reset, 0);
        assert_eq!(bus.read32(secondary + status, 0), reset_status);
    }
}
