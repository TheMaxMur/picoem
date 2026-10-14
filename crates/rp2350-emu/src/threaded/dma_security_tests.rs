// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn threaded_dma_grants_preserve_channel_security_for_all_widths() {
    let shared = SharedState::new_default();
    let mut bus = WorkerBus::new(0, shared.clone());
    bus.write32(0x5000_0000, 0x2000_1000, 0);
    bus.write32(0x4006_0044, 0xacce_00ff, 0);
    for size in [1, 2, 4] {
        assert!(bus.begin_access(0x5000_0000, size, 0, false, true));
        match size {
            1 => {
                assert_eq!(bus.read8(0x5000_0000, 0), 0);
                bus.write8(0x5000_0000, 0xff, 0);
            }
            2 => {
                assert_eq!(bus.read16(0x5000_0000, 0), 0);
                bus.write16(0x5000_0000, 0xffff, 0);
            }
            _ => {
                assert_eq!(bus.read32(0x5000_0000, 0), 0);
                bus.write32(0x5000_0000, u32::MAX, 0);
            }
        }
        bus.end_access(0);
        assert!(bus.bus_fault(0), "threaded NS accessed an S DMA channel");
        bus.clear_bus_fault(0);
        assert_eq!(bus.read32(0x5000_0000, 0), 0x2000_1000);
    }
}
