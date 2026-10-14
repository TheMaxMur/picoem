// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn threaded_nonsecure_sio_preserves_secure_fifo_locks_and_doorbells() {
    let shared = SharedState::new_default();
    let mut bus = WorkerBus::new(0, shared.clone());
    shared.sio.fifo_push(1, 0xdead_beef);
    shared.sio.spinlock_claim(3);
    shared.sio.doorbell_set(0, 1);
    for (address, expected) in [(0xd000_0058, 0), (0xd000_010c, 8), (0xd000_0188, 0)] {
        assert!(bus.begin_access(address, 4, 0, false, true));
        assert_eq!(
            bus.read32(address, 0),
            expected,
            "threaded NS bank was shared"
        );
        bus.end_access(0);
    }
    for address in [0xd000_010c, 0xd000_018c] {
        assert!(bus.begin_access(address, 4, 0, false, true));
        bus.write32(address, 15, 0);
        bus.end_access(0);
    }
    assert_eq!(shared.sio.fifo_pop(0), Some(0xdead_beef));
    assert_eq!(shared.sio.spinlock_bits(), 8);
    assert_eq!(shared.sio.doorbell_read(0), 1);
}

#[test]
fn threaded_sio_mirror_reaches_only_the_nonsecure_bank() {
    let shared = SharedState::new_default();
    let mut bus = WorkerBus::new(0, shared.clone());
    assert!(bus.begin_access(0xd002_0054, 4, 0, true, true));
    bus.write32(0xd002_0054, 42, 0);
    bus.end_access(0);
    assert_eq!(shared.sio_ns.fifo_pop(1), Some(42));
    assert_eq!(shared.sio.fifo_st(1) & 1, 0);
    assert!(!bus.begin_access(0xd002_0054, 4, 0, false, true));
    bus.end_access(0);
    assert!(bus.bus_fault(0));
}

#[test]
fn threaded_gpio_masks_cover_both_banks_and_narrow_writes() {
    let shared = SharedState::new_default();
    let mut bus = WorkerBus::new(0, shared.clone());
    bus.write32(0x4006_000c, 15, 0);
    bus.write32(0x4006_0010, 15, 0);
    for (bank, address) in [(0, 0xd000_0010), (1, 0xd000_0014)] {
        shared.gpio.write_out(bank, 0x1234_5678);
        assert!(bus.begin_access(address, 4, 0, false, true));
        assert_eq!(bus.read32(address, 0), 8, "threaded NS read protected GPIO");
        bus.write8(address, 0xff, 0);
        bus.end_access(0);
        assert_eq!(
            shared.gpio.read_out(bank),
            0x1234_567f,
            "threaded NS changed protected GPIO"
        );
    }
}

#[test]
fn sio_interrupts_remain_separate_for_each_security_bank() {
    let shared = SharedState::new_default();
    shared.sio_ns.fifo_push(1, 42);
    shared.sio_ns.doorbell_set(0, 1);
    assert_eq!(shared.sio_irq_pending(0), (1 << 27) | (1 << 28));
    assert_eq!(shared.sio_irq_pending(1), 0);
    shared.sio.fifo_push(1, 13);
    assert_eq!(shared.sio_irq_pending(0), (1 << 25) | (1 << 27) | (1 << 28));
    shared.sio_ns.fifo_pop(0);
    shared.sio_ns.doorbell_clear(0, 15);
    assert_eq!(shared.sio_irq_pending(0), 1 << 25);
}

#[cfg(all(
    feature = "threading",
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
))]
#[test]
fn promotion_preserves_the_nonsecure_sio_bank_and_gpio_masks() {
    let mut emu = crate::Emulator::new(crate::Config::default());
    emu.bus.write32(0xd002_0054, 42, 0);
    emu.bus.write32(0xd002_010c, 0, 0);
    assert_eq!(emu.bus.read32(0xd002_010c, 0), 8);
    emu.bus.write32(0xd000_0014, 0x1234_5678, 0);
    emu.bus.write32(0x4006_0010, 15, 0);
    emu.bus.pending_cache_invalidations.clear();
    let threaded = crate::threaded::ThreadedEmulator::from_emulator(emu);
    let shared = threaded.shared();
    assert_eq!(shared.sio_ns.fifo_pop(1), Some(42));
    assert_eq!(shared.sio_ns.spinlock_bits(), 8);
    assert_eq!(shared.sio.spinlock_bits(), 0);
    assert_eq!(shared.gpio.read_out(1), 0x1234_5678);
    assert_eq!(shared.accessctrl.lock().unwrap().read(0x4006_0010), 15);
}
