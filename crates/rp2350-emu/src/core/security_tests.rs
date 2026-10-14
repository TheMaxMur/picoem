// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SECRET: u32 = 0x2000_0200;
const NS_DATA: u32 = 0x2007_0000;
const NS_CODE: u32 = 0x2007_1000;
const NSC: u32 = 0x2007_2000;
const HANDLER: u32 = 0x2000_0100;

fn machine(op: u16) -> (CortexM33, Bus) {
    let mut cpu = CortexM33::for_test(0);
    let mut bus = Bus::with_atomics(Arc::clone(&cpu.atomics));
    cpu.ppb.sau_ctrl = 1;
    cpu.ppb.sau_regions[0] = (NS_DATA, 0x2007_1fe1);
    cpu.ppb.sau_regions[1] = (NSC, (NSC + 0x1f) | 3);
    cpu.ppb.vtor = 0x2000_0000;
    cpu.ppb.shcsr = 1 << 19;
    bus.write32(cpu.ppb.vtor + 7 * 4, HANDLER | 1, 0);
    bus.write32(cpu.ppb.vtor + 3 * 4, HANDLER | 1, 0);
    bus.write16(HANDLER, 0xe7fe, 0);
    bus.write32(SECRET, 0xdead_beef, 0);
    bus.write16(NS_CODE, op, 0);
    cpu.regs.msp = 0x2000_1000;
    cpu.regs.r[13] = cpu.regs.msp;
    cpu.transition_to_nonsecure();
    cpu.regs.msp = NS_DATA + 0x800;
    cpu.regs.r[13] = cpu.regs.msp;
    cpu.regs.set_pc(NS_CODE);
    cpu.regs.r[1] = SECRET;
    (cpu, bus)
}

#[test]
fn nonsecure_loads_cannot_read_secure_memory() {
    for op in [0x7808, 0x8808, 0x6808] {
        let (mut cpu, mut bus) = machine(op);
        cpu.step(&mut bus);
        assert_eq!(cpu.regs.r[0], 0, "a denied load exported a secret");
        assert_eq!(
            cpu.regs.ipsr(),
            7,
            "a denied load did not raise SecureFault"
        );
        assert!(cpu.secure);
    }
}

#[test]
fn nonsecure_stores_cannot_change_secure_memory() {
    for op in [0x7008, 0x8008, 0x6008] {
        let (mut cpu, mut bus) = machine(op);
        cpu.regs.r[0] = 0x1122_3344;
        cpu.step(&mut bus);
        assert_eq!(
            bus.read32(SECRET, 0),
            0xdead_beef,
            "a denied store changed S RAM"
        );
        assert_eq!(cpu.regs.ipsr(), 7);
    }
}

#[test]
fn permitted_nonsecure_load_and_store_still_work() {
    let (mut cpu, mut bus) = machine(0x6808);
    cpu.regs.r[1] = NS_DATA;
    bus.write32(NS_DATA, 0x1234_5678, 0);
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.r[0], 0x1234_5678);
    assert_eq!(cpu.regs.ipsr(), 0);
    cpu.regs.set_pc(NS_CODE + 2);
    bus.write16(NS_CODE + 2, 0x6008, 0);
    cpu.regs.r[0] = 0xaabb_ccdd;
    cpu.step(&mut bus);
    assert_eq!(bus.read32(NS_DATA, 0), 0xaabb_ccdd);
    assert!(!cpu.secure);
}

#[test]
fn secure_cached_instruction_cannot_execute_in_nonsecure_state() {
    let (mut cpu, mut bus) = machine(0xbf00);
    bus.write16(SECRET, 0x2042, 0); // MOVS r0, #0x42.
    cpu.transition_to_secure();
    cpu.regs.set_pc(SECRET);
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.r[0], 0x42);
    cpu.transition_to_nonsecure();
    cpu.regs.set_pc(SECRET);
    cpu.regs.r[0] = 0;
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.r[0], 0, "decode cache bypassed fetch attribution");
    assert_eq!(cpu.regs.ipsr(), 7);
}

#[test]
fn gateway_requires_sg_and_nsc_attribution() {
    for (address, opcode, allowed) in [
        (NSC, 0xe97f_e97f, true),
        (NSC, 0xbf00_bf00, false),
        (SECRET, 0xe97f_e97f, false),
        (NS_CODE, 0xe97f_e97f, false),
    ] {
        let (mut cpu, mut bus) = machine(0xbf00);
        bus.write32(address, opcode, 0);
        cpu.regs.set_pc(address);
        cpu.step(&mut bus);
        assert!(cpu.secure);
        assert_eq!(cpu.regs.ipsr(), if allowed { 0 } else { 7 });
    }
}

#[test]
fn nonsecure_data_access_to_nsc_is_refused() {
    let (mut cpu, mut bus) = machine(0x6808);
    cpu.regs.r[1] = NSC;
    bus.write32(NSC, 0xe97f_e97f, 0);
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.r[0], 0);
    assert_eq!(cpu.regs.ipsr(), 7);
}

#[test]
fn secure_fault_status_is_secure_only_and_write_one_to_clear() {
    let (mut cpu, mut bus) = machine(0x6808);
    assert!(!cpu.check_data_access(SECRET, 4, false));
    assert_eq!(cpu.ppb.sfsr, (1 << 3) | (1 << 6));
    assert_eq!(cpu.ppb.sfar, SECRET);
    assert_eq!(cpu.bus_read32(0xe000_ede4, &mut bus), 0);
    cpu.bus_write32(0xe000_ede4, u32::MAX, &mut bus);
    assert_ne!(cpu.ppb.sfsr, 0);
    cpu.transition_to_secure();
    assert_eq!(cpu.bus_read32(0xe000_ede4, &mut bus), 0x48);
    cpu.bus_write32(0xe000_ede4, 1 << 3, &mut bus);
    assert_eq!(cpu.ppb.sfsr, 1 << 6);
}

#[test]
fn a_nonsecure_span_crossing_the_sau_boundary_is_refused() {
    let (mut cpu, _) = machine(0x6808);
    assert!(cpu.check_data_access(NS_DATA + 0x1ffc, 4, false));
    assert!(!cpu.check_data_access(NS_DATA + 0x1ffe, 4, false));
    assert!(matches!(cpu.pending_fault, Some(Fault::SecureFault)));
    assert!(!cpu.check_data_access(u32::MAX - 1, 4, true));
}

#[test]
fn nonsecure_mpu_denies_ro_writes_and_xn_fetches() {
    let (mut cpu, mut bus) = machine(0x6008);
    cpu.ppb.ns.mpu_ctrl = 5;
    cpu.ppb.ns.mpu_regions[0] = (NS_DATA | (3 << 1), (NS_DATA + 0x1f) | 1);
    cpu.regs.r[1] = NS_DATA;
    cpu.regs.r[0] = 42;
    cpu.step(&mut bus);
    assert_eq!(bus.read32(NS_DATA, 0), 0);
    assert_ne!(cpu.ppb.ns.cfsr & (1 << 1), 0);
    assert_eq!(cpu.ppb.ns.mmfar, NS_DATA);
    assert_eq!(cpu.regs.ipsr(), 3);

    let (mut cpu, mut bus) = machine(0x2042);
    cpu.ppb.ns.mpu_ctrl = 5;
    cpu.ppb.ns.mpu_regions[0] = (NS_CODE | 1, (NS_CODE + 0x1f) | 1);
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.r[0], 0);
    assert_ne!(cpu.ppb.ns.cfsr & 1, 0);
    assert_eq!(cpu.regs.ipsr(), 3);
}

#[test]
fn rom_hooks_cannot_bypass_secure_fetch_attribution() {
    let (mut cpu, mut bus) = machine(0xbf00);
    cpu.bootrom_reboot_hook_pc_s = Some(0x100);
    cpu.regs.set_pc(0x100);
    cpu.step(&mut bus);
    assert!(!cpu.bootrom_hook_fired);
    assert_eq!(cpu.regs.ipsr(), 7);
}
