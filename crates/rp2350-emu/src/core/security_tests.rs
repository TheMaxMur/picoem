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

fn secure_banks(cpu: &CortexM33) -> [u32; 8] {
    [
        cpu.regs.msp_ns,
        cpu.regs.psp_ns,
        cpu.regs.msplim_ns,
        cpu.regs.psplim_ns,
        cpu.regs.primask_ns,
        cpu.regs.basepri_ns,
        cpu.regs.faultmask_ns,
        cpu.regs.control_ns,
    ]
}

#[test]
fn nonsecure_special_register_aliases_cannot_read_secure_banks() {
    for sysm in [0x88, 0x89, 0x8a, 0x8b, 0x90, 0x91, 0x93, 0x94] {
        let (mut cpu, _) = machine(0xbf00);
        cpu.regs.msp_ns = 0x2000_1234;
        cpu.regs.psp_ns = 0x2000_5678;
        cpu.regs.msplim_ns = 0x2000_1000;
        cpu.regs.psplim_ns = 0x2000_5000;
        cpu.regs.primask_ns = 1;
        cpu.regs.basepri_ns = 0x40;
        cpu.regs.faultmask_ns = 1;
        cpu.regs.control_ns = 3;
        cpu.execute_one_wide(0xf3ef, 0x8000 | sysm);
        assert_eq!(cpu.regs.r[0], 0, "NS MRS alias read S state");
    }
}

#[test]
fn nonsecure_special_register_aliases_cannot_write_secure_banks() {
    for sysm in [0x88, 0x89, 0x8a, 0x8b, 0x90, 0x91, 0x93, 0x94] {
        let (mut cpu, _) = machine(0xbf00);
        let before = secure_banks(&cpu);
        cpu.regs.r[0] = u32::MAX;
        cpu.execute_one_wide(0xf380, 0x8800 | sysm);
        assert_eq!(secure_banks(&cpu), before, "NS MSR alias changed S state");
    }
}

fn irq_machine(from_secure: bool) -> (CortexM33, Bus) {
    let (mut cpu, mut bus) = machine(0x4770); // BX LR.
    cpu.ppb.nvic_itns[0] = 1 << 3;
    cpu.ppb.ns.vtor = NS_DATA;
    bus.write32(NS_DATA + 19 * 4, NS_CODE | 1, 0);
    if from_secure {
        cpu.transition_to_secure();
        cpu.regs.set_pc(SECRET);
    }
    cpu.regs.r[4] = 0xdead_beef;
    cpu.enter_exception(19, &mut bus);
    (cpu, bus)
}

#[test]
fn forged_exception_return_cannot_elevate_a_nonsecure_handler() {
    let (mut cpu, mut bus) = irq_machine(false);
    let s_sp = cpu.regs.msp_ns;
    bus.write32(s_sp, 0x1234_5678, 0);
    bus.write32(s_sp + 24, SECRET | 1, 0);
    bus.write32(s_sp + 28, 0x0100_0000, 0);
    cpu.regs.set_lr(cpu.regs.lr() | (1 << 6) | 1);
    cpu.step(&mut bus);
    assert_ne!(cpu.ppb.sfsr & (1 << 2), 0, "forged EXC_RETURN elevated NS");
    assert_ne!(
        cpu.regs.r[0], 0x1234_5678,
        "S frame was exported before refusal"
    );
    assert_eq!(cpu.regs.ipsr(), 7);
}

#[test]
fn an_exception_return_in_thread_mode_cannot_pop_a_secure_frame() {
    let (mut cpu, mut bus) = machine(0x4770);
    let s_sp = cpu.regs.msp_ns;
    bus.write32(s_sp, 0x1234_5678, 0);
    bus.write32(s_sp + 24, SECRET | 1, 0);
    bus.write32(s_sp + 28, 0x0100_0000, 0);
    cpu.regs.set_lr(0xffff_fff8);
    cpu.step(&mut bus);
    assert_ne!(cpu.regs.r[0], 0x1234_5678);
    assert_eq!(cpu.regs.ipsr(), 3);
}

#[test]
fn a_secure_context_can_return_from_its_nonsecure_interrupt() {
    let (mut cpu, mut bus) = irq_machine(true);
    assert!(!cpu.secure);
    assert_eq!(cpu.regs.r[4], 0);
    assert_ne!(
        cpu.regs.lr() & (1 << 5),
        0,
        "DCRS must retain the default rules"
    );
    cpu.step(&mut bus);
    assert!(cpu.secure);
    assert_eq!(cpu.regs.ipsr(), 0);
    assert_eq!(cpu.regs.r[4], 0xdead_beef);
    assert_eq!(cpu.regs.pc(), SECRET);
}

#[test]
fn a_nonsecure_context_can_return_from_its_nonsecure_interrupt() {
    let (mut cpu, mut bus) = irq_machine(false);
    cpu.step(&mut bus);
    assert!(!cpu.secure);
    assert_eq!(cpu.regs.ipsr(), 0);
    assert_eq!(cpu.regs.r[4], 0xdead_beef);
}

#[test]
fn corrupted_secure_integrity_signature_prevents_register_restore() {
    let (mut cpu, mut bus) = irq_machine(true);
    bus.write32(cpu.regs.msp_ns, 0, 0);
    cpu.step(&mut bus);
    assert_ne!(cpu.ppb.sfsr & (1 << 1), 0, "bad signature was accepted");
    assert_eq!(
        cpu.regs.r[4], 0,
        "S callee registers were restored before refusal"
    );
    assert_eq!(cpu.regs.ipsr(), 7);
}

#[test]
fn real_nonsecure_loads_obey_peripheral_accessctrl_filters() {
    for address in [
        0x5010_0000,
        0x5011_0000,
        0x400f_0000,
        0x4012_0000,
        0x400d_0000,
        0x4002_0000,
        0x4001_0000,
        0x400e_0000,
    ] {
        let (mut cpu, mut bus) = machine(0x6808);
        cpu.regs.r[1] = address;
        cpu.step(&mut bus);
        assert_eq!(cpu.regs.ipsr(), 3, "NS touched a protected peripheral");
        assert_eq!(cpu.ppb.bfar, address);
    }
}

#[test]
fn nonsecure_cpu_cannot_grant_itself_usb_access() {
    let (mut cpu, mut bus) = machine(0x6008);
    cpu.regs.r[1] = 0x4006_0048;
    cpu.regs.r[0] = 0xacce_00ff;
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.ipsr(), 0);
    assert_eq!(bus.read32(0x4006_0048, 0), 0xfc);
}

#[test]
fn secure_grant_allows_real_nonsecure_usb_access() {
    let (mut cpu, mut bus) = machine(0x6808);
    bus.write32(0x4006_0048, 0xacce_001a, 0);
    cpu.regs.r[1] = 0x5011_0000;
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.ipsr(), 0);
    assert!(!cpu.secure);
}

#[test]
fn nonsecure_rom_hooks_obey_bus_permissions() {
    let (mut cpu, mut bus) = machine(0xbf00);
    cpu.bootrom_reboot_hook_pc_ns = Some(0x5000);
    cpu.regs.set_pc(0x5000);
    bus.write32(0x4006_0014, 0xacce_0038, 0);
    cpu.step(&mut bus);
    assert!(!cpu.bootrom_hook_fired, "ROM hook bypassed ACCESSCTRL");
    assert_eq!(cpu.regs.ipsr(), 3);
    assert_eq!(cpu.ppb.bfar, 0x5000);
}

#[test]
fn nonsecure_sio_cannot_read_or_inject_secure_fifo_messages() {
    let (mut cpu, mut bus) = machine(0x6808);
    bus.write32(0xd000_0054, 0xdead_beef, 1);
    cpu.regs.r[1] = 0xd000_0058;
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.r[0], 0, "NS read the Secure FIFO");
    assert_eq!(bus.read32(0xd000_0058, 0), 0xdead_beef);
    cpu.bus_write32(0xd000_0054, 0x1234_5678, &mut bus);
    assert_eq!(bus.read32(0xd000_0050, 1) & 1, 0, "NS injected into S FIFO");
    assert_eq!(bus.read32(0xd002_0058, 1), 0x1234_5678);
}

#[test]
fn nonsecure_spinlocks_do_not_claim_or_release_secure_locks() {
    let (mut cpu, mut bus) = machine(0xbf00);
    assert_eq!(bus.read32(0xd000_010c, 0), 8);
    assert_eq!(
        cpu.bus_read32(0xd000_010c, &mut bus),
        8,
        "NS lock bank was shared"
    );
    cpu.bus_write32(0xd000_010c, 0, &mut bus);
    assert_eq!(bus.read32(0xd000_005c, 0), 8, "NS released an S lock");
}

#[test]
fn nonsecure_doorbells_do_not_modify_secure_pending_bits() {
    let (mut cpu, mut bus) = machine(0xbf00);
    bus.write32(0xd000_0180, 1, 1);
    assert_eq!(
        cpu.bus_read32(0xd000_0188, &mut bus),
        0,
        "NS saw an S doorbell"
    );
    cpu.bus_write32(0xd000_018c, 15, &mut bus);
    assert_eq!(bus.read32(0xd000_0188, 0), 1, "NS cleared an S doorbell");
}

#[test]
fn nonsecure_code_cannot_access_the_secure_to_nonsecure_sio_mirror() {
    let (mut cpu, mut bus) = machine(0x6808);
    cpu.regs.r[1] = 0xd002_0050;
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.ipsr(), 3, "NS accessed the S-only SIO mirror");
    assert_eq!(cpu.ppb.bfar, 0xd002_0050);
}

#[test]
fn nonsecure_gpio_masks_filter_reads_and_preserve_secure_outputs() {
    for width in [1, 2, 4] {
        let (mut cpu, mut bus) = machine(0xbf00);
        bus.write32(0x4006_000c, 0x0f, 0);
        bus.write32(0xd000_0010, 0x1234_5678, 0);
        bus.write32(0xd000_0030, 0x8765_4321, 0);
        assert_eq!(cpu.bus_read32(0xd000_0010, &mut bus), 8, "NS read S GPIO");
        match width {
            1 => cpu.bus_write8(0xd000_0010, 0xff, &mut bus),
            2 => cpu.bus_write16(0xd000_0010, 0xffff, &mut bus),
            _ => cpu.bus_write32(0xd000_0010, u32::MAX, &mut bus),
        }
        assert_eq!(
            bus.read32(0xd000_0010, 0),
            0x1234_567f,
            "NS overwrote S GPIO"
        );
        cpu.bus_write32(0xd000_0040, u32::MAX, &mut bus);
        assert_eq!(bus.read32(0xd000_0030, 0), 0x8765_4320);
    }
}

#[test]
fn interpolators_are_accessible_only_from_the_assigned_sio_bank() {
    let (mut cpu, mut bus) = machine(0x6808);
    cpu.regs.r[1] = 0xd000_0080;
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.ipsr(), 3, "NS read the Secure interpolator");
    let (mut cpu, mut bus) = machine(0xbf00);
    bus.write32(0xd000_0190, 1, 0);
    cpu.bus_write32(0xd000_0080, 42, &mut bus);
    assert_eq!(cpu.bus_read32(0xd000_0080, &mut bus), 42);
    assert!(!bus.bus_fault(0));
    cpu.transition_to_secure();
    cpu.bus_read32(0xd000_0080, &mut bus);
    assert!(bus.bus_fault(0), "S retained the assigned NS interpolator");
}

#[test]
fn nonsecure_cannot_reassign_sio_peripherals_or_use_mtime() {
    for address in [0xd000_0190, 0xd000_01a4, 0xd000_01b0] {
        let (mut cpu, mut bus) = machine(0x6808);
        cpu.regs.r[1] = address;
        cpu.step(&mut bus);
        assert_eq!(cpu.regs.ipsr(), 3, "NS touched Secure-only SIO state");
    }
}

#[test]
fn nonsecure_cp0_obeys_gpio_masks() {
    let (mut cpu, mut bus) = machine(0xbf00);
    cpu.ppb.nsacr = 1;
    cpu.ppb.ns.cpacr = 3;
    bus.write32(0x4006_000c, 15, 0);
    bus.write32(0xd000_0010, 0x1234_5678, 0);
    cpu.thumb32_coprocessor(0xee10, 0x0010, &mut bus);
    assert_eq!(cpu.regs.r[0], 8, "CP0 read bypassed NS GPIO masks");
    cpu.regs.r[0] = u32::MAX;
    cpu.thumb32_coprocessor(0xee00, 0x0010, &mut bus);
    assert_eq!(bus.read32(0xd000_0010, 0), 0x1234_567f, "CP0 wrote S GPIO");
}

#[test]
fn nonsecure_gpio_input_and_high_bank_masks_are_enforced() {
    let (mut cpu, mut bus) = machine(0xbf00);
    bus.write32(0x4006_000c, 15, 0);
    bus.write32(0x4006_0010, 15, 0);
    bus.gpio_in
        .store(u32::MAX, std::sync::atomic::Ordering::Relaxed);
    bus.write32(0xd000_0014, 0x1234_5678, 0);
    assert_eq!(cpu.bus_read32(0xd000_0004, &mut bus), 15);
    assert_eq!(cpu.bus_read32(0xd000_0014, &mut bus), 8);
    cpu.bus_write32(0xd000_0014, u32::MAX, &mut bus);
    assert_eq!(bus.read32(0xd000_0014, 0), 0x1234_567f);
}

#[test]
fn serial_high_gpio_outputs_drive_pins_before_nonsecure_input_filtering() {
    let mut emu = crate::Emulator::new(crate::Config::default());
    emu.bus.write32(0xd000_0014, 0x1234, 0);
    emu.bus.write32(0xd000_0034, 0xffff, 0);
    emu.update_gpio();
    assert_eq!(
        emu.bus.read32(0xd000_0008, 0) & 0xffff,
        0x1234,
        "high SIO output did not drive its pins"
    );
    let (mut cpu, _) = machine(0xbf00);
    emu.bus.write32(0x4006_0010, 15, 0);
    assert_eq!(cpu.bus_read32(0xd000_0008, &mut emu.bus), 4);
}

#[test]
fn nonsecure_dma_controller_grant_does_not_expose_secure_channel_registers() {
    let (mut cpu, mut bus) = machine(0x6808);
    bus.write32(0x4002_3000, 1 << crate::bus::RESET_DMA, 0);
    bus.write32(0x5000_0000, SECRET, 0);
    bus.write32(0x4006_0044, 0xacce_00ff, 0);
    cpu.regs.r[1] = 0x5000_0000;
    cpu.step(&mut bus);
    assert_eq!(cpu.regs.r[0], 0, "NS saw Secure DMA channel pointers");
    assert_eq!(cpu.regs.ipsr(), 3);
}

#[test]
fn nonsecure_dma_narrow_stores_cannot_change_secure_channel_addresses() {
    for op in [0x7008, 0x8008, 0x6008] {
        let (mut cpu, mut bus) = machine(op);
        bus.write32(0x4002_3000, 1 << crate::bus::RESET_DMA, 0);
        bus.write32(0x5000_0000, SECRET, 0);
        bus.write32(0x4006_0044, 0xacce_00ff, 0);
        cpu.regs.r[1] = 0x5000_0000;
        cpu.regs.r[0] = NS_DATA;
        cpu.step(&mut bus);
        assert_eq!(
            bus.read32(0x5000_0000, 0),
            SECRET,
            "NS changed an S DMA pointer"
        );
        assert_eq!(cpu.regs.ipsr(), 3);
    }
}
