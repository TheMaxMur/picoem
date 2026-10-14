// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::bus::ppb::{FPCCR_LSPACT, FPCCR_LSPEN};

#[test]
fn a_nested_basic_return_preserves_the_outer_lazy_fp_frame() {
    let mut cpu = CortexM33::for_test(0);
    let mut bus = Bus::with_atomics(Arc::clone(&cpu.atomics));
    cpu.ppb.vtor = 0x2000_0000;
    cpu.regs.msp = 0x2000_1000;
    cpu.regs.r[13] = cpu.regs.msp;
    cpu.regs.set_pc(0x2000_0200);
    cpu.regs.control |= 1 << 2;
    cpu.ppb.fpccr = FPCCR_LSPEN;
    bus.write32(cpu.ppb.vtor + 16 * 4, 0x2000_0301, 0);
    bus.write32(cpu.ppb.vtor + 17 * 4, 0x2000_0401, 0);
    cpu.enter_exception(16, &mut bus);
    let outer_return = cpu.regs.lr();
    let fp_address = cpu.ppb.fpcar;
    assert_eq!(outer_return & (1 << 4), 0);
    assert_ne!(cpu.ppb.fpccr & FPCCR_LSPACT, 0);
    cpu.enter_exception(17, &mut bus);
    let inner_return = cpu.regs.lr();
    assert_ne!(inner_return & (1 << 4), 0);
    assert_eq!(cpu.ppb.fpcar, fp_address);
    assert!(
        cpu.exit_exception(inner_return, &mut bus) > 0,
        "a valid nested basic return was refused"
    );
    assert!(cpu.pending_fault.is_none());
    assert_eq!(cpu.regs.ipsr(), 16);
    assert_ne!(cpu.ppb.fpccr & FPCCR_LSPACT, 0);
    assert_eq!(cpu.ppb.fpcar, fp_address);
    assert!(cpu.exit_exception(outer_return, &mut bus) > 0);
    assert!(cpu.pending_fault.is_none());
    assert_eq!(cpu.regs.ipsr(), 0);
    assert_eq!(cpu.ppb.fpccr & FPCCR_LSPACT, 0);
    assert_eq!(cpu.regs.msp, 0x2000_1000);
}

#[test]
fn an_invalid_exception_return_has_invpc_without_undefined_instruction() {
    let mut cpu = CortexM33::for_test(0);
    let mut bus = Bus::with_atomics(Arc::clone(&cpu.atomics));
    cpu.ppb.vtor = 0x2000_0000;
    cpu.regs.msp = 0x2000_1000;
    cpu.regs.r[13] = cpu.regs.msp;
    bus.write32(cpu.ppb.vtor + 16 * 4, 0x2000_0301, 0);
    bus.write32(cpu.ppb.vtor + 3 * 4, 0x2000_0401, 0);
    cpu.enter_exception(16, &mut bus);
    let invalid = cpu.regs.lr() | 2;
    assert_eq!(cpu.exit_exception(invalid, &mut bus), 0);
    assert!(matches!(cpu.pending_fault, Some(Fault::UsageFault)));
    cpu.deliver_fault(Fault::UsageFault, &mut bus);
    assert_ne!(
        cpu.ppb.cfsr & (1 << 18),
        0,
        "INVPC was not reported in its architectural bit"
    );
    assert_eq!(
        cpu.ppb.cfsr & (1 << 16),
        0,
        "exception return was labelled an undefined instruction"
    );
}

#[test]
fn undefined_decoders_report_only_undefined_instruction() {
    for wide in [false, true] {
        let mut cpu = CortexM33::for_test(0);
        let mut bus = Bus::with_atomics(Arc::clone(&cpu.atomics));
        cpu.ppb.vtor = 0x2000_0000;
        cpu.regs.msp = 0x2000_1000;
        cpu.regs.r[13] = cpu.regs.msp;
        bus.write32(cpu.ppb.vtor + 3 * 4, 0x2000_0401, 0);
        if wide {
            cpu.thumb32_undefined(0, 0, &mut bus);
        } else {
            cpu.thumb16_undefined(0, 0, &mut bus);
        }
        cpu.deliver_fault(Fault::UsageFault, &mut bus);
        assert_ne!(cpu.ppb.cfsr & (1 << 16), 0);
        assert_eq!(cpu.ppb.cfsr & (1 << 18), 0);
    }
}
