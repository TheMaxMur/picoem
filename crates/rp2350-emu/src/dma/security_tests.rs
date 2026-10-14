// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SOURCE: u32 = 0x2000_0100;
const DEST: u32 = 0x2007_0200;

fn copy_bus(source: u32, dest: u32) -> Bus {
    let mut bus = Bus::new();
    bus.write32(0x4002_3000, 1 << crate::bus::RESET_DMA, 0);
    bus.write32(SOURCE, 0xdead_beef, 0);
    bus.write32(DMA_BASE, source, 0);
    bus.write32(DMA_BASE + 4, dest, 0);
    bus.write32(DMA_BASE + 8, 1, 0);
    bus.write32(
        DMA_BASE + 12,
        CTRL_EN | (2 << CTRL_DATA_SIZE_SHIFT) | (u32::from(DREQ_FORCE) << CTRL_TREQ_SEL_SHIFT),
        0,
    );
    bus
}

#[test]
fn dma_reads_obey_the_dma_master_bit_in_accessctrl() {
    let mut bus = copy_bus(SOURCE, DEST);
    bus.write32(0x4006_001c, 0xacce_00bf, 0);
    bus.tick_dma();
    assert_eq!(
        bus.read32(DEST, 0),
        0,
        "DMA read bypassed the master filter"
    );
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_READ_ERROR, 0);
    assert!(!bus.dma.channel(0).busy);
    assert_ne!(bus.dma.intr() & 1, 0);
    assert!(!bus.bus_fault(0), "DMA failure leaked into CPU fault state");
}

#[test]
fn dma_writes_obey_the_dma_master_bit_in_accessctrl() {
    let mut bus = copy_bus(SOURCE, DEST);
    bus.write32(0x4006_001c, 0xacce_00bf, 0);
    // Destination uses the same interleaved bank; allow the source bank by
    // putting it in SRAM8's linear window instead.
    bus.write32(0x2008_0000, 0xdead_beef, 0);
    bus.write32(DMA_BASE, 0x2008_0000, 0);
    bus.tick_dma();
    assert_eq!(
        bus.read32(DEST, 0),
        0,
        "DMA write bypassed the master filter"
    );
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_WRITE_ERROR, 0);
}

#[test]
fn dma_cannot_write_accessctrl_even_with_secure_privileged_attributes() {
    let mut bus = copy_bus(SOURCE, 0x4006_0014);
    bus.write32(SOURCE, 0xacce_0038, 0);
    bus.tick_dma();
    assert_eq!(bus.read32(0x4006_0014, 0), 0xff, "DMA changed ACCESSCTRL");
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_WRITE_ERROR, 0);
}

#[test]
fn dma_cannot_address_processor_local_sio() {
    let mut bus = copy_bus(SOURCE, 0xd000_0010);
    bus.tick_dma();
    assert_eq!(
        bus.read32(0xd000_0010, 0),
        0,
        "DMA addressed processor-local SIO"
    );
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_WRITE_ERROR, 0);
}

#[test]
fn dma_security_registers_have_hardware_reset_values_and_lock() {
    let mut dma = Dma::new();
    assert_eq!(dma.read32(0x480), 3);
    assert_eq!(dma.read32(0x4c0), 3);
    assert_eq!(dma.read32(0x4d0), 0x3ff);
    dma.write32(0x480, 1, 0);
    dma.write32(CH_READ_ADDR, DEST, 0);
    assert_eq!(dma.read32(0x480), 5);
    dma.write32(0x480, 3, 0);
    assert_eq!(dma.read32(0x480), 5);
}

#[test]
fn permitted_secure_dma_copy_preserves_existing_behavior() {
    let mut bus = copy_bus(SOURCE, DEST);
    bus.tick_dma();
    assert_eq!(bus.read32(DEST, 0), 0xdead_beef);
    assert_eq!(
        bus.read32(DMA_BASE + 12, 0) & (CTRL_READ_ERROR | CTRL_WRITE_ERROR),
        0
    );
    assert!(!bus.dma.channel(0).busy);
}

fn ns_bus(source: u32, dest: u32, mpu: bool) -> Bus {
    let mut bus = Bus::new();
    bus.write32(0x4002_3000, 1 << crate::bus::RESET_DMA, 0);
    bus.write32(DMA_BASE + 0x480, 1, 0);
    if mpu {
        bus.write32(DMA_BASE + 0x500, 6, 0);
        bus.write32(DMA_BASE + 0x504, 0x2007_0000, 0);
        bus.write32(DMA_BASE + 0x508, 0x2007_ffe3, 0);
    }
    bus.write32(source, 0xdead_beef, 0);
    bus.write32(DMA_BASE, source, 0);
    bus.write32(DMA_BASE + 4, dest, 0);
    bus.write32(DMA_BASE + 8, 1, 0);
    bus.write32(
        DMA_BASE + 12,
        CTRL_EN | (2 << CTRL_DATA_SIZE_SHIFT) | (u32::from(DREQ_FORCE) << CTRL_TREQ_SEL_SHIFT),
        0,
    );
    bus
}

#[test]
fn nonsecure_dma_mpu_refuses_secure_reads_and_writes() {
    let mut bus = ns_bus(SOURCE, DEST, true);
    bus.tick_dma();
    assert_eq!(bus.read32(DEST, 0), 0, "NS DMA exported S memory");
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_READ_ERROR, 0);
    let mut bus = ns_bus(DEST, SOURCE, true);
    bus.write32(SOURCE, 42, 0);
    bus.tick_dma();
    assert_eq!(bus.read32(SOURCE, 0), 42, "NS DMA overwrote S memory");
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_WRITE_ERROR, 0);
}

#[test]
fn permitted_nonsecure_dma_copy_still_works() {
    let mut bus = ns_bus(DEST + 32, DEST, true);
    bus.tick_dma();
    assert_eq!(bus.read32(DEST, 0), 0xdead_beef);
    assert_eq!(
        bus.read32(DMA_BASE + 12, 0) & (CTRL_READ_ERROR | CTRL_WRITE_ERROR),
        0
    );
}

#[test]
fn dma_mpu_checks_logical_aliases_overflow_and_region_precedence() {
    let mut dma = Dma::new();
    dma.write32(0x480, 1, 0);
    dma.write32(0x500, 6, 0);
    dma.write32(0x504, 0x2007_0000, 0);
    dma.write32(0x508, 0x2007_ffe3, 0);
    assert!(dma.security.transfer_allowed(DEST, 4, 0));
    assert!(!dma.security.transfer_allowed(0x2107_0200, 4, 0));
    assert!(!dma.security.transfer_allowed(0x2007_fffe, 4, 0));
    assert!(!dma.security.transfer_allowed(u32::MAX - 1, 4, 0));
    dma.write32(0x50c, 0x2000_0000, 0);
    dma.write32(0x510, 0x2007_ffe7, 0);
    assert!(
        dma.security.transfer_allowed(DEST, 4, 0),
        "lowest region must take precedence"
    );
    assert!(!dma.security.transfer_allowed(SOURCE, 4, 0));
}

#[test]
fn nonsecure_config_writes_cannot_raise_channel_or_mpu_security() {
    let ns = Access::core(0, false, true);
    let mut dma = Dma::new();
    dma.write32_as(0x480, 0, 0, ns).unwrap();
    assert_eq!(dma.read32(0x480), 3);
    dma.write32(0x480, 1, 0);
    dma.write32_as(0x480, 7, 0, ns).unwrap();
    assert_eq!(dma.read32(0x480), 1, "NS raised S or LOCK bits");
    dma.write32_as(0x480, 0, 0, ns).unwrap();
    assert_eq!(dma.read32(0x480), 0);
    dma.write32(0x504, SOURCE, 0);
    dma.write32(0x508, (SOURCE & !31) | 7, 0);
    assert_eq!(dma.read32_as(0x504, ns), Ok(0));
    assert_eq!(dma.read32_as(0x508, ns), Ok(7));
    dma.write32_as(0x504, DEST, 0, ns).unwrap();
    dma.write32_as(0x508, 0, 0, ns).unwrap();
    assert_eq!(dma.read32(0x504), SOURCE);
    assert_eq!(dma.read32(0x508), (SOURCE & !31) | 7);
    assert!(
        dma.write32_as(0x480, 0, 0, Access::core(0, false, false))
            .is_err()
    );
    assert!(dma.read32_as(0x500, Access::core(0, true, false)).is_err());
}

#[test]
fn dma_self_read_cannot_export_a_higher_security_channels_pointer() {
    let mut bus = ns_bus(DEST + 32, DEST, false);
    bus.write32(0x4006_0044, 0xacce_00ff, 0);
    bus.write32(DMA_BASE + 0x40, SOURCE, 0);
    bus.write32(DMA_BASE, DMA_BASE + 0x40, 0);
    bus.tick_dma();
    assert_eq!(
        bus.read32(DEST, 0),
        0,
        "DMA self-read exported S channel state"
    );
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_READ_ERROR, 0);
}

#[test]
fn dma_bus_error_requires_w1c_before_restart_and_preserves_cpu_context() {
    let mut bus = copy_bus(0xf000_0000, DEST);
    bus.tick_dma();
    assert_eq!(
        bus.read32(DMA_BASE + 12, 0) & (CTRL_READ_ERROR | CTRL_AHB_ERROR),
        CTRL_READ_ERROR | CTRL_AHB_ERROR
    );
    assert!(!bus.bus_fault(0));
    bus.write32(DMA_BASE, SOURCE, 0);
    let ctrl =
        CTRL_EN | (2 << CTRL_DATA_SIZE_SHIFT) | (u32::from(DREQ_FORCE) << CTRL_TREQ_SEL_SHIFT);
    bus.write32(DMA_BASE + 12, ctrl, 0);
    assert!(
        !bus.dma.channel(0).busy,
        "ordinary CTRL write restarted a failed DMA channel"
    );
    bus.write32(DMA_BASE + 12, ctrl | CTRL_READ_ERROR, 0);
    bus.tick_dma();
    assert_eq!(bus.read32(DEST, 0), 0xdead_beef);
    assert_eq!(
        bus.read32(DMA_BASE + 12, 0) & (CTRL_READ_ERROR | CTRL_AHB_ERROR),
        0
    );
}

#[test]
fn dma_narrow_writes_preserve_unselected_error_status() {
    let mut bus = copy_bus(0xf000_0000, DEST);
    bus.tick_dma();
    bus.write8(DMA_BASE + 12, CTRL_EN as u8, 0);
    assert_ne!(bus.read32(DMA_BASE + 12, 0) & CTRL_READ_ERROR, 0);
    assert!(!bus.dma.channel(0).busy);
    bus.write8(DMA_BASE + 15, (CTRL_READ_ERROR >> 24) as u8, 0);
    assert_eq!(bus.read32(DMA_BASE + 12, 0) & CTRL_READ_ERROR, 0);
}

#[test]
fn lower_security_irq_cannot_observe_or_acknowledge_secure_channels() {
    let ns = Access::core(0, false, true);
    let mut dma = Dma::new();
    dma.write32(0x484, 1, 0);
    dma.write32(0x4c0, 1, 0);
    dma.intr = 3;
    dma.write32_as(REG_INTE0, 3, 0, ns).unwrap();
    assert_eq!(dma.read32_as(REG_INTR, ns), Ok(2));
    assert_eq!(dma.read32_as(REG_INTS0, ns), Ok(2));
    dma.write32_as(REG_INTS0, 3, 0, ns).unwrap();
    assert_eq!(dma.intr, 1, "NS IRQ acknowledged an S channel");
    let atomics = crate::threaded::CoreAtomics::default();
    dma.route_irqs(&atomics);
    assert_eq!(atomics.irq_pending_load(0), 0);
}

#[test]
fn nonsecure_dma_cannot_observe_secure_peripheral_or_timer_dreqs() {
    let mut bus = ns_bus(DEST + 32, DEST, true);
    let mut dma = std::mem::take(&mut bus.dma);
    assert!(!dma.dreq_visible(crate::dreq::DREQ_SPI0_TX, 0, &bus));
    assert!(!dma.dreq_visible(DREQ_TIMER0, 0, &bus));
    bus.write32(0x4006_0090, 0xacce_00fe, 0);
    assert!(dma.dreq_visible(crate::dreq::DREQ_SPI0_TX, 0, &bus));
    dma.write32(0x4d0, 0x3f7, 0);
    assert!(dma.dreq_visible(DREQ_TIMER0, 0, &bus));
}

#[test]
fn nonsecure_channel_cannot_chain_to_a_secure_channel() {
    let mut bus = ns_bus(DEST + 32, DEST, true);
    bus.write32(DMA_BASE + 0x40 + CH_TRANS_COUNT, 1, 0);
    bus.write32(DMA_BASE + 0x40 + CH_AL1_CTRL, CTRL_EN, 0);
    let ctrl = bus.read32(DMA_BASE + CH_CTRL_TRIG, 0) | (1 << CTRL_CHAIN_TO_SHIFT);
    bus.write32(DMA_BASE + CH_CTRL_TRIG, ctrl, 0);
    bus.tick_dma();
    assert_eq!(bus.read32(DEST, 0), 0xdead_beef);
    assert!(
        !bus.dma.channel(1).busy,
        "NS completion started an S channel"
    );
}
