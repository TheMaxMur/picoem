// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const TX_EMPTY_CTRL: u32 = 1 << 8;
const TEN_BIT_FIRST_ADDRESS_NOACK: u32 = 1 << 1;

#[test]
fn nack_releases_a_blocking_write_and_preserves_its_reason_until_cleared() {
    for stop in [0, DATA_CMD_STOP] {
        let mut i2c = I2cRegs::new(IRQ_I2C0_IRQ, DREQ_I2C0_TX, DREQ_I2C0_RX);
        let mut irqs = 0;
        let con = i2c.read32(IC_CON);
        i2c.write32(IC_CON, con | TX_EMPTY_CTRL, 0, &mut irqs);
        i2c.write32(IC_TAR, 0x1a, 0, &mut irqs);
        i2c.write32(IC_ENABLE, 1, 0, &mut irqs);
        for _ in 0..2 {
            i2c.write32(IC_DATA_CMD, 0xd1 | stop, 0, &mut irqs);
            let raw = i2c.read32(IC_RAW_INTR_STAT);
            assert_ne!(
                raw & INT_TX_EMPTY,
                0,
                "the driver can finish waiting for TX"
            );
            assert_ne!(raw & INT_TX_ABRT, 0);
            assert_ne!(
                raw & INT_STOP_DET,
                0,
                "NACK generates STOP without a STOP command"
            );
            assert_eq!(i2c.read32(IC_TXFLR), 0);
            assert_eq!(i2c.read32(IC_TX_ABRT_SOURCE), ABRT_7B_ADDR_NOACK);
            i2c.read32(IC_CLR_STOP_DET);
            assert_eq!(i2c.read32(IC_TX_ABRT_SOURCE), ABRT_7B_ADDR_NOACK);
            i2c.read32(IC_CLR_TX_ABRT);
            assert_eq!(i2c.read32(IC_TX_ABRT_SOURCE), 0);
            assert_eq!(i2c.read32(IC_RAW_INTR_STAT) & INT_TX_ABRT, 0);
        }
    }
}

#[test]
fn ten_bit_nack_is_distinct_and_bulk_clear_releases_it() {
    let mut i2c = I2cRegs::new(IRQ_I2C0_IRQ, DREQ_I2C0_TX, DREQ_I2C0_RX);
    let mut irqs = 0;
    let con = i2c.read32(IC_CON);
    i2c.write32(IC_CON, con | IC_CON_10BIT_ADDR_MASTER, 0, &mut irqs);
    i2c.write32(IC_TAR, 0x100, 0, &mut irqs);
    i2c.write32(IC_ENABLE, 1, 0, &mut irqs);
    i2c.write32(IC_DATA_CMD, DATA_CMD_READ | DATA_CMD_STOP, 0, &mut irqs);
    assert_eq!(i2c.read32(IC_TX_ABRT_SOURCE), TEN_BIT_FIRST_ADDRESS_NOACK);
    i2c.read32(IC_CLR_INTR);
    assert_eq!(i2c.read32(IC_TX_ABRT_SOURCE), 0);
    assert_eq!(
        i2c.read32(IC_RAW_INTR_STAT) & (INT_TX_ABRT | INT_STOP_DET),
        0
    );
}

#[test]
fn disabled_i2c_does_not_simulate_a_transaction() {
    let mut i2c = I2cRegs::new(IRQ_I2C0_IRQ, DREQ_I2C0_TX, DREQ_I2C0_RX);
    i2c.write32(IC_DATA_CMD, DATA_CMD_STOP, 0, &mut 0);
    assert_eq!(i2c.read32(IC_RAW_INTR_STAT), 0);
    assert_eq!(i2c.read32(IC_TX_ABRT_SOURCE), 0);
}
