// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const FDEBUG: u32 = 0x008;
const INSTR_MEM0: u32 = 0x048;
const SM0_CLKDIV: u32 = 0x0c8;
const SM0_EXECCTRL: u32 = 0x0cc;
const SM0_SHIFTCTRL: u32 = 0x0d0;
const SM0_INSTR: u32 = 0x0d8;
const SM0_PINCTRL: u32 = 0x0dc;
const SM_STRIDE: u32 = 0x18;
const PULL_BLOCK: u32 = 0x80a0;

#[test]
fn blocking_pull_latches_each_sms_bit_until_w1c_or_reset() {
    for sm in 0..4 {
        let mut pio = PioBlock::new();
        let bit = 1 << (24 + sm);
        pio.write32(INSTR_MEM0, PULL_BLOCK, 0);
        pio.write32(0, 1 << sm, 0);
        pio.step(0);
        assert_eq!(pio.read32(FDEBUG), bit);

        pio.write32(0, 0, 0);
        pio.step_n(10, 0);
        assert_eq!(
            pio.read32(FDEBUG),
            bit,
            "disabling does not clear the latch"
        );
        pio.write32(FDEBUG, bit, 0);
        assert_eq!(pio.read32(FDEBUG), 0);
        pio.write32(0, 1 << sm, 0);
        pio.step(0);
        assert_eq!(pio.read32(FDEBUG), bit, "a continued stall relatches");

        pio.write32(0x010 + 4 * sm, 0x1234, 0);
        pio.step(0);
        assert_eq!(
            pio.read32(FDEBUG),
            bit,
            "refilling does not clear the latch"
        );
        pio.write32(FDEBUG, bit, 0);
        pio.step(0);
        assert_eq!(pio.read32(FDEBUG), 0, "the unblocked PULL has advanced");
        pio.reset();
        assert_eq!(pio.read32(FDEBUG), 0);
    }
}

#[test]
fn w1c_clears_only_the_selected_sticky_bit() {
    let mut pio = PioBlock::new();
    pio.write32(INSTR_MEM0, PULL_BLOCK, 0);
    pio.write32(0, 0xf, 0);
    pio.step(0);
    assert_eq!(pio.read32(FDEBUG), 0x0f00_0000);
    pio.write32(FDEBUG, 1 << 26, 0);
    assert_eq!(pio.read32(FDEBUG), 0x0b00_0000);
}

#[test]
fn forced_blocking_pull_latches_while_the_sm_is_disabled() {
    for sm in 0..4 {
        let mut pio = PioBlock::new();
        pio.write32(SM0_INSTR + sm * SM_STRIDE, PULL_BLOCK, 0);
        assert_eq!(pio.read32(0), 0);
        assert_eq!(pio.read32(FDEBUG), 1 << (24 + sm));
    }
}

#[test]
fn idle_batches_relatch_only_when_a_real_pio_tick_elapses() {
    let mut pio = PioBlock::new();
    pio.write32(INSTR_MEM0, PULL_BLOCK, 0);
    pio.write32(SM0_CLKDIV, 4 << 16, 0);
    pio.write32(0, 1, 0);
    pio.step_n(4, 0);
    assert_eq!(pio.read32(FDEBUG), 1 << 24);
    pio.write32(FDEBUG, 1 << 24, 0);
    pio.step_n(0, 0);
    pio.step_n(3, 0);
    assert_eq!(pio.read32(FDEBUG), 0, "no divider tick has elapsed");
    pio.step_n(2, 0);
    assert_eq!(pio.read32(FDEBUG), 1 << 24);

    pio.write32(FDEBUG, 1 << 24, 0);
    pio.step_n(3, 0);
    assert_eq!(
        pio.read32(FDEBUG),
        1 << 24,
        "the skipped ticks must relatch too"
    );
}

#[test]
fn disabled_nonblocking_and_other_stalls_do_not_latch_txstall() {
    for instruction in [PULL_BLOCK, 0x8080, 0x2080, 0x8020] {
        let mut pio = PioBlock::new();
        pio.write32(INSTR_MEM0, instruction, 0);
        pio.step_n(20, 0);
        assert_eq!(pio.read32(FDEBUG), 0, "disabled SM");
        if instruction != PULL_BLOCK {
            pio.write32(0, 1, 0);
            pio.step_n(20, 0);
            assert_eq!(pio.read32(FDEBUG), 0, "non-TX stall or nonblocking PULL");
        }
    }
}

#[test]
fn display_autopull_stalls_only_after_the_last_byte_has_left_the_osr() {
    let mut pio = PioBlock::new();
    pio.write32(INSTR_MEM0, 0x6001, 0); // OUT PINS, 1 SIDE 0
    pio.write32(INSTR_MEM0 + 4, 0xb042, 0); // NOP SIDE 1
    pio.write32(SM0_EXECCTRL, 1 << 12, 0);
    pio.write32(SM0_SHIFTCTRL, (1 << 17) | (8 << 25) | (1 << 30), 0);
    pio.write32(SM0_PINCTRL, (1 << 29) | (1 << 20) | (1 << 10), 0);
    pio.write32(0x010, 0xa500_0000, 0);
    pio.write32(0, 1, 0);
    for bit in (0..8).rev() {
        pio.step(0);
        assert!(
            pio.read32(0x004) & (1 << 24) != 0,
            "TXEMPTY precedes the last wire bit"
        );
        assert_eq!(pio.pad_out & 3, (0xa5 >> bit) & 1);
        assert_eq!(pio.read32(FDEBUG), 0);
        pio.step(0);
        assert_eq!(pio.pad_out & 3, 2 | ((0xa5 >> bit) & 1));
        assert_eq!(pio.read32(FDEBUG), 0);
    }
    pio.step(0);
    assert_eq!(pio.read32(FDEBUG), 1 << 24);
}
