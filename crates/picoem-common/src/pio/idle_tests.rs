// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

const PULL_BLOCK: u16 = 0x80a0;

fn pull_block(divider: u32, mask: u8) -> PioBlock {
    let mut pio = PioBlock::new();
    pio.instr_mem.fill(PULL_BLOCK | (1 << 12));
    pio.shared_pin_values = 0x55;
    pio.shared_pin_dirs = 0xffff;
    pio.irq_flags = 0xa5;
    pio.write32(0x168, 16, 0);
    for i in 0..4 {
        pio.write32(0x0c8 + i * 0x18, divider, 0);
        pio.write32(0x0dc + i * 0x18, (1 << 29) | (3 << 10) | (1 << 26), 0);
        let sm = &mut pio.sm[i as usize];
        sm.pc = if i == 0 { 0x19 } else { i as u8 };
        sm.x = 123 + i;
        sm.y = 456 + i;
        sm.isr = 789 + i;
        sm.stall_cycles = u64::MAX - 10;
        sm.cycles_stalled_at_pc_0x19 = u64::MAX - 5;
        pio.set_sm_enabled(i as usize, mask & (1 << i) != 0);
    }
    pio.pad_out_mosi_writes_of_1 = u64::MAX - 4;
    pio
}

fn slow(pio: &mut PioBlock, n: u32, pins: u64) {
    for _ in 0..n {
        pio.step_with_pins(pins);
    }
}

fn stall(kind: &StallKind) -> (u8, bool, u8) {
    match *kind {
        StallKind::None => (0, false, 0),
        StallKind::WaitGpio { polarity, index } => (1, polarity, index),
        StallKind::WaitPin { polarity, index } => (2, polarity, index),
        StallKind::WaitIrq { polarity, index } => (3, polarity, index),
        StallKind::Pull => (4, false, 0),
        StallKind::Push => (5, false, 0),
        StallKind::IrqWait { index } => (6, false, index),
    }
}

fn assert_same(mut fast: PioBlock, mut reference: PioBlock) {
    macro_rules! same {
        ($a:expr, $b:expr; $($field:ident),+ $(,)?) => {
            $(assert_eq!($a.$field, $b.$field, stringify!($field));)+
        };
    }
    same!(fast, reference;
        instr_mem, irq_flags, input_sync_bypass, fdebug, gpio_base,
        shared_pin_values, shared_pin_dirs, pad_out, pad_oe,
        sm_enabled_mask, any_sideset_programmed, int0_inte, int0_intf,
        int1_inte, int1_intf, pad_out_cs_falls, pad_out_cs_rises,
        pad_out_sck_toggles, pad_out_mosi_writes_of_1, prev_pad_out_diag,
    );
    for (a, b) in fast.sm.iter_mut().zip(&mut reference.sm) {
        same!(a, b;
            pc, x, y, isr, osr, isr_count, osr_count, delay_count, stalled,
            enabled, last_insn, pending_exec, sm_id, clkdiv_int, clkdiv_frac,
            clkdiv_acc, execctrl, shiftctrl, pinctrl, sideset_pins, sideset_dirs,
            autopush_count, last_autopush_word, pc_visits, stall_cycles,
            cycles_stalled_at_pc_0x19,
        );
        assert_eq!(stall(&a.stall_kind), stall(&b.stall_kind));
        for (a, b) in [
            (&mut a.tx_fifo, &mut b.tx_fifo),
            (&mut a.rx_fifo, &mut b.rx_fifo),
        ] {
            same!(a, b; push_success, push_drop);
            assert_eq!(a.level(), b.level());
            assert_eq!(a.is_full(), b.is_full());
            while !a.is_empty() || !b.is_empty() {
                assert_eq!(a.pop(), b.pop());
            }
        }
    }
}

#[test]
fn pull_stall_batches_match_each_sysclk_across_dividers_and_phases() {
    for divider in [0, 0xff00, 1 << 16, 0x0001_8000, 0x0003_ff00, 0xffff_ff00] {
        for phase in [0, 1, 255, 256, 511, 1_000_000] {
            for n in [0, 1, 2, 3, 255, 256, 257, 1023, 65537] {
                for mask in [0, 1, 5, 15] {
                    let setup = || {
                        let mut pio = pull_block(divider, mask);
                        for sm in &mut pio.sm {
                            sm.clkdiv_acc = phase;
                        }
                        pio
                    };
                    let mut fast = setup();
                    let mut reference = setup();
                    fast.step_n_with_pins(n, 0x1234_5678_9abc);
                    slow(&mut reference, n, 0x1234_5678_9abc);
                    assert_same(fast, reference);
                }
            }
        }
    }
}

#[test]
fn pull_stall_batches_preserve_distinct_dividers_sideset_and_fifo_wakeup() {
    for dirs in [false, true] {
        let setup = || {
            let mut pio = pull_block(0x0001_8000, 15);
            for (i, sm) in pio.sm.iter_mut().enumerate() {
                sm.clkdiv_int = (i + 1) as u16;
                sm.clkdiv_frac = (i * 57) as u8;
                if dirs {
                    sm.execctrl |= 1 << 29;
                }
                sm.pinctrl |= 8 << 20;
            }
            pio
        };
        let mut fast = setup();
        let mut reference = setup();
        fast.step_n_with_pins(600, 0);
        slow(&mut reference, 600, 0);
        for pio in [&mut fast, &mut reference] {
            for sm in &mut pio.sm {
                assert!(sm.stalled);
                assert!(sm.tx_fifo.push(0x1234_5678));
                let next = usize::from((sm.pc + 1) & 31);
                pio.instr_mem[next] = 0x6008; // OUT PINS, 8
            }
        }
        fast.step_n_with_pins(500, u64::MAX);
        slow(&mut reference, 500, u64::MAX);
        assert!(fast.sm.iter().all(|sm| sm.tx_fifo.is_empty()));
        assert_same(fast, reference);
    }
}

#[test]
fn divider_reprogramming_does_not_discard_accumulated_credit() {
    let mut fast = pull_block(100 << 16, 1);
    let mut reference = pull_block(100 << 16, 1);
    for pio in [&mut fast, &mut reference] {
        slow(pio, 199, 0);
        assert!(pio.sm[0].stalled);
        pio.write32(0x0c8, 1 << 16, 0);
    }
    fast.step_n_with_pins(1024, 0);
    slow(&mut reference, 1024, 0);
    assert_eq!(fast.sm[0].clkdiv_acc, 99 * 256);
    assert_same(fast, reference);
}

#[test]
fn other_stalls_delays_pending_exec_and_active_sms_keep_the_cycle_path() {
    for case in 0..8 {
        let setup = || {
            let mut pio = pull_block(1 << 16, 3);
            slow(&mut pio, 1, 0);
            let sm = &mut pio.sm[1];
            match case {
                0 => {
                    sm.stall_kind = StallKind::WaitGpio {
                        polarity: true,
                        index: 1,
                    }
                }
                1 => {
                    sm.stall_kind = StallKind::WaitPin {
                        polarity: true,
                        index: 1,
                    }
                }
                2 => {
                    sm.stall_kind = StallKind::WaitIrq {
                        polarity: true,
                        index: 1,
                    }
                }
                3 => sm.stall_kind = StallKind::IrqWait { index: 2 },
                4 => sm.stall_kind = StallKind::Push,
                5 => sm.delay_count = 10,
                6 => sm.pending_exec = Some(0xe001),
                7 => {
                    sm.stalled = false;
                    sm.stall_kind = StallKind::None;
                    pio.instr_mem[1] = 0xe001;
                    pio.instr_mem[2] = 0xe000;
                    sm.execctrl = (2 << 12) | (1 << 7);
                }
                _ => unreachable!(),
            }
            pio
        };
        let mut fast = setup();
        let mut reference = setup();
        for pins in [0, 2 << 16, u64::MAX] {
            fast.step_n_with_pins(71, pins);
            slow(&mut reference, 71, pins);
        }
        assert_same(fast, reference);
    }
}

#[test]
fn a_maximum_batch_keeps_clock_phase_and_wrapping_diagnostics() {
    let mut pio = pull_block(0x0003_8000, 1);
    slow(&mut pio, 4, 0);
    let sm = &pio.sm[0];
    let before = sm.stall_cycles;
    let pc_before = sm.cycles_stalled_at_pc_0x19;
    let phase = u64::from(sm.clkdiv_acc);
    let n = u32::MAX;
    let ticks = (phase + u64::from(n) * 256) / (3 * 256 + 128);
    let mosi_before = pio.pad_out_mosi_writes_of_1;
    pio.step_n_with_pins(n, 0);
    assert_eq!(
        u64::from(pio.sm[0].clkdiv_acc),
        (phase + u64::from(n) * 256) % 896
    );
    assert_eq!(pio.sm[0].stall_cycles, before.wrapping_add(ticks));
    assert_eq!(
        pio.sm[0].cycles_stalled_at_pc_0x19,
        pc_before.wrapping_add(ticks)
    );
    assert!(pio.sm[0].stalled);
    assert_eq!(pio.sm[0].pc_visits, [0; 32]);
    if cfg!(feature = "pio-pad-diag") {
        assert_eq!(
            pio.pad_out_mosi_writes_of_1,
            mosi_before.wrapping_add(u64::from(n))
        );
    } else {
        assert_eq!(pio.pad_out_mosi_writes_of_1, mosi_before);
    }
}

#[test]
#[ignore = "host throughput measurement; run with --release --ignored --nocapture"]
fn benchmark_pull_stall_batches() {
    use std::hint::black_box;
    use std::time::Instant;

    let mut fast = pull_block(0x000f_a000, 1);
    let mut reference = pull_block(0x000f_a000, 1);
    let start = Instant::now();
    for _ in 0..10_000 {
        slow(black_box(&mut reference), 16_000, 0);
    }
    let reference_time = start.elapsed();
    let start = Instant::now();
    for _ in 0..10_000 {
        black_box(&mut fast).step_n_with_pins(16_000, 0);
    }
    let fast_time = start.elapsed();
    eprintln!("160M idle PIO sysclks: cycle loop {reference_time:?}, batch {fast_time:?}");
    assert_same(fast, reference);
}
