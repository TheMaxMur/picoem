//! External MMIO devices — host-side peripheral models mounted over the
//! RP2350 peripheral window.
//!
//! A host (harness, application embedding the emulator) mounts an
//! [`MmioDevice`] over an address range with [`Bus::mount_mmio`] (or
//! [`crate::Emulator::mount_mmio`]). On the Serial bus every access that
//! lands in the range reaches the device **before** the built-in
//! per-width dispatch, so a mount can replace a built-in stub (USBCTRL,
//! TRNG, OTP, PSM, …) as well as fill an unmodelled hole. Mounts are
//! consulted only for the peripheral window `0x4000_0000..0x6000_0000`;
//! ROM / XIP / SRAM / SIO / PPB accesses never pay for the seam beyond one
//! `is_empty` check.
//!
//! The threaded runtime does not consult mounts:
//! [`crate::Emulator::mount_mmio`] refuses a Threaded emulator.
//!
//! # What a device sees
//!
//! * `offset` — byte offset from the mount base. On an
//!   [`MmioAliasing::Atomic`] mount the atomic-alias bits (12–13) are
//!   stripped first; on a [`MmioAliasing::Flat`] mount they are ordinary
//!   offset bits.
//! * `size` — 1, 2 or 4, the width the bus master issued. The seam does no
//!   byte-lane replication and no read-modify-write: a narrow access
//!   reaches the device as issued, `value` right-aligned.
//! * `alias` (writes only) — on an `Atomic` mount the 2-bit alias code
//!   (0 normal, 1 XOR, 2 SET, 3 CLR — RP2350 datasheet §2.1.3 "Atomic
//!   Register Access"); always 0 on a `Flat` mount. **The device applies
//!   it**, typically with [`crate::peripherals::apply_alias_rmw`]. Only
//!   the device knows which registers have write side effects (W1C,
//!   FIFO push), and resolving the alias in the seam would need a read of
//!   the old value that can fire read side effects (FIFO pop) the
//!   hardware's internal RMW does not. This is the same `(offset, value,
//!   alias)` contract the built-in peripherals follow.
//!
//! Reads through an alias address reach the device as a plain read of
//! the canonical offset.
//!
//! # Flash
//!
//! [`MmioCtx::flash`] and [`MmioCtx::write_flash`] reach the XIP flash
//! backing the core's reads of 0x1000_0000 see, so a model of an external
//! flash chip (behind a mounted QMI) can erase and program the same bytes
//! the XIP read path serves. A write drops both cores' decoded ops for the
//! XIP region at the next drain point, as [`Bus::write_flash`] does.
//!
//! # Time and interrupts
//!
//! [`MmioDevice::tick`] runs once per quantum from
//! `Bus::tick_peripherals`, after the built-in peripherals. Every call
//! receives an [`MmioCtx`]; lines set in [`MmioCtx::raise_irqs`] are
//! asserted on both cores' NVICs when the call returns (the shared-line
//! path the built-in peripherals use). The NVIC latches a pend, so a
//! level-sensitive line is modelled by raising it on every tick while it
//! is high.

use std::any::Any;

use super::{Bus, invalidation_regions};
use crate::memory::Memory;

/// A host-side peripheral model. See the [module docs](self) for the
/// access contract.
///
/// `Any` lets the host get its concrete device back through
/// [`Bus::mmio_device`] / [`Bus::mmio_device_mut`]; `Send` keeps `Bus`
/// movable across threads like every other field.
pub trait MmioDevice: Any + Send {
    /// Read `size` (1, 2 or 4) bytes at `offset`; the result is
    /// right-aligned. Bits above `size` are discarded.
    fn read(&mut self, offset: u32, size: u8, ctx: &mut MmioCtx) -> u32;

    /// Write `size` (1, 2 or 4) bytes of `value` (right-aligned) at
    /// `offset`. `alias` is the atomic-alias code, see the module docs.
    fn write(&mut self, offset: u32, value: u32, size: u8, alias: u32, ctx: &mut MmioCtx);

    /// Advance by `sys_clks` system-clock cycles. Called once per quantum;
    /// the default does nothing.
    fn tick(&mut self, sys_clks: u32, ctx: &mut MmioCtx) {
        let _ = (sys_clks, ctx);
    }
}

/// Per-call context handed to an [`MmioDevice`].
#[derive(Debug, Default)]
pub struct MmioCtx<'a> {
    /// Bus master that issued the access (core 0 / 1); 0 inside
    /// [`MmioDevice::tick`].
    pub core: u8,
    /// Master cycle at the start of the current quantum. Staleness is
    /// bounded by one quantum, as for the built-in peripherals.
    pub cycle: u64,
    /// Current `clk_sys` frequency in Hz.
    pub sys_clk_hz: u32,
    /// External IRQ lines to assert on both cores when the call returns
    /// (bit `n` = NVIC line `n`). Lines outside the peripheral IRQ range
    /// are dropped.
    pub raise_irqs: u64,
    /// The bus's flash backing; `None` in a context built outside a bus
    /// call (e.g. `MmioCtx::default()` in a device's own tests).
    flash: Option<FlashPort<'a>>,
}

/// A mounted device's handle on the XIP flash backing.
struct FlashPort<'a> {
    memory: &'a mut Memory,
    invalidation_regions: &'a mut u8,
}

impl std::fmt::Debug for FlashPort<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlashPort")
            .field("flash_len", &self.memory.xip_bytes().len())
            .finish_non_exhaustive()
    }
}

impl MmioCtx<'_> {
    /// The XIP flash backing (empty when no flash is loaded or the context
    /// has no bus behind it).
    pub fn flash(&self) -> &[u8] {
        self.flash.as_ref().map_or(&[], |f| f.memory.xip_bytes())
    }

    /// Overwrite flash bytes at `offset` in place, as an external flash
    /// chip's erase or program would (the caller applies the NOR bit
    /// semantics). Clamped to the backing; returns the bytes written.
    pub fn write_flash(&mut self, offset: u32, data: &[u8]) -> usize {
        let Some(f) = self.flash.as_mut() else {
            return 0;
        };
        let n = f.memory.xip_write(offset, data);
        *f.invalidation_regions |= invalidation_regions::XIP;
        n
    }
}

/// How address bits 12–13 decode inside a mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioAliasing {
    /// A register block with RP2350 atomic aliases: `+0x1000` XOR,
    /// `+0x2000` SET, `+0x3000` CLR. The mount must sit inside one 4 KB
    /// block whose base has bits 12–13 clear; the aliases are claimed
    /// with it.
    Atomic,
    /// A flat window (RAM-like apertures such as USB DPRAM, boot RAM or
    /// the OTP data views): every address bit is offset, no aliases.
    Flat,
}

/// Returned by [`Bus::mount_mmio`]; names the device for
/// [`Bus::mmio_device`] / [`Bus::mmio_device_mut`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioHandle(usize);

/// Why a mount was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountError {
    /// The range is empty or leaves the peripheral window
    /// `0x4000_0000..0x6000_0000`.
    OutsidePeripheralWindow,
    /// An [`MmioAliasing::Atomic`] mount that does not sit inside one
    /// 4 KB register block with alias bits 12–13 clear.
    NotOneRegisterBlock,
    /// The range (aliases included) overlaps an earlier mount.
    Overlap,
    /// The emulator runs the Threaded model, which does not consult
    /// mounts. Only [`crate::Emulator::mount_mmio`] returns this.
    SerialOnly,
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            MountError::OutsidePeripheralWindow => {
                "MMIO mount is empty or leaves the peripheral window 0x4000_0000..0x6000_0000"
            }
            MountError::NotOneRegisterBlock => {
                "atomic-alias MMIO mount must sit inside one 4 KB register block"
            }
            MountError::Overlap => "MMIO mount overlaps an earlier mount",
            MountError::SerialOnly => "MMIO mounts are Serial-only",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for MountError {}

/// One mounted device. `base` is canonical (alias bits clear for an
/// `Atomic` mount).
pub(crate) struct MmioMount {
    base: u32,
    size: u32,
    aliasing: MmioAliasing,
    device: Box<dyn MmioDevice>,
}

impl MmioMount {
    /// The bus address ranges this mount claims, as `[start, end)` in
    /// u64 so the window's top edge cannot overflow: one range for a
    /// `Flat` mount, the canonical range plus its three aliases for an
    /// `Atomic` one.
    fn claimed(&self) -> impl Iterator<Item = (u64, u64)> {
        let copies = match self.aliasing {
            MmioAliasing::Atomic => 4,
            MmioAliasing::Flat => 1,
        };
        let (base, size) = (self.base as u64, self.size as u64);
        (0..copies).map(move |alias| {
            let start = base + alias * 0x1000;
            (start, start + size)
        })
    }

    fn overlaps(&self, other: &MmioMount) -> bool {
        self.claimed()
            .any(|(s, e)| other.claimed().any(|(os, oe)| s < oe && os < e))
    }
}

const PERIPHERAL_WINDOW: std::ops::Range<u64> = 0x4000_0000..0x6000_0000;

impl Bus {
    /// Mount `device` over `size` bytes at `base`. See the module docs.
    ///
    /// Fails if the range leaves the peripheral window, overlaps an
    /// earlier mount, or (for [`MmioAliasing::Atomic`]) is not inside one
    /// 4 KB register block with alias bits clear. Mounts survive
    /// [`crate::Emulator::reset`]; a device that models reset state
    /// resets itself.
    pub fn mount_mmio<D: MmioDevice>(
        &mut self,
        base: u32,
        size: u32,
        aliasing: MmioAliasing,
        device: D,
    ) -> Result<MmioHandle, MountError> {
        let end = base as u64 + size as u64;
        if size == 0 || !PERIPHERAL_WINDOW.contains(&(base as u64)) || end > PERIPHERAL_WINDOW.end {
            return Err(MountError::OutsidePeripheralWindow);
        }
        if aliasing == MmioAliasing::Atomic
            && (base & 0x3000 != 0 || (base & !0xFFF) as u64 != (end - 1) & !0xFFF)
        {
            return Err(MountError::NotOneRegisterBlock);
        }
        let mount = MmioMount {
            base,
            size,
            aliasing,
            device: Box::new(device),
        };
        if self.external_mmio.iter().any(|m| m.overlaps(&mount)) {
            return Err(MountError::Overlap);
        }
        self.external_mmio.push(mount);
        Ok(MmioHandle(self.external_mmio.len() - 1))
    }

    /// The device behind `handle`, if it is a `T`.
    pub fn mmio_device<T: MmioDevice>(&self, handle: MmioHandle) -> Option<&T> {
        let device: &dyn Any = self.external_mmio.get(handle.0)?.device.as_ref();
        device.downcast_ref::<T>()
    }

    /// Mutable form of [`Self::mmio_device`].
    pub fn mmio_device_mut<T: MmioDevice>(&mut self, handle: MmioHandle) -> Option<&mut T> {
        let device: &mut dyn Any = self.external_mmio.get_mut(handle.0)?.device.as_mut();
        device.downcast_mut::<T>()
    }

    /// The mount serving `addr`, as `(index, offset, alias)`. Callers
    /// gate on `!external_mmio.is_empty()` and the 0x4/0x5 region first.
    #[inline]
    pub(crate) fn find_mmio(&self, addr: u32) -> Option<(usize, u32, u32)> {
        self.external_mmio.iter().enumerate().find_map(|(i, m)| {
            let (canonical, alias) = match m.aliasing {
                MmioAliasing::Atomic => (addr & !0x3000, (addr >> 12) & 3),
                MmioAliasing::Flat => (addr, 0),
            };
            let offset = canonical.wrapping_sub(m.base);
            (canonical >= m.base && offset < m.size).then_some((i, offset, alias))
        })
    }

    /// Run `f` on mount `index` with a context that carries the flash
    /// port, then raise the IRQs the device asked for.
    fn with_mount<R>(
        &mut self,
        index: usize,
        core: u8,
        f: impl FnOnce(&mut dyn MmioDevice, &mut MmioCtx) -> R,
    ) -> R {
        let (cycle, sys_clk_hz) = (self.master_cycle, self.clock_tree.sys_clk_hz);
        let Bus {
            external_mmio,
            memory,
            pending_invalidation_regions,
            ..
        } = self;
        let mut ctx = MmioCtx {
            core,
            cycle,
            sys_clk_hz,
            raise_irqs: 0,
            flash: Some(FlashPort {
                memory,
                invalidation_regions: pending_invalidation_regions,
            }),
        };
        let r = f(external_mmio[index].device.as_mut(), &mut ctx);
        let raise = ctx.raise_irqs;
        self.raise_irqs_u64(raise);
        r
    }

    /// Route a read to mount `index`; raises the IRQs it asks for.
    pub(crate) fn mmio_read(&mut self, index: usize, offset: u32, size: u8, core: u8) -> u32 {
        self.with_mount(index, core, |d, ctx| d.read(offset, size, ctx))
    }

    /// Route a write to mount `index`; raises the IRQs it asks for.
    pub(crate) fn mmio_write(
        &mut self,
        index: usize,
        offset: u32,
        value: u32,
        size: u8,
        alias: u32,
        core: u8,
    ) {
        self.with_mount(index, core, |d, ctx| {
            d.write(offset, value, size, alias, ctx)
        });
    }

    /// Quantum-end tick for every mount. Called from `tick_peripherals`.
    pub(crate) fn tick_mmio(&mut self, sys_clks: u32) {
        for i in 0..self.external_mmio.len() {
            self.with_mount(i, 0, |d, ctx| d.tick(sys_clks, ctx));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Emulator};

    const BASE: u32 = 0x4010_8000; // Unmodelled APB hole.
    const TRNG: u32 = crate::peripherals::trng::TRNG_BASE;
    const IRQ_LINE: u32 = 30;

    /// One access as the device saw it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Seen {
        Read {
            offset: u32,
            size: u8,
            core: u8,
        },
        Write {
            offset: u32,
            value: u32,
            size: u8,
            alias: u32,
        },
    }

    /// Four plain-storage registers; a write to register 3 raises
    /// `IRQ_LINE`; `level` holds `IRQ_LINE` high on every tick.
    #[derive(Default)]
    struct Dummy {
        regs: [u32; 4],
        seen: Vec<Seen>,
        ticks: u32,
        level: bool,
    }

    impl MmioDevice for Dummy {
        fn read(&mut self, offset: u32, size: u8, ctx: &mut MmioCtx) -> u32 {
            self.seen.push(Seen::Read {
                offset,
                size,
                core: ctx.core,
            });
            self.regs[(offset as usize / 4) % 4] >> ((offset & 3) * 8)
        }

        fn write(&mut self, offset: u32, value: u32, size: u8, alias: u32, ctx: &mut MmioCtx) {
            self.seen.push(Seen::Write {
                offset,
                value,
                size,
                alias,
            });
            let reg = (offset as usize / 4) % 4;
            crate::peripherals::apply_alias_rmw(&mut self.regs[reg], value, alias);
            if reg == 3 {
                ctx.raise_irqs |= 1 << IRQ_LINE;
            }
        }

        fn tick(&mut self, _sys_clks: u32, ctx: &mut MmioCtx) {
            self.ticks += 1;
            if self.level {
                ctx.raise_irqs |= 1 << IRQ_LINE;
            }
        }
    }

    fn dummy(emu: &mut Emulator, h: MmioHandle) -> &mut Dummy {
        emu.bus.mmio_device_mut::<Dummy>(h).expect("mounted Dummy")
    }

    #[test]
    fn word_access_reaches_device_and_round_trips() {
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        emu.mmio_write32(BASE + 4, 0xA5A5_0F0F);
        assert_eq!(emu.mmio_read32(BASE + 4), 0xA5A5_0F0F);
        assert_eq!(
            dummy(&mut emu, h).seen,
            vec![
                Seen::Write {
                    offset: 4,
                    value: 0xA5A5_0F0F,
                    size: 4,
                    alias: 0
                },
                Seen::Read {
                    offset: 4,
                    size: 4,
                    core: 0
                },
            ]
        );
    }

    #[test]
    fn atomic_aliases_arrive_canonical_with_their_code() {
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        emu.mmio_write32(BASE, 0x0000_00F0);
        emu.mmio_write32(BASE + 0x2000, 0x0000_000F); // SET
        emu.mmio_write32(BASE + 0x3000, 0x0000_0030); // CLR
        emu.mmio_write32(BASE + 0x1000, 0x0000_0101); // XOR
        assert_eq!(emu.mmio_read32(BASE + 0x2000), 0x0000_01CE);
        let aliases: Vec<(u32, u32)> = dummy(&mut emu, h)
            .seen
            .iter()
            .filter_map(|s| match *s {
                Seen::Write { offset, alias, .. } => Some((offset, alias)),
                Seen::Read { .. } => None,
            })
            .collect();
        assert_eq!(aliases, vec![(0, 0), (0, 2), (0, 3), (0, 1)]);
        // An alias read reaches the device as a plain canonical read.
        assert_eq!(
            dummy(&mut emu, h).seen.last(),
            Some(&Seen::Read {
                offset: 0,
                size: 4,
                core: 0
            })
        );
    }

    /// A stand-in for an external flash chip: a write of `v` to offset 0
    /// programs the halfword `v` at flash offset 0; a read of offset 4
    /// returns the flash word at offset 0 as the device sees it.
    struct FlashChip;

    impl MmioDevice for FlashChip {
        fn read(&mut self, offset: u32, _: u8, ctx: &mut MmioCtx) -> u32 {
            let f = ctx.flash();
            match offset {
                4 => u32::from_le_bytes(f[0..4].try_into().unwrap()),
                _ => f.len() as u32,
            }
        }

        fn write(&mut self, offset: u32, value: u32, _: u8, _: u32, ctx: &mut MmioCtx) {
            if offset == 0 {
                assert_eq!(ctx.write_flash(0, &(value as u16).to_le_bytes()), 2);
            }
        }
    }

    /// A device programming flash through its context changes what the
    /// core fetches next: the decoded `movs r0, #1` at 0x1000_0000 is
    /// dropped and the rewritten `movs r0, #2` runs.
    #[test]
    fn device_flash_writes_reach_the_xip_path_and_the_decode_cache() {
        let mut emu = Emulator::new(Config::default());
        let mut image = vec![0xFFu8; 0x1000];
        image[0..4].copy_from_slice(&[0x01, 0x20, 0xFE, 0xE7]); // movs r0,#1; b .
        emu.load_flash(&image);
        emu.core_mut(1).halt();
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, FlashChip)
            .unwrap();
        emu.core_mut(0).regs.set_pc(0x1000_0000);
        emu.step().unwrap();
        assert_eq!(emu.core(0).regs.r[0], 1);

        assert_eq!(emu.mmio_read32(BASE), 0x1000, "the device sees the backing");
        emu.mmio_write32(BASE, 0x2002); // movs r0, #2
        assert_eq!(emu.mmio_read32(BASE + 4), 0xE7FE_2002);
        assert_eq!(emu.bus.read16(0x1000_0000, 0), 0x2002, "XIP reads see it");
        emu.core_mut(0).regs.set_pc(0x1000_0000);
        emu.step().unwrap();
        assert_eq!(emu.core(0).regs.r[0], 2, "no stale decoded op");
        let _ = h;
    }

    #[test]
    fn narrow_access_is_passed_through_unwidened() {
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        emu.bus.write8(BASE + 9, 0xAB, 1);
        emu.bus.write16(BASE + 0x2006, 0xBEEF, 0);
        dummy(&mut emu, h).regs[2] = 0x4433_2211;
        assert_eq!(emu.bus.read8(BASE + 9, 1), 0x22);
        assert_eq!(emu.bus.read16(BASE + 0x100A, 0), 0x4433);
        assert_eq!(
            dummy(&mut emu, h).seen,
            vec![
                Seen::Write {
                    offset: 9,
                    value: 0xAB,
                    size: 1,
                    alias: 0
                },
                Seen::Write {
                    offset: 6,
                    value: 0xBEEF,
                    size: 2,
                    alias: 2
                },
                Seen::Read {
                    offset: 9,
                    size: 1,
                    core: 1
                },
                Seen::Read {
                    offset: 10,
                    size: 2,
                    core: 0
                },
            ]
        );
    }

    #[test]
    fn flat_mount_keeps_bits_12_13_as_offset() {
        let mut emu = Emulator::new(Config::default());
        let base = 0x4013_0000; // OTP data aperture: flat, 32 KB.
        let h = emu
            .mount_mmio(base, 0x8000, MmioAliasing::Flat, Dummy::default())
            .unwrap();
        emu.mmio_write32(base + 0x3004, 7);
        assert_eq!(
            dummy(&mut emu, h).seen,
            vec![Seen::Write {
                offset: 0x3004,
                value: 7,
                size: 4,
                alias: 0
            }]
        );
    }

    #[test]
    fn mount_overrides_a_built_in_peripheral() {
        let mut emu = Emulator::new(Config::default());
        // Built-in TRNG: EHR_DATA0 is a counter starting at 0.
        assert_eq!(emu.mmio_read32(TRNG + 0x114), 0);
        let h = emu
            .mount_mmio(TRNG, 0x1000, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        dummy(&mut emu, h).regs[1] = 0x5EED;
        // 0x114 % 16 = 4 → the device's register 1, not the counter.
        assert_eq!(emu.mmio_read32(TRNG + 0x114), 0x5EED);
    }

    #[test]
    fn unmounted_addresses_keep_the_built_in_path() {
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        // Just past the mount: HashMap fallthrough, not the device.
        emu.mmio_write32(BASE + 0x10, 0x1234);
        assert_eq!(emu.mmio_read32(BASE + 0x10), 0x1234);
        assert!(dummy(&mut emu, h).seen.is_empty());
    }

    #[test]
    fn write_side_irq_pends_on_both_cores() {
        let mut emu = Emulator::new(Config::default());
        emu.mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        emu.mmio_write32(BASE + 12, 1); // register 3 raises IRQ_LINE
        for core in 0..2 {
            assert_ne!(
                emu.bus.atomics.irq_pending_load(core) & (1 << IRQ_LINE),
                0,
                "core {core} must see the pend"
            );
        }
    }

    #[test]
    fn tick_runs_every_quantum_and_holds_a_level_irq() {
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        emu.core_mut(0).halt();
        emu.core_mut(1).halt();
        emu.step().unwrap();
        emu.step().unwrap();
        assert_eq!(dummy(&mut emu, h).ticks, 2);
        assert_eq!(emu.bus.atomics.irq_pending_load(0) & (1 << IRQ_LINE), 0);
        dummy(&mut emu, h).level = true;
        emu.step().unwrap();
        assert_ne!(emu.bus.atomics.irq_pending_load(0) & (1 << IRQ_LINE), 0);
        // Consumed (as dispatch would) — the next tick re-pends it.
        emu.bus.atomics.clear_irq(0, IRQ_LINE);
        emu.step().unwrap();
        assert_ne!(emu.bus.atomics.irq_pending_load(0) & (1 << IRQ_LINE), 0);
    }

    #[test]
    fn firmware_loads_and_stores_reach_the_device() {
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        dummy(&mut emu, h).regs[0] = 0x0000_0042;
        // r0 = BASE; ldr r1, [r0]; str r1, [r0, #8]; b .
        let prog: [u16; 3] = [0x6801, 0x6081, 0xE7FE];
        for (i, hw) in prog.iter().enumerate() {
            emu.bus.memory.sram_write16((i * 2) as u32, *hw);
        }
        emu.core_mut(1).halt();
        emu.core_mut(0).regs.r[0] = BASE;
        emu.core_mut(0).regs.set_pc(0x2000_0000);
        emu.step().unwrap();
        assert_eq!(emu.core(0).regs.r[1], 0x42);
        assert_eq!(dummy(&mut emu, h).regs[2], 0x42);
    }

    #[test]
    fn mount_validation() {
        let mut emu = Emulator::new(Config::default());
        let d = Dummy::default;
        assert_eq!(
            emu.mount_mmio(0x2000_0000, 4, MmioAliasing::Flat, d()),
            Err(MountError::OutsidePeripheralWindow)
        );
        assert_eq!(
            emu.mount_mmio(0x5FFF_FFFC, 8, MmioAliasing::Flat, d()),
            Err(MountError::OutsidePeripheralWindow)
        );
        assert_eq!(
            emu.mount_mmio(BASE, 0, MmioAliasing::Flat, d()),
            Err(MountError::OutsidePeripheralWindow)
        );
        // Atomic: must not straddle 4 KB, and the base must not be an alias.
        assert_eq!(
            emu.mount_mmio(BASE + 0xFF0, 0x20, MmioAliasing::Atomic, d()),
            Err(MountError::NotOneRegisterBlock)
        );
        assert_eq!(
            emu.mount_mmio(BASE + 0x2000, 4, MmioAliasing::Atomic, d()),
            Err(MountError::NotOneRegisterBlock)
        );
        // The window's top edge is reachable.
        assert!(
            emu.mount_mmio(0x5FFF_FFFC, 4, MmioAliasing::Flat, d())
                .is_ok()
        );
        emu.mount_mmio(BASE, 0x10, MmioAliasing::Atomic, d())
            .unwrap();
        // An Atomic mount claims its aliases: a flat mount there overlaps.
        assert_eq!(
            emu.mount_mmio(BASE + 0x3008, 4, MmioAliasing::Flat, d()),
            Err(MountError::Overlap)
        );
        assert_eq!(
            emu.mount_mmio(BASE + 8, 4, MmioAliasing::Atomic, d()),
            Err(MountError::Overlap)
        );
        // Disjoint registers of the same block, aliases included, do not.
        assert!(
            emu.mount_mmio(BASE + 0x10, 4, MmioAliasing::Atomic, d())
                .is_ok()
        );
        assert!(
            emu.mount_mmio(BASE + 0x3014, 4, MmioAliasing::Flat, d())
                .is_ok()
        );
    }

    #[test]
    fn device_lookup_is_typed() {
        struct Other;
        impl MmioDevice for Other {
            fn read(&mut self, _: u32, _: u8, _: &mut MmioCtx) -> u32 {
                0
            }
            fn write(&mut self, _: u32, _: u32, _: u8, _: u32, _: &mut MmioCtx) {}
        }
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        assert!(emu.bus.mmio_device::<Dummy>(h).is_some());
        assert!(emu.bus.mmio_device::<Other>(h).is_none());
    }

    #[test]
    fn mounts_survive_reset() {
        let mut emu = Emulator::new(Config::default());
        let h = emu
            .mount_mmio(BASE, 0x10, MmioAliasing::Atomic, Dummy::default())
            .unwrap();
        emu.reset();
        emu.mmio_write32(BASE, 5);
        assert_eq!(dummy(&mut emu, h).regs[0], 5);
    }
}
