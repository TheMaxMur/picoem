//! RP2350 bootrom mask-ROM hook resolution (HLD V5 §"Component 3").
//!
//! Walks the bootrom's `rom_func_table` to resolve a 2-byte ASCII code
//! (e.g. `b"RB"` for reboot, `b"FA"` for flash_abort) to its ARM_SEC
//! entry-point PC. The resolver is offline-only: it parses the bootrom
//! binary directly and returns PCs that the emulator hot-path then
//! compares against `CortexM33::pc` to fire the bootrom hook.
//!
//! ## Table format
//!
//! - The well-known pointer at bootrom offset `0x14` is a u16 holding
//!   the table's start file-offset within the bootrom binary (e.g.
//!   `0x7cd4` for the in-tree pinned bootrom). On RP2350 the bootrom
//!   is mapped at PC `0x0000_0000`, so the file offset and the runtime
//!   PC coincide; resolved PCs are returned directly without rebasing.
//! - Each entry is `(u16 code, u16 bitmask)` followed by a variable-
//!   length tail of u16 slots — one slot per set bit in the bitmask.
//! - The bitmask encodes which "flavours" of pointer the entry has.
//!   The flavours follow the `RT_FLAG_*` ordering used by pico-sdk:
//!     - bit 0 — `RT_FLAG_FUNC_RISCV` (Hazard3)
//!     - bit 1 — `RT_FLAG_FUNC_RISCV_FAR`
//!     - bit 2 — `RT_FLAG_FUNC_ARM_SEC` (Secure ARM code, what we want)
//!     - bit 3 — flavour-distinguishing aux
//!     - bit 4 — `RT_FLAG_FUNC_ARM_NONSEC` (Non-Secure: secure-gateway PC)
//!     - bit 6 — `RT_FLAG_DATA`
//!     - bit 7 — table-walk val variant
//! - The end of the table is signalled by `code == 0`.
//!
//! For each entry, slot N corresponds to the N-th lowest set bit in the
//! bitmask. So if `bitmask == 0x0017` (bits 0,1,2,4 set), slot 0 is at
//! `entry+4` (RISCV), slot 1 is at `entry+6` (RISCV_FAR), slot 2 is at
//! `entry+8` (ARM_SEC) — that is the PC we want for an ARM hook.
//!
//! Bootrom code addresses fit in u16 because the bootrom region is
//! `0x0000_0000..0x0000_8000` (32 KB); we widen the resolved value to
//! `u32` for hook comparison against `CortexM33::pc`.
//!
//! ## NS aliasing
//!
//! RP2350 IDAU treats `0x0000_8000..0x0000_FFFF` as the Non-Secure ROM
//! alias of `0x0000_0000..0x0000_7FFF` (see
//! `crates/rp2350_emu/src/core/exceptions.rs:837`). The hook fires from
//! both aliases, so [`resolve_bootrom_hooks`] returns both PCs.

/// Walks the `rom_func_table` in a 32 KB ARM bootrom binary and
/// returns the **ARM_SEC** entry-point PC (Secure-state) for the
/// 2-byte code, or `None` if the code is not present (or the entry has
/// no ARM_SEC flavour).
///
/// The `code` parameter is a 2-byte ASCII pair, little-endian — e.g.
/// `b"RB"` matches the table entry whose `u16` `code` field equals
/// `0x4252` (`'B' << 8 | 'R'`).
pub fn resolve_rom_func(bootrom: &[u8], code: &[u8; 2]) -> Option<u32> {
    // Bitmask bit for ARM_SEC. We pick the lowest matching bit on ARM
    // hosts that the bootrom would resolve through `lookup_entry` —
    // bit 2 (`RT_FLAG_FUNC_ARM_SEC`).
    const ARM_SEC_BIT: u32 = 1 << 2;

    if bootrom.len() < 0x18 {
        return None;
    }
    // Well-known pointer at offset 0x14 is a u16 (file offset of the
    // table).
    let table_off = read_u16(bootrom, 0x14)? as usize;
    if table_off == 0 || table_off >= bootrom.len() {
        return None;
    }

    let want_code = u16::from_le_bytes(*code);
    let mut entry_off = table_off;

    loop {
        // Bounds-check entry header (4 bytes: code + bitmask).
        let entry_code = read_u16(bootrom, entry_off)?;
        if entry_code == 0 {
            // End-of-table sentinel.
            return None;
        }
        let bm = read_u16(bootrom, entry_off + 2)? as u32;

        // Number of u16 slots that follow the (code,bm) header.
        let total_slots = bm.count_ones() as usize;

        if entry_code == want_code {
            // Walk the bitmask from bit 0 upwards; the slot index for
            // ARM_SEC is the count of set bits below bit 2.
            if bm & ARM_SEC_BIT == 0 {
                // No ARM_SEC flavour for this code.
                return None;
            }
            let slot_index = (bm & (ARM_SEC_BIT - 1)).count_ones() as usize;
            let slot_off = entry_off + 4 + slot_index * 2;
            // Strip the Thumb LSB from the table-stored PC. The bootrom
            // table holds branch-target PCs with the Thumb bit set
            // (e.g. 0x6f3); production fetch PCs at instruction
            // boundaries are LSB-clear because every branch in the core
            // calls `set_pc(target & !1)` (see `core/exceptions.rs:208`,
            // `core/execute*.rs`). Without this mask, the hook check
            // `Some(pc) == hook_pc_s` never matches in real firmware.
            return read_u16(bootrom, slot_off).map(|v| (v as u32) & !1);
        }

        // Advance: skip the (code,bm) header (4 bytes) + total_slots*2.
        entry_off = entry_off
            .checked_add(4 + total_slots * 2)
            .filter(|&v| v + 4 <= bootrom.len())?;
    }
}

/// Resolves both the Secure (S) and Non-Secure (NS) PCs at which the
/// hook should fire for the given code. Returns `(s, ns)`.
///
/// The NS PC is the S PC plus `0x8000` per RP2350 IDAU aliasing —
/// terminate-only hook semantics: regardless of whether NS firmware
/// reaches the bootrom function via direct fetch (bootrom mapped at NS
/// alias) or via secure gateway, we want the hook to fire.
///
/// If the code resolves to no ARM_SEC entry, both halves of the tuple
/// are `None`.
pub fn resolve_bootrom_hooks(bootrom: &[u8], code: &[u8; 2]) -> (Option<u32>, Option<u32>) {
    let s = resolve_rom_func(bootrom, code);
    let ns = s.map(|pc| pc.wrapping_add(0x0000_8000));
    (s, ns)
}

/// Resolves each code to `(pc, code)` pairs — its Secure entry PC and
/// the Non-Secure alias — in the form [`crate::CortexM33::rom_call_hooks`]
/// holds. Codes without an ARM_SEC entry in `bootrom` are skipped.
pub fn resolve_rom_call_hooks(bootrom: &[u8], codes: &[[u8; 2]]) -> Vec<(u32, [u8; 2])> {
    codes
        .iter()
        .flat_map(|code| {
            let (s, ns) = resolve_bootrom_hooks(bootrom, code);
            [s, ns].into_iter().flatten().map(move |pc| (pc, *code))
        })
        .collect()
}

/// A bootrom function call a hooked core stopped at, as reported by
/// [`crate::Emulator::pending_rom_call`]. The core sits halted at the
/// function's entry with the AAPCS argument registers intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RomCall {
    /// Core that made the call (0 or 1).
    pub core: usize,
    /// The function's two-character `rom_func_table` code, e.g. `*b"RE"`.
    pub code: [u8; 2],
    /// `r0..=r3` at the call.
    pub args: [u32; 4],
}

/// Why [`crate::Emulator::hook_rom_call`] refused a code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RomHookError {
    /// The loaded bootrom has no ARM_SEC entry for the code.
    NotInRomTable,
    /// `RB` is the built-in terminate-only reboot hook
    /// (`Emulator::shutdown_requested`).
    Reserved,
    /// Only a Serial, Arm emulator surfaces hooked calls to the host.
    Unsupported,
}

impl std::fmt::Display for RomHookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            RomHookError::NotInRomTable => "the loaded bootrom has no ARM_SEC entry for this code",
            RomHookError::Reserved => "RB is the built-in terminate-only reboot hook",
            RomHookError::Unsupported => "ROM-call hooks need a Serial, Arm emulator",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for RomHookError {}

#[inline]
fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    bytes
        .get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned_bootrom() -> Vec<u8> {
        crate::load_pinned_silicon_bootrom()
            .expect("in-tree pinned bootrom must load and match its sha256")
    }

    #[test]
    fn resolve_rom_func_finds_known_codes() {
        // Pinned LSB-stripped value: production fetch PC at instruction
        // boundary is `regs.pc()` which is always LSB-clear (every
        // branch in the core does `set_pc(target & !1)`). The hook
        // check compares against this exact value, so an exact-equal
        // assertion catches any future regression that re-introduces
        // the Thumb LSB into resolved PCs.
        let rom = pinned_bootrom();
        let pc = resolve_rom_func(&rom, b"RB").expect("RB must be in the rom_func_table");
        assert_eq!(
            pc, 0x6f2,
            "RB ARM_SEC PC must be the LSB-stripped table value the hook check sees"
        );
    }

    #[test]
    fn resolve_rom_func_finds_other_known_codes() {
        // FA = flash_abort. Stage 0 confirmed this code is present.
        // Same LSB-stripped pin as RB above — see the rationale there.
        let rom = pinned_bootrom();
        let pc = resolve_rom_func(&rom, b"FA").expect("FA must be in the rom_func_table");
        assert_eq!(
            pc, 0xde4,
            "FA ARM_SEC PC must be the LSB-stripped table value the hook check sees"
        );
    }

    #[test]
    fn resolve_rom_func_returns_none_for_unknown_code() {
        let rom = pinned_bootrom();
        assert_eq!(resolve_rom_func(&rom, b"ZZ"), None);
    }

    #[test]
    fn resolve_bootrom_hooks_pairs_secure_with_ns_alias() {
        let rom = pinned_bootrom();
        let (s, ns) = resolve_bootrom_hooks(&rom, b"RB");
        let s = s.expect("RB S hook PC must resolve");
        let ns = ns.expect("RB NS hook PC must resolve when S resolves");
        assert_eq!(ns, s + 0x8000, "NS hook is S + 0x8000 alias");
    }

    #[test]
    fn resolve_bootrom_hooks_handles_missing_code_gracefully() {
        let rom = pinned_bootrom();
        let (s, ns) = resolve_bootrom_hooks(&rom, b"ZZ");
        assert_eq!(s, None);
        assert_eq!(ns, None);
    }

    #[test]
    fn resolve_rom_func_rejects_short_buffer() {
        // Garbage 16-byte buffer must not panic, must return None.
        let rom = [0u8; 16];
        assert_eq!(resolve_rom_func(&rom, b"RB"), None);
    }

    #[test]
    fn resolve_rom_func_handles_zero_table_pointer() {
        // 32-byte buffer with table-pointer field zeroed → None, no panic.
        let mut rom = [0u8; 32];
        // Leave offset 0x14 as zero.
        rom[0x10] = 0x4d;
        rom[0x11] = 0x75; // magic
        assert_eq!(resolve_rom_func(&rom, b"RB"), None);
    }

    // ------------------------------------------------------------------
    // Emulator-level integration tests for the hook check (HLD V5
    // §"Component 3 — Hook check placement").
    // ------------------------------------------------------------------

    use crate::{Config, Emulator};

    /// After loading the pinned silicon bootrom, both cores must have
    /// the `RB` hook PCs populated (Secure + Non-Secure alias).
    #[test]
    fn bootrom_hook_pcs_populated_after_load() {
        let mut emu = Emulator::new(Config::default());
        emu.load_bootrom(&pinned_bootrom());
        let cs = emu.cores.expect_arm();
        let pc_s = cs[0]
            .bootrom_reboot_hook_pc_s
            .expect("S hook PC must be populated");
        let pc_ns = cs[0]
            .bootrom_reboot_hook_pc_ns
            .expect("NS hook PC must be populated");
        assert_eq!(pc_ns, pc_s + 0x8000);
        // Core 1 mirrors core 0 — both seeded by load_bootrom.
        assert_eq!(cs[1].bootrom_reboot_hook_pc_s, Some(pc_s));
        assert_eq!(cs[1].bootrom_reboot_hook_pc_ns, Some(pc_ns));
    }

    /// Driving core 0 at the hook PC then stepping the Emulator must
    /// halt the core, latch `bootrom_hook_fired`, and surface
    /// `shutdown_requested` on the Emulator.
    ///
    /// Regression-guard for the Thumb-LSB bug: production PCs arrive
    /// at the hook check via `set_pc(target & !1)` from branch sites
    /// (see `core/exceptions.rs:208`, `core/execute*.rs`). To prove
    /// the resolver hands back PCs in the same LSB-clear form the
    /// hook check actually sees, we synthesise the production path
    /// here — start from the Thumb-set table value `(pc_s | 1)`, mask
    /// the LSB exactly as a real branch would, then store. Before the
    /// resolver was fixed to strip LSBs internally, `bootrom_reboot_hook_pc_s`
    /// held `0x6f3` while `regs.pc()` (post `& !1`) was `0x6f2` — the
    /// hook never fired in real firmware, but a test that wrote `pc_s`
    /// raw still passed.
    #[test]
    fn bootrom_hook_fires_when_pc_matches() {
        let mut emu = Emulator::new(Config::default());
        emu.load_bootrom(&pinned_bootrom());
        emu.reset();

        let pc_s = emu.cores.expect_arm()[0]
            .bootrom_reboot_hook_pc_s
            .expect("S hook PC must be populated");
        // Sanity-check the resolver already stripped the LSB. If it
        // ever stops doing so, this assertion catches it before the
        // fire path runs (and the failure message is the bug).
        assert_eq!(pc_s & 1, 0, "resolver must hand back LSB-clear PCs");

        // Park core 1 (halted, can't fire spuriously).
        emu.cores.expect_arm_mut()[1].halt();

        // Simulate the production branch path: a real `BX hook_pc`
        // arrives with the Thumb bit set in the operand and the core
        // stores it via `set_pc(operand & !1)`. We re-set the bit so
        // the masking step is exercised explicitly here.
        let branch_target = pc_s | 1;
        emu.cores.expect_arm_mut()[0]
            .regs
            .set_pc(branch_target & !1);
        // Make sure it isn't halted before stepping.
        emu.cores.expect_arm_mut()[0].wake();

        assert!(!emu.shutdown_requested);
        // One quantum is enough — the hook fires before
        // `decode_execute`, halting the core immediately.
        emu.step().unwrap();

        assert!(
            emu.cores.expect_arm()[0].bootrom_hook_fired,
            "core 0 must latch bootrom_hook_fired"
        );
        assert!(
            emu.cores.expect_arm()[0].is_halted(),
            "core 0 must be halted after hook fires"
        );
        assert!(
            emu.shutdown_requested,
            "Emulator::shutdown_requested must be set"
        );
    }

    /// Hook must NOT fire while PC is somewhere unrelated. We seed
    /// SRAM with a tiny self-loop and run a few quanta — the latch
    /// should remain clear.
    #[test]
    fn bootrom_hook_does_not_fire_for_other_pcs() {
        let mut emu = Emulator::new(Config::default());
        emu.load_bootrom(&pinned_bootrom());
        emu.reset();

        // Park core 1 to keep the test single-cored.
        emu.cores.expect_arm_mut()[1].halt();

        // Place a self-loop "B ." at SRAM address 0x2000_0000 and
        // point core 0 at it. The hook PC for RB lives in the bootrom
        // (`pc < 0x4a40`) — SRAM is far from there.
        emu.bus.memory.sram_write8(0x0000_0000, 0xFE);
        emu.bus.memory.sram_write8(0x0000_0001, 0xE7); // B . (Thumb)
        emu.cores.expect_arm_mut()[0].regs.set_pc(0x2000_0000);
        emu.cores.expect_arm_mut()[0].wake();

        // Run several quanta.
        for _ in 0..16 {
            emu.step().unwrap();
        }

        assert!(
            !emu.cores.expect_arm()[0].bootrom_hook_fired,
            "hook must NOT fire when PC stays away from the hook PC"
        );
        assert!(
            !emu.shutdown_requested,
            "shutdown_requested must remain clear"
        );
    }

    /// The NS alias (`hook_pc_s + 0x8000`) must also fire the hook —
    /// covers the IDAU-aliased fetch path used by Non-Secure firmware.
    /// Same Thumb-LSB regression guard as `bootrom_hook_fires_when_pc_matches`:
    /// stage the PC via the production `set_pc(target & !1)` path so a
    /// resolver that hands back LSB-set PCs would fail this test.
    #[test]
    fn bootrom_hook_handles_ns_alias() {
        let mut emu = Emulator::new(Config::default());
        emu.load_bootrom(&pinned_bootrom());
        emu.reset();

        let pc_ns = emu.cores.expect_arm()[0]
            .bootrom_reboot_hook_pc_ns
            .expect("NS hook PC must be populated");
        assert_eq!(pc_ns & 1, 0, "resolver must hand back LSB-clear NS PC");

        // Park core 1.
        emu.cores.expect_arm_mut()[1].halt();
        // Stage via the production branch path (see fires_when_pc_matches).
        let branch_target = pc_ns | 1;
        emu.cores.expect_arm_mut()[0]
            .regs
            .set_pc(branch_target & !1);
        emu.cores.expect_arm_mut()[0].wake();

        emu.step().unwrap();

        assert!(emu.cores.expect_arm()[0].bootrom_hook_fired);
        assert!(emu.shutdown_requested);
    }

    /// HLD V5 §"Hazard3 isolation": the RISC-V step path does not
    /// check or fire the bootrom hook. Hazard3 is a separate struct
    /// (`Hazard3`) without the `bootrom_reboot_hook_pc_*` fields, so
    /// the check is structurally absent. This test pins the ABI: a
    /// RISC-V emulator must not accidentally inherit hook fields, and
    /// actually drives the RV step path so a future change that wires
    /// hook firing into `core_riscv::Hazard3::step` (or the
    /// `step_pair_riscv` driver) breaks this test rather than slipping
    /// past unobserved.
    #[test]
    fn hazard3_does_not_check_arm_hook() {
        let mut emu = crate::EmulatorBuilder::new(Config::default())
            .arch(crate::Arch::RiscV)
            .build()
            .expect("RV serial build is infallible");
        emu.load_bootrom(&pinned_bootrom());
        // `load_bootrom`'s `if let Cores::Arm` guard means no hook PCs
        // were written onto either Hazard3 hart, so no fields exist
        // for the RV step path to check against. The compile-time
        // proof is that `Hazard3` has no `bootrom_reboot_hook_pc_*`
        // members; the runtime proof follows.
        assert!(!emu.shutdown_requested);

        // Drive the RV step path. The Hazard3 reset PC is
        // `0x2000_0000` (SRAM), which is zero-initialised — fetching
        // there decodes as an all-zero word and traps as an illegal
        // instruction. That trap is fine for our purposes: the
        // assertion is "hook never fires," not "step succeeds." Any
        // future change that wires the Arm bootrom hook into the RV
        // dispatch would also fire it on this step regardless of the
        // illegal-instruction trap, so this assertion catches it.
        for _ in 0..16 {
            // Serial-mode `step()` dispatches to `step_pair_riscv` for
            // RV emulators; threaded mode is Arm-only today.
            emu.step().unwrap();
        }
        assert!(
            !emu.shutdown_requested,
            "RV step path must never fire the Arm bootrom hook"
        );
    }

    /// Soft-reboot reload semantic: a second `load_bootrom` must
    /// recompute hook PCs. We synthesise a "different bootrom" by
    /// zero-filling and verifying the hook PCs become `None`, then
    /// reloading the real bootrom and verifying they come back.
    #[test]
    fn load_bootrom_reload_recomputes_hook_pcs() {
        let mut emu = Emulator::new(Config::default());
        emu.load_bootrom(&pinned_bootrom());
        let original_s = emu.cores.expect_arm()[0]
            .bootrom_reboot_hook_pc_s
            .expect("first load populates the hook");

        // Zeroed buffer → no `RB` entry → hook PCs cleared.
        emu.load_bootrom(&vec![0u8; 32 * 1024]);
        assert_eq!(emu.cores.expect_arm()[0].bootrom_reboot_hook_pc_s, None);
        assert_eq!(emu.cores.expect_arm()[0].bootrom_reboot_hook_pc_ns, None);

        // Re-load the real bootrom → hook PCs come back identical.
        emu.load_bootrom(&pinned_bootrom());
        assert_eq!(
            emu.cores.expect_arm()[0].bootrom_reboot_hook_pc_s,
            Some(original_s)
        );
    }

    // ------------------------------------------------------------------
    // Host-serviced ROM-call hooks (`Emulator::hook_rom_call`).
    // ------------------------------------------------------------------

    /// SRAM address of a `b .` the tests return into.
    const LOOP: u32 = 0x2000_0100;

    fn emu_with_hooked(code: &[u8; 2]) -> Emulator {
        let mut emu = Emulator::new(Config::default());
        emu.load_bootrom(&pinned_bootrom());
        emu.reset();
        emu.cores.expect_arm_mut()[1].halt();
        emu.bus.memory.sram_write16(LOOP & 0xFFFF, 0xE7FE);
        emu.hook_rom_call(*code).unwrap();
        emu
    }

    /// Park core 0 at `code`'s Secure entry as a `BLX` from SRAM would.
    fn call_hooked(emu: &mut Emulator, code: &[u8; 2], args: [u32; 4]) {
        let entry = resolve_rom_func(&pinned_bootrom(), code).unwrap();
        let c = &mut emu.cores.expect_arm_mut()[0];
        c.regs.r[..4].copy_from_slice(&args);
        c.regs.set_lr(LOOP | 1);
        c.regs.set_pc(entry);
        c.wake();
    }

    #[test]
    fn hooked_rom_call_round_trip() {
        let mut emu = emu_with_hooked(b"RE");
        call_hooked(&mut emu, b"RE", [0x1000, 0x2000, 1 << 31, 0]);
        emu.step().unwrap();
        let call = emu.pending_rom_call().expect("the hook must stop the core");
        assert_eq!(
            call,
            RomCall {
                core: 0,
                code: *b"RE",
                args: [0x1000, 0x2000, 1 << 31, 0]
            }
        );
        assert!(emu.cores.expect_arm()[0].is_halted());
        assert!(!emu.shutdown_requested, "only RB terminates");
        // Nothing moves until the host answers.
        emu.step().unwrap();
        assert_eq!(emu.pending_rom_call(), Some(call));

        assert!(emu.return_from_rom_call(0, Some(0xABCD)));
        let c = &emu.cores.expect_arm()[0];
        assert_eq!(c.regs.r[0], 0xABCD);
        assert_eq!(c.regs.pc(), LOOP);
        assert!(!c.is_halted());
        assert_eq!(emu.pending_rom_call(), None);
        emu.step().unwrap();
        assert_eq!(emu.cores.expect_arm()[0].regs.pc(), LOOP);
        assert!(!emu.return_from_rom_call(0, None), "no call left to finish");
    }

    /// A genuine call path: firmware asks the ROM's own `rom_table_lookup`
    /// (halfword pointer at 0x16) for `RE`, then `BLX`es the result. The
    /// hook must fire on the entry the ROM hands out, and the return must
    /// land after the `BLX`.
    #[test]
    fn hook_catches_a_call_through_the_rom_lookup() {
        let mut emu = emu_with_hooked(b"RE");
        // blx r2; mov r4, r0; movs r0, #1; movs r1, #2; blx r4; b .
        let prog: [u16; 6] = [0x4790, 0x4604, 0x2001, 0x2102, 0x47A0, 0xE7FE];
        for (i, hw) in prog.iter().enumerate() {
            emu.bus.memory.sram_write16((i * 2) as u32, *hw);
        }
        let lookup = emu.bus.memory.rom_read16(0x16) as u32;
        let c = &mut emu.cores.expect_arm_mut()[0];
        // Post-boot state a direct boot must supply: the bootrom leaves
        // CP7 (RCP) enabled, and every public ROM function, the lookup
        // included, opens with an RCP canary.
        c.ppb.cpacr |= 0x3 << 14;
        c.regs.r[0] = u16::from_le_bytes(*b"RE") as u32;
        c.regs.r[1] = 0x0004; // RT_FLAG_FUNC_ARM_SEC
        c.regs.r[2] = lookup;
        c.regs.msp = 0x2000_2000;
        c.regs.r[13] = 0x2000_2000;
        c.regs.set_pc(0x2000_0000);
        c.wake();
        let mut call = None;
        for _ in 0..64 {
            emu.step().unwrap();
            call = emu.pending_rom_call();
            if call.is_some() {
                break;
            }
        }
        let call = call.expect("the lookup's answer must be the hooked entry");
        assert_eq!((call.code, call.args[0], call.args[1]), (*b"RE", 1, 2));
        emu.return_from_rom_call(0, None);
        emu.step().unwrap();
        assert_eq!(emu.cores.expect_arm()[0].regs.pc(), 0x2000_000A);
    }

    #[test]
    fn hooked_core_waits_for_the_host_not_an_interrupt() {
        /// Holds IRQ 3 high from the quantum-end tick, where the wake
        /// check sees it (a pend made between steps is merged into the
        /// NVIC at the next quantum's start, before that check runs).
        struct Irq3;
        impl crate::MmioDevice for Irq3 {
            fn read(&mut self, _: u32, _: u8, _: &mut crate::MmioCtx) -> u32 {
                0
            }
            fn write(&mut self, _: u32, _: u32, _: u8, _: u32, _: &mut crate::MmioCtx) {}
            fn tick(&mut self, _: u32, ctx: &mut crate::MmioCtx) {
                ctx.raise_irqs |= 1 << 3;
            }
        }
        let mut emu = emu_with_hooked(b"RE");
        emu.mmio_write32(0xE000_E100, 1 << 3); // NVIC_ISER0: IRQ 3
        emu.mount_mmio(0x4010_8000, 4, crate::MmioAliasing::Flat, Irq3)
            .unwrap();
        call_hooked(&mut emu, b"RE", [0; 4]);
        // An enabled, pending IRQ wakes a WFI-halted core; it must not
        // wake one parked on a hooked call.
        for _ in 0..3 {
            emu.step().unwrap();
            assert!(emu.cores.expect_arm()[0].is_halted());
        }
        assert!(emu.pending_rom_call().is_some());
    }

    #[test]
    fn rom_call_hooks_follow_reset_and_bootrom_reload() {
        let mut emu = emu_with_hooked(b"RE");
        let entry = resolve_rom_func(&pinned_bootrom(), b"RE").unwrap();
        let expect = vec![(entry, *b"RE"), (entry + 0x8000, *b"RE")];
        assert_eq!(emu.cores.expect_arm()[1].rom_call_hooks, expect);
        emu.hook_rom_call(*b"RE").unwrap(); // idempotent
        emu.reset();
        assert_eq!(emu.cores.expect_arm()[0].rom_call_hooks, expect);
        emu.load_bootrom(&vec![0u8; 32 * 1024]);
        assert!(emu.cores.expect_arm()[0].rom_call_hooks.is_empty());
        emu.load_bootrom(&pinned_bootrom());
        assert_eq!(emu.cores.expect_arm()[0].rom_call_hooks, expect);
    }

    #[test]
    fn hook_rom_call_refusals() {
        let mut emu = Emulator::new(Config::default());
        emu.load_bootrom(&pinned_bootrom());
        assert_eq!(emu.hook_rom_call(*b"RB"), Err(RomHookError::Reserved));
        assert_eq!(emu.hook_rom_call(*b"ZZ"), Err(RomHookError::NotInRomTable));
        let mut rv = crate::EmulatorBuilder::new(Config::default())
            .arch(crate::Arch::RiscV)
            .build()
            .unwrap();
        rv.load_bootrom(&pinned_bootrom());
        assert_eq!(rv.hook_rom_call(*b"RE"), Err(RomHookError::Unsupported));
    }
}
