// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::{CoreBus, CortexM33, Fault};

const SFSR_INVEP: u32 = 1;
const SFSR_AUVIOL: u32 = 1 << 3;
const SFSR_SFARVALID: u32 = 1 << 6;

impl CortexM33 {
    pub(crate) fn security_fault(&mut self, addr: u32, cause: u32) -> bool {
        self.ppb.sfsr |= cause;
        if cause & SFSR_AUVIOL != 0 {
            self.ppb.sfsr |= SFSR_SFARVALID;
            self.ppb.sfar = addr;
        }
        self.pending_fault = Some(Fault::SecureFault);
        false
    }

    pub(crate) fn check_data_access(&mut self, addr: u32, size: u32, write: bool) -> bool {
        let Some(end) = addr.checked_add(size - 1) else {
            return self.security_fault(addr, SFSR_AUVIOL);
        };
        for address in [addr, end] {
            if !self.secure && !self.security_attribution(address).ns {
                return self.security_fault(address, SFSR_AUVIOL);
            }
            if !self.check_mpu(address, write, false) {
                return false;
            }
        }
        true
    }

    pub(crate) fn check_fetch<B: CoreBus>(&mut self, addr: u32, size: u32, bus: &mut B) -> bool {
        let Some(end) = addr.checked_add(size - 1) else {
            return self.security_fault(addr, SFSR_INVEP);
        };
        if !self.secure {
            let first = self.fetch_attribution(addr);
            let last = self.fetch_attribution(end);
            if first.nsc && last.nsc {
                if bus.read16(addr, self.core_id) == 0xe97f
                    && bus.read16(addr.wrapping_add(2), self.core_id) == 0xe97f
                    && self.fetch_attribution(addr.wrapping_add(3)).nsc
                {
                    return true;
                }
                return self.security_fault(addr, SFSR_INVEP);
            }
            if !first.ns || !last.ns {
                return self.security_fault(addr, SFSR_INVEP);
            }
        }
        self.check_mpu(addr, false, true) && self.check_mpu(end, false, true)
    }

    fn check_mpu(&mut self, addr: u32, write: bool, execute: bool) -> bool {
        let (ctrl, regions) = if self.secure {
            (self.ppb.mpu_ctrl, &self.ppb.mpu_regions)
        } else {
            (self.ppb.ns.mpu_ctrl, &self.ppb.ns.mpu_regions)
        };
        // Unless HFNMIENA is set, the MPU is bypassed at negative priority.
        if ctrl & 1 == 0
            || (ctrl & 2 == 0 && (matches!(self.regs.ipsr(), 2 | 3) || self.regs.faultmask != 0))
        {
            return true;
        }
        let unpriv = !self.regs.in_handler_mode() && self.regs.control & 1 != 0;
        let (readable, writable, region) = self.mpu_access(addr, !self.secure, unpriv);
        let xn = region.is_some_and(|index| regions[index as usize].0 & 1 != 0);
        if readable && (!write || writable) && (!execute || (!xn && addr < 0x4000_0000)) {
            return true;
        }
        let cause = if execute { 1 } else { (1 << 1) | (1 << 7) };
        if self.secure {
            self.ppb.cfsr |= cause;
            self.ppb.mmfar = addr;
        } else {
            self.ppb.ns.cfsr |= cause;
            self.ppb.ns.mmfar = addr;
        }
        self.pending_fault = Some(Fault::MemManage);
        false
    }
}
