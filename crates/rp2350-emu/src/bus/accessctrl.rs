// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use crate::memory::bank_for_address;

pub(crate) const ACCESSCTRL_BASE: u32 = 0x4006_0000;
const PASSWORD: u32 = 0xacce_0000;
const REGISTER_COUNT: usize = 0xec / 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Master {
    Core0,
    Core1,
    Dma,
    Debugger,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Access {
    pub master: Master,
    pub secure: bool,
    pub privileged: bool,
}

impl Access {
    pub fn debugger() -> Self {
        Self {
            master: Master::Debugger,
            secure: true,
            privileged: true,
        }
    }

    pub fn core(core: u8, secure: bool, privileged: bool) -> Self {
        Self {
            master: if core == 0 {
                Master::Core0
            } else {
                Master::Core1
            },
            secure,
            privileged,
        }
    }
}

#[derive(Clone)]
pub(crate) struct AccessCtrl {
    registers: [u32; REGISTER_COUNT],
    pub contexts: [Access; 2],
    pub peri_nonsec: [u32; 2],
}

impl Default for AccessCtrl {
    fn default() -> Self {
        // pico-sdk 2.2.0 hardware/regs/accessctrl.h; register offsets 0x00..0xe8.
        let mut registers = [0xfc; REGISTER_COUNT];
        registers[0] = 4;
        registers[1..5].fill(0);
        registers[5..17].fill(0xff);
        for offset in [
            0x58, 0x5c, 0xb0, 0xb4, 0xbc, 0xc0, 0xc4, 0xc8, 0xcc, 0xd0, 0xd4, 0xd8, 0xdc, 0xe0,
            0xe4,
        ] {
            registers[offset / 4] = 0xb8;
        }
        registers[0x60 / 4] = 0xff;
        registers[0xb8 / 4] = 0xf8;
        registers[0xe8 / 4] = 0xf8;
        Self {
            registers,
            contexts: [Access::debugger(); 2],
            peri_nonsec: [0; 2],
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Write {
    Applied,
    Ignored,
    BusError,
}

impl AccessCtrl {
    pub fn owns(addr: u32) -> bool {
        (ACCESSCTRL_BASE..ACCESSCTRL_BASE + 0x4000).contains(&addr)
    }

    pub fn read(&self, addr: u32) -> u32 {
        self.registers
            .get(((addr & 0xfff) / 4) as usize)
            .copied()
            .unwrap_or(0)
    }

    pub fn effective(&self, mut access: Access) -> Access {
        if access.master == Master::Core1 && self.registers[1] & 2 != 0 {
            access.secure = false;
        }
        access
    }

    pub fn write(&mut self, addr: u32, value: u32, access: Access) -> Write {
        let access = self.effective(access);
        let offset = addr & 0xfff & !3;
        if !access.privileged || access.master == Master::Dma {
            return Write::BusError;
        }
        let gpio_mask = matches!(offset, 0x0c | 0x10);
        if !gpio_mask && value & 0xffff_0000 != PASSWORD {
            return Write::BusError;
        }
        let master_bit = match access.master {
            Master::Core0 => 1,
            Master::Core1 => 2,
            Master::Dma => 4,
            Master::Debugger => 8,
        };
        if self.registers[0] & master_bit != 0 {
            return Write::Ignored;
        }
        let Some(old) = self.registers.get_mut((offset / 4) as usize) else {
            return Write::Ignored;
        };
        let alias = (addr >> 12) & 3;
        let payload = if gpio_mask { value } else { value & 0xffff };
        let new = match alias {
            1 => *old ^ payload,
            2 => *old | payload,
            3 => *old & !payload,
            _ => payload,
        };
        if !access.secure {
            if offset >= 0x14 && *old & 2 != 0 {
                *old = (*old & !1) | (new & 1);
                return Write::Applied;
            }
            return Write::Ignored;
        }
        match offset {
            0 => *old |= new & 0xf,
            4 => *old = new & 2,
            8 => {
                if new & 1 != 0 {
                    let lock = self.registers[0];
                    let force = self.registers[1];
                    let contexts = self.contexts;
                    let peri_nonsec = self.peri_nonsec;
                    *self = Self::default();
                    self.registers[0] = lock;
                    self.registers[1] = force;
                    self.contexts = contexts;
                    self.peri_nonsec = peri_nonsec;
                }
            }
            0x0c => *old = new,
            0x10 => *old = new & 0xff00_ffff,
            _ => *old = new & 0xff,
        }
        Write::Applied
    }

    pub fn sio_nonsecure(&self, addr: u32, access: Access) -> bool {
        !self.effective(access).secure || addr & 0xffff_0000 == 0xd002_0000
    }

    pub fn gpio_mask(&self, addr: u32, core: u8, high: bool) -> u32 {
        if self.sio_nonsecure(addr, self.contexts[core as usize]) {
            self.registers[if high { 4 } else { 3 }]
        } else {
            u32::MAX
        }
    }

    pub fn nonsecure_dreq_permitted(&self, addr: u32, privileged: bool) -> bool {
        let Some(offset) = target_register(addr) else {
            return false;
        };
        let permissions = self.registers[(offset / 4) as usize];
        permissions & 2 != 0 && (privileged || permissions & 1 != 0)
    }

    pub fn permitted(&self, addr: u32, access: Access) -> bool {
        let access = self.effective(access);
        if addr >> 28 == 0xd {
            if addr & 0xffff_0000 == 0xd002_0000 && !access.secure {
                return false;
            }
            let ns = self.sio_nonsecure(addr, access);
            let offset = addr & 0xfff;
            let core = usize::from(access.master == Master::Core1);
            let assigned = match offset {
                0x080..=0x0bf => Some(1),
                0x0c0..=0x0ff => Some(2),
                0x1c0..=0x1df => Some(1 << 5),
                0x190..=0x193 | 0x1a4..=0x1bf => return !ns,
                _ => None,
            };
            return assigned.is_none_or(|bit| (self.peri_nonsec[core] & bit != 0) == ns);
        }
        if (0x400e_0000..0x400e_4000).contains(&addr) || (0xe004_0000..0xe004_4000).contains(&addr)
        {
            return access.secure;
        }
        let Some(offset) = target_register(addr) else {
            return true;
        };
        let permissions = self.registers[(offset / 4) as usize];
        let master_bit = match access.master {
            Master::Core0 => 0x10,
            Master::Core1 => 0x20,
            Master::Dma => 0x40,
            Master::Debugger => 0x80,
        };
        let privileged_bit = if access.secure { 8 } else { 2 };
        let unprivileged_bit = if access.secure { 4 } else { 1 };
        permissions & master_bit != 0
            && permissions & privileged_bit != 0
            && (access.privileged || permissions & unprivileged_bit != 0)
    }
}

fn target_register(addr: u32) -> Option<u32> {
    if let Some(bank) = bank_for_address(addr) {
        return Some(0x1c + u32::from(bank) * 4);
    }
    match addr {
        0x0000_0000..=0x0000_ffff => Some(0x14),
        0x1000_0000..=0x13ff_ffff => Some(0x18),
        0x5000_0000..=0x5000_ffff => Some(0x44),
        0x5010_0000..=0x5011_ffff => Some(0x48),
        0x5020_0000..=0x5020_ffff => Some(0x4c),
        0x5030_0000..=0x5030_ffff => Some(0x50),
        0x5040_0000..=0x5040_ffff => Some(0x54),
        0x5050_0000..=0x5050_ffff => Some(0xe8),
        0x5060_0000..=0x5060_ffff => Some(0x80),
        0x5070_0000..=0x5070_ffff => Some(0x58),
        0x4000_0000..=0x4016_ffff => match addr & !0x7fff {
            0x4000_0000 => Some(0x60),
            0x4000_8000 => Some(0xbc),
            0x4001_0000 => Some(0xc0),
            0x4001_8000 => Some(0xdc),
            0x4002_0000 => Some(0x64),
            0x4002_8000 => Some(0x68),
            0x4003_0000 => Some(0x6c),
            0x4003_8000 => Some(0x70),
            0x4004_0000 => Some(0x74),
            0x4004_8000 => Some(0xc4),
            0x4005_0000 => Some(0xcc),
            0x4005_8000 => Some(0xd0),
            0x4006_8000 => Some(0x78),
            0x4007_0000 => Some(0xa0),
            0x4007_8000 => Some(0xa4),
            0x4008_0000 => Some(0x90),
            0x4008_8000 => Some(0x94),
            0x4009_0000 => Some(0x84),
            0x4009_8000 => Some(0x88),
            0x400a_0000 => Some(0x7c),
            0x400a_8000 => Some(0x8c),
            0x400b_0000 => Some(0x98),
            0x400b_8000 => Some(0x9c),
            0x400c_0000 => Some(0x80),
            0x400c_8000 => Some(0xe0),
            0x400d_0000 => Some(0xe4),
            0x400d_8000 => Some(0xd8),
            0x400e_8000 => Some(0xc8),
            0x400f_0000 => Some(0xb4),
            0x400f_8000 => Some(0xb8),
            0x4010_0000 => Some(0xb0),
            0x4010_8000 => Some(0xd4),
            0x4012_0000 | 0x4013_0000 => Some(0xa8),
            0x4014_0000 => Some(0x5c),
            0x4016_0000 => Some(0xac),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
#[path = "accessctrl_tests.rs"]
mod tests;
