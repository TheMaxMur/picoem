// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use crate::bus::accessctrl::{Access, Master};

pub(super) const SECCFG_CH: u32 = 0x480;
pub(super) const SECCFG_IRQ: u32 = 0x4c0;
const SECCFG_MISC: u32 = 0x4d0;
const MPU_CTRL: u32 = 0x500;
const MPU_BAR: u32 = 0x504;
const MPU_END: u32 = MPU_BAR + 8 * 8;
const CH_LOCK: u32 = 4;

pub(super) struct Security {
    channels: [u32; 16],
    irqs: [u32; 4],
    misc: u32,
    mpu_ctrl: u32,
    regions: [(u32, u32); 8],
}

impl Default for Security {
    fn default() -> Self {
        Self {
            channels: [3; 16],
            irqs: [3; 4],
            misc: 0x3ff,
            mpu_ctrl: 0,
            regions: [(0, 0); 8],
        }
    }
}

pub(super) fn level(access: Access) -> u32 {
    (u32::from(access.secure) << 1) | u32::from(access.privileged)
}

fn aliased(old: u32, value: u32, alias: u32) -> u32 {
    match alias {
        1 => old ^ value,
        2 => old | value,
        3 => old & !value,
        _ => value,
    }
}

impl Security {
    pub fn channel_level(&self, channel: usize) -> u32 {
        self.channels[channel] & 3
    }

    pub fn channel_access(&self, channel: usize) -> Access {
        let attrs = self.channel_level(channel);
        Access {
            master: Master::Dma,
            secure: attrs & 2 != 0,
            privileged: attrs & 1 != 0,
        }
    }

    pub fn irq_level(&self, irq: usize) -> u32 {
        self.irqs[irq] & 3
    }

    pub fn timer_level(&self, timer: usize) -> u32 {
        (self.misc >> (2 + timer * 2)) & 3
    }

    pub fn lock_channel(&mut self, channel: usize) {
        self.channels[channel] |= CH_LOCK;
    }

    pub fn channel_mask(&self, max_level: u32) -> u32 {
        self.channels
            .iter()
            .enumerate()
            .fold(0, |mask, (i, attrs)| {
                if attrs & 3 <= max_level {
                    mask | (1 << i)
                } else {
                    mask
                }
            })
    }

    pub fn required(&self, offset: u32) -> u32 {
        match offset {
            0..=0x3ff => self.channel_level((offset / 0x40) as usize),
            0x404..=0x40f => self.irq_level(0),
            0x414..=0x41f => self.irq_level(1),
            0x424..=0x42f => self.irq_level(2),
            0x434..=0x43f => self.irq_level(3),
            0x440..=0x44f => self.timer_level(((offset - 0x440) / 4) as usize),
            0x454..=0x45b => self.misc & 3,
            0x800..=0xbff => self.channel_level(((offset - 0x800) / 0x40) as usize),
            _ => 0,
        }
    }

    pub fn read(&self, offset: u32, access: Access) -> Result<Option<u32>, ()> {
        Ok(match offset {
            SECCFG_CH..SECCFG_IRQ => Some(self.channels[((offset - SECCFG_CH) / 4) as usize]),
            SECCFG_IRQ..SECCFG_MISC => Some(self.irqs[((offset - SECCFG_IRQ) / 4) as usize]),
            SECCFG_MISC => Some(self.misc),
            MPU_CTRL => {
                if !access.privileged {
                    return Err(());
                }
                Some(self.mpu_ctrl)
            }
            MPU_BAR..MPU_END => {
                if !access.privileged {
                    return Err(());
                }
                let (bar, lar) = self.regions[((offset - MPU_BAR) / 8) as usize];
                let visible = access.secure || (lar & 4 == 0 && self.mpu_ctrl & 8 == 0);
                Some(if offset & 4 != 0 {
                    if visible { bar } else { 0 }
                } else if visible {
                    lar
                } else {
                    lar & 7
                })
            }
            _ => None,
        })
    }

    pub fn write(
        &mut self,
        offset: u32,
        value: u32,
        alias: u32,
        access: Access,
    ) -> Result<bool, ()> {
        let old = match offset {
            SECCFG_CH..SECCFG_IRQ => &mut self.channels[((offset - SECCFG_CH) / 4) as usize],
            SECCFG_IRQ..SECCFG_MISC => &mut self.irqs[((offset - SECCFG_IRQ) / 4) as usize],
            SECCFG_MISC => &mut self.misc,
            MPU_CTRL => {
                if !access.privileged {
                    return Err(());
                }
                if access.secure {
                    self.mpu_ctrl = aliased(self.mpu_ctrl, value, alias) & 0xe;
                }
                return Ok(true);
            }
            MPU_BAR..MPU_END => {
                if !access.privileged {
                    return Err(());
                }
                let (bar, lar) = &mut self.regions[((offset - MPU_BAR) / 8) as usize];
                if offset & 4 != 0 {
                    if access.secure {
                        *bar = aliased(*bar, value, alias) & !31;
                    }
                } else {
                    let new = aliased(*lar, value, alias);
                    if access.secure {
                        *lar = new & !0x18;
                    } else if *lar & 4 == 0 {
                        *lar = (*lar & !2) | (new & 2);
                    }
                }
                return Ok(true);
            }
            _ => return Ok(false),
        };
        if !access.privileged {
            return Err(());
        }
        let channel = (SECCFG_CH..SECCFG_IRQ).contains(&offset);
        if channel && *old & CH_LOCK != 0 {
            return Ok(true);
        }
        let new = aliased(*old, value, alias);
        if access.secure {
            *old = new
                & if channel {
                    7
                } else if offset == SECCFG_MISC {
                    0x3ff
                } else {
                    3
                };
        } else {
            for shift in (0..if offset == SECCFG_MISC { 10 } else { 2 }).step_by(2) {
                if *old & (2 << shift) == 0 {
                    *old = (*old & !(1 << shift)) | (new & (1 << shift));
                }
            }
        }
        Ok(true)
    }

    pub fn transfer_allowed(&self, addr: u32, size: u32, channel: usize) -> bool {
        let Some(end) = size.checked_sub(1).and_then(|n| addr.checked_add(n)) else {
            return false;
        };
        [addr, end].into_iter().all(|address| {
            let required = self
                .regions
                .iter()
                .find_map(|(bar, lar)| {
                    (lar & 1 != 0 && address >= *bar && address <= (*lar | 31))
                        .then_some((lar >> 1) & 3)
                })
                .unwrap_or((self.mpu_ctrl >> 1) & 3);
            self.channel_level(channel) >= required
        })
    }
}
