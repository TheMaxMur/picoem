// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const USB: u32 = 0x5011_0000;
const USB_PERMISSION: u32 = ACCESSCTRL_BASE + 0x48;
const NS: Access = Access {
    master: Master::Core0,
    secure: false,
    privileged: true,
};
const S: Access = Access {
    master: Master::Core0,
    secure: true,
    privileged: true,
};

#[test]
fn defaults_match_the_hardware_privilege_and_master_filters() {
    let policy = AccessCtrl::default();
    assert!(policy.permitted(USB, S));
    assert!(!policy.permitted(USB, NS));
    assert!(policy.permitted(0x4000_0000, NS)); // SYSINFO.
    assert!(!policy.permitted(0x400f_0000, NS)); // TRNG.
    assert!(!policy.permitted(
        0x400f_0000,
        Access {
            master: Master::Dma,
            ..S
        }
    ));
    assert!(policy.permitted(
        0x400f_0000,
        Access {
            master: Master::Debugger,
            ..S
        }
    ));
    assert!(!policy.permitted(
        0x400f_0000,
        Access {
            privileged: false,
            ..S
        }
    ));
}

#[test]
fn ns_cannot_change_protected_permissions_or_gpio_masks() {
    let mut policy = AccessCtrl::default();
    for address in [
        USB_PERMISSION,
        ACCESSCTRL_BASE,
        ACCESSCTRL_BASE + 4,
        ACCESSCTRL_BASE + 8,
    ] {
        let before = policy.read(address);
        assert_eq!(policy.write(address, PASSWORD | 0xffff, NS), Write::Ignored);
        assert_eq!(policy.read(address), before);
    }
    assert_eq!(
        policy.write(ACCESSCTRL_BASE + 0xc, u32::MAX, NS),
        Write::Ignored
    );
    assert_eq!(policy.read(ACCESSCTRL_BASE + 0xc), 0);
}

#[test]
fn ns_can_change_only_nsu_after_secure_code_grants_nsp() {
    let mut policy = AccessCtrl::default();
    assert_eq!(
        policy.write(USB_PERMISSION, PASSWORD | 0x1a, S),
        Write::Applied
    );
    assert!(policy.permitted(USB, NS));
    assert!(!policy.permitted(
        USB,
        Access {
            privileged: false,
            ..NS
        }
    ));
    assert_eq!(
        policy.write(USB_PERMISSION, PASSWORD | 0xff, NS),
        Write::Applied
    );
    assert_eq!(policy.read(USB_PERMISSION), 0x1b);
    assert!(policy.permitted(
        USB,
        Access {
            privileged: false,
            ..NS
        }
    ));
    assert!(!policy.permitted(
        USB,
        Access {
            master: Master::Core1,
            ..NS
        }
    ));
}

#[test]
fn writes_need_password_and_gpio_masks_are_the_exception() {
    let mut policy = AccessCtrl::default();
    assert_eq!(policy.write(USB_PERMISSION, 0xff, S), Write::BusError);
    assert_eq!(policy.read(USB_PERMISSION), 0xfc);
    assert_eq!(policy.write(USB_PERMISSION + 0x2000, 2, S), Write::BusError);
    assert_eq!(
        policy.write(ACCESSCTRL_BASE + 0xc, u32::MAX, S),
        Write::Applied
    );
    assert_eq!(policy.read(ACCESSCTRL_BASE + 0xc), u32::MAX);
    assert_eq!(
        policy.write(ACCESSCTRL_BASE + 0x10, u32::MAX, S),
        Write::Applied
    );
    assert_eq!(policy.read(ACCESSCTRL_BASE + 0x10), 0xff00_ffff);
}

#[test]
fn aliases_and_lock_cannot_erase_protected_permissions() {
    let mut policy = AccessCtrl::default();
    assert_eq!(
        policy.write(USB_PERMISSION + 0x2000, PASSWORD | 2, S),
        Write::Applied
    );
    assert_eq!(policy.read(USB_PERMISSION), 0xfe);
    assert_eq!(
        policy.write(USB_PERMISSION + 0x3000, PASSWORD | 2, S),
        Write::Applied
    );
    assert_eq!(policy.read(USB_PERMISSION), 0xfc);
    assert_eq!(
        policy.write(ACCESSCTRL_BASE, PASSWORD | 1, S),
        Write::Applied
    );
    assert_eq!(
        policy.write(ACCESSCTRL_BASE + 0x3000, PASSWORD | 1, S),
        Write::Ignored
    );
    assert_eq!(
        policy.write(USB_PERMISSION, PASSWORD | 0xff, S),
        Write::Ignored
    );
    assert_eq!(
        policy.write(ACCESSCTRL_BASE + 8, PASSWORD | 1, S),
        Write::Ignored
    );
    assert_eq!(policy.read(ACCESSCTRL_BASE), 5);
    assert_eq!(policy.read(USB_PERMISSION), 0xfc);
}

#[test]
fn unprivileged_and_dma_writes_fault_even_when_the_master_is_locked() {
    let mut policy = AccessCtrl::default();
    assert_eq!(
        policy.write(
            USB_PERMISSION,
            PASSWORD | 0xff,
            Access {
                privileged: false,
                ..S
            }
        ),
        Write::BusError
    );
    assert_eq!(
        policy.write(
            USB_PERMISSION,
            PASSWORD | 0xff,
            Access {
                master: Master::Dma,
                ..S
            }
        ),
        Write::BusError
    );
}

#[test]
fn reset_keeps_locks_and_force_core_ns_but_restores_permissions() {
    let mut policy = AccessCtrl::default();
    policy.write(ACCESSCTRL_BASE + 4, PASSWORD | 2, S);
    policy.write(ACCESSCTRL_BASE, PASSWORD | 2, S);
    policy.write(USB_PERMISSION, PASSWORD | 0xff, S);
    policy.write(ACCESSCTRL_BASE + 8, PASSWORD | 1, S);
    assert_eq!(policy.read(ACCESSCTRL_BASE), 6);
    assert_eq!(policy.read(ACCESSCTRL_BASE + 4), 2);
    assert_eq!(policy.read(USB_PERMISSION), 0xfc);
    assert!(!policy.permitted(
        USB,
        Access {
            master: Master::Core1,
            ..S
        }
    ));
}

#[test]
fn bootram_and_its_aliases_are_always_secure_only() {
    let policy = AccessCtrl::default();
    for base in [0x400e_0000, 0xe004_0000] {
        for alias in [0, 0x1000, 0x2000, 0x3000] {
            assert!(!policy.permitted(base + alias, NS));
            assert!(policy.permitted(base + alias, S));
        }
    }
}

#[test]
fn sram_aliases_use_the_same_bank_permissions() {
    let mut policy = AccessCtrl::default();
    policy.write(ACCESSCTRL_BASE + 0x1c, PASSWORD | 0x18, S);
    for address in [0x2000_0000, 0x2100_0000, 0x2200_0000, 0x2300_0000] {
        assert!(!policy.permitted(address, NS));
        assert!(policy.permitted(address, S));
    }
}
