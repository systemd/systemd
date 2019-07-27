/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 * Port to systemd-boot
 * Copyright © 2017 Max Resch <resch.max@gmail.com>
 *
 * Security Policy Handling
 * Copyright © 2012 <James.Bottomley@HansenPartnership.com>
 * https://github.com/mjg59/efitools
 */
#pragma once

BOOLEAN shim_loaded(void);

BOOLEAN secure_boot_enabled(void);

EFI_STATUS security_policy_install(void);
