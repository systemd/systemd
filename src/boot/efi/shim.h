/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Port to systemd-boot
 * Copyright 2017 Max Resch <resch.max@gmail.com>
 *
 * Security Policy Handling
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 * https://github.com/mjg59/efitools
 */

#ifndef __SDBOOT_SHIM_H
#define __SDBOOT_SHIM_H

BOOLEAN shim_loaded(void);

BOOLEAN secure_boot_enabled(void);

EFI_STATUS security_policy_install(void);

EFI_STATUS security_policy_uninstall(void);

#endif
