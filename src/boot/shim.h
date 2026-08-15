/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Port to systemd-boot
 * Copyright © 2017 Max Resch <resch.max@gmail.com>
 *
 * Security Policy Handling
 * Copyright © 2012 <James.Bottomley@HansenPartnership.com>
 * https://github.com/mjg59/efitools
 */
#pragma once

#include "efi.h"

bool shim_loaded(void);
bool shim_loader_available(void);
EFI_STATUS shim_load_image(EFI_HANDLE parent, const EFI_DEVICE_PATH *device_path, bool boot_policy, EFI_HANDLE *ret_image);
void shim_retain_protocol(void);
