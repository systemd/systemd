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
#include "proto/loaded-image.h"

bool shim_loaded(void);
EFI_STATUS shim_load_image(EFI_HANDLE parent, const EFI_DEVICE_PATH *device_path, bool boot_policy, EFI_HANDLE *ret_image);
EFI_STATUS shim_start_image(EFI_HANDLE image);
EFI_STATUS shim_load_kernel(EFI_HANDLE parent, EFI_LOADED_IMAGE_PROTOCOL *loaded_image, const void *source, size_t len, EFI_HANDLE *ret_image);
void shim_retain_protocol(void);
