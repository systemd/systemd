/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* The default path of the PE stub that addons are built from */
#define PE_ADDON_STUB_PATH BOOTLIBDIR "/addon" EFI_MACHINE_TYPE_NAME ".efi.stub"

/* Builds a systemd-stub addon from the specified stub, carrying the specified kernel command line and
 * initrd (each if not empty), and writes it to the specified file descriptor. An .sbat section is
 * added, so that the addon can be revoked via SBAT when signed. */
int pe_addon_make(
                const char *stub_path,
                const char *cmdline,
                const struct iovec *initrd,
                int output_fd);
