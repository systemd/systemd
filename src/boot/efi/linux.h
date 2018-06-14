/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 * Copyright © 2015 Kay Sievers <kay@vrfy.org>
 */

#ifndef __SDBOOT_kernel_H
#define __SDBOOT_kernel_H

EFI_STATUS linux_exec(EFI_HANDLE *image,
                      CHAR8 *cmdline, UINTN cmdline_size,
                      UINTN linux_addr,
                      UINTN initrd_addr, UINTN initrd_size, BOOLEAN secure);
#endif
