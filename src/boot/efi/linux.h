/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

EFI_STATUS linux_exec(
        EFI_HANDLE *image, CHAR8 *cmdline, UINTN cmdline_size, UINTN linux_addr, UINTN initrd_addr, UINTN initrd_size, BOOLEAN secure);
