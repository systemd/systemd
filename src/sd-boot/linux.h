/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
 * Copyright (C) 2015 Kay Sievers <kay@vrfy.org>
 */

#ifndef __SDBOOT_kernel_H
#define __SDBOOT_kernel_H

EFI_STATUS linux_exec(EFI_HANDLE *image,
                      CHAR8 *cmdline, UINTN cmdline_size,
                      UINTN linux_addr,
                      UINTN initrd_addr, UINTN initrd_size);
#endif
