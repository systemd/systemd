/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 * Copyright © 2015 Kay Sievers <kay@vrfy.org>
 */

#ifndef __SDBOOT_DISK_H
#define __SDBOOT_DISK_H

EFI_STATUS disk_get_part_uuid(EFI_HANDLE *handle, CHAR16 uuid[37]);
#endif
