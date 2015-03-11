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
 * Copyright (C) 2012-2013 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2012 Harald Hoyer <harald@redhat.com>
 */

#ifndef __SDBOOT_UTIL_H
#define __SDBOOT_UTIL_H

#include <efi.h>
#include <efilib.h>

#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

static inline const CHAR16 *yes_no(BOOLEAN b) {
        return b ? L"yes" : L"no";
}

EFI_STATUS parse_boolean(CHAR8 *v, BOOLEAN *b);

UINT64 ticks_read(void);
UINT64 ticks_freq(void);
UINT64 time_usec(void);

EFI_STATUS efivar_set(CHAR16 *name, CHAR16 *value, BOOLEAN persistent);
EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, CHAR16 *name, CHAR8 *buf, UINTN size, BOOLEAN persistent);
EFI_STATUS efivar_set_int(CHAR16 *name, UINTN i, BOOLEAN persistent);
VOID efivar_set_time_usec(CHAR16 *name, UINT64 usec);

EFI_STATUS efivar_get(CHAR16 *name, CHAR16 **value);
EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, CHAR16 *name, CHAR8 **buffer, UINTN *size);
EFI_STATUS efivar_get_int(CHAR16 *name, UINTN *i);

CHAR8 *strchra(CHAR8 *s, CHAR8 c);
CHAR16 *stra_to_path(CHAR8 *stra);
CHAR16 *stra_to_str(CHAR8 *stra);

INTN file_read(EFI_FILE_HANDLE dir, CHAR16 *name, UINTN off, UINTN size, CHAR8 **content);
#endif
