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

#include <efi.h>
#include <efilib.h>

#include "util.h"

/*
 * Allocated random UUID, intended to be shared across tools that implement
 * the (ESP)\loader\entries\<vendor>-<revision>.conf convention and the
 * associated EFI variables.
 */
static const EFI_GUID loader_guid = { 0x4a67b082, 0x0a4c, 0x41cf, {0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} };

#ifdef __x86_64__
UINT64 ticks_read(VOID) {
        UINT64 a, d;
        __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
        return (d << 32) | a;
}
#else
UINT64 ticks_read(VOID) {
        UINT64 val;
        __asm__ volatile ("rdtsc" : "=A" (val));
        return val;
}
#endif

/* count TSC ticks during a millisecond delay */
UINT64 ticks_freq(VOID) {
        UINT64 ticks_start, ticks_end;

        ticks_start = ticks_read();
        uefi_call_wrapper(BS->Stall, 1, 1000);
        ticks_end = ticks_read();

        return (ticks_end - ticks_start) * 1000;
}

UINT64 time_usec(VOID) {
        UINT64 ticks;
        static UINT64 freq;

        ticks = ticks_read();
        if (ticks == 0)
                return 0;

        if (freq == 0) {
                freq = ticks_freq();
                if (freq == 0)
                        return 0;
        }

        return 1000 * 1000 * ticks / freq;
}

EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, CHAR16 *name, CHAR8 *buf, UINTN size, BOOLEAN persistent) {
        UINT32 flags;

        flags = EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS;
        if (persistent)
                flags |= EFI_VARIABLE_NON_VOLATILE;

        return uefi_call_wrapper(RT->SetVariable, 5, name, (EFI_GUID *)vendor, flags, size, buf);
}

EFI_STATUS efivar_set(CHAR16 *name, CHAR16 *value, BOOLEAN persistent) {
        return efivar_set_raw(&loader_guid, name, (CHAR8 *)value, value ? (StrLen(value)+1) * sizeof(CHAR16) : 0, persistent);
}

EFI_STATUS efivar_set_int(CHAR16 *name, UINTN i, BOOLEAN persistent) {
        CHAR16 str[32];

        SPrint(str, 32, L"%d", i);
        return efivar_set(name, str, persistent);
}

EFI_STATUS efivar_get(CHAR16 *name, CHAR16 **value) {
        CHAR8 *buf;
        CHAR16 *val;
        UINTN size;
        EFI_STATUS err;

        err = efivar_get_raw(&loader_guid, name, &buf, &size);
        if (EFI_ERROR(err))
                return err;

        val = StrDuplicate((CHAR16 *)buf);
        if (!val) {
                FreePool(buf);
                return EFI_OUT_OF_RESOURCES;
        }

        *value = val;
        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_int(CHAR16 *name, UINTN *i) {
        CHAR16 *val;
        EFI_STATUS err;

        err = efivar_get(name, &val);
        if (!EFI_ERROR(err)) {
                *i = Atoi(val);
                FreePool(val);
        }
        return err;
}

EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, CHAR16 *name, CHAR8 **buffer, UINTN *size) {
        CHAR8 *buf;
        UINTN l;
        EFI_STATUS err;

        l = sizeof(CHAR16 *) * EFI_MAXIMUM_VARIABLE_SIZE;
        buf = AllocatePool(l);
        if (!buf)
                return EFI_OUT_OF_RESOURCES;

        err = uefi_call_wrapper(RT->GetVariable, 5, name, (EFI_GUID *)vendor, NULL, &l, buf);
        if (!EFI_ERROR(err)) {
                *buffer = buf;
                if (size)
                        *size = l;
        } else
                FreePool(buf);
        return err;

}

VOID efivar_set_time_usec(CHAR16 *name, UINT64 usec) {
        CHAR16 str[32];

        if (usec == 0)
                usec = time_usec();
        if (usec == 0)
                return;

        SPrint(str, 32, L"%ld", usec);
        efivar_set(name, str, FALSE);
}

static INTN utf8_to_16(CHAR8 *stra, CHAR16 *c) {
        CHAR16 unichar;
        UINTN len;
        UINTN i;

        if (stra[0] < 0x80)
                len = 1;
        else if ((stra[0] & 0xe0) == 0xc0)
                len = 2;
        else if ((stra[0] & 0xf0) == 0xe0)
                len = 3;
        else if ((stra[0] & 0xf8) == 0xf0)
                len = 4;
        else if ((stra[0] & 0xfc) == 0xf8)
                len = 5;
        else if ((stra[0] & 0xfe) == 0xfc)
                len = 6;
        else
                return -1;

        switch (len) {
        case 1:
                unichar = stra[0];
                break;
        case 2:
                unichar = stra[0] & 0x1f;
                break;
        case 3:
                unichar = stra[0] & 0x0f;
                break;
        case 4:
                unichar = stra[0] & 0x07;
                break;
        case 5:
                unichar = stra[0] & 0x03;
                break;
        case 6:
                unichar = stra[0] & 0x01;
                break;
        }

        for (i = 1; i < len; i++) {
                if ((stra[i] & 0xc0) != 0x80)
                        return -1;
                unichar <<= 6;
                unichar |= stra[i] & 0x3f;
        }

        *c = unichar;
        return len;
}

CHAR16 *stra_to_str(CHAR8 *stra) {
        UINTN strlen;
        UINTN len;
        UINTN i;
        CHAR16 *str;

        len = strlena(stra);
        str = AllocatePool((len + 1) * sizeof(CHAR16));

        strlen = 0;
        i = 0;
        while (i < len) {
                INTN utf8len;

                utf8len = utf8_to_16(stra + i, str + strlen);
                if (utf8len <= 0) {
                        /* invalid utf8 sequence, skip the garbage */
                        i++;
                        continue;
                }

                strlen++;
                i += utf8len;
        }
        str[strlen] = '\0';
        return str;
}

CHAR16 *stra_to_path(CHAR8 *stra) {
        CHAR16 *str;
        UINTN strlen;
        UINTN len;
        UINTN i;

        len = strlena(stra);
        str = AllocatePool((len + 2) * sizeof(CHAR16));

        str[0] = '\\';
        strlen = 1;
        i = 0;
        while (i < len) {
                INTN utf8len;

                utf8len = utf8_to_16(stra + i, str + strlen);
                if (utf8len <= 0) {
                        /* invalid utf8 sequence, skip the garbage */
                        i++;
                        continue;
                }

                if (str[strlen] == '/')
                        str[strlen] = '\\';
                if (str[strlen] == '\\' && str[strlen-1] == '\\') {
                        /* skip double slashes */
                        i += utf8len;
                        continue;
                }

                strlen++;
                i += utf8len;
        }
        str[strlen] = '\0';
        return str;
}

CHAR8 *strchra(CHAR8 *s, CHAR8 c) {
        do {
                if (*s == c)
                        return s;
        } while (*s++);
        return NULL;
}

INTN file_read(EFI_FILE_HANDLE dir, CHAR16 *name, UINTN off, UINTN size, CHAR8 **content) {
        EFI_FILE_HANDLE handle;
        CHAR8 *buf;
        UINTN buflen;
        EFI_STATUS err;
        UINTN len;

        err = uefi_call_wrapper(dir->Open, 5, dir, &handle, name, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return err;

        if (size == 0) {
                EFI_FILE_INFO *info;

                info = LibFileInfo(handle);
                buflen = info->FileSize+1;
                FreePool(info);
        } else
                buflen = size;

        if (off > 0) {
                err = uefi_call_wrapper(handle->SetPosition, 2, handle, off);
                if (EFI_ERROR(err))
                        return err;
        }

        buf = AllocatePool(buflen);
        err = uefi_call_wrapper(handle->Read, 3, handle, &buflen, buf);
        if (!EFI_ERROR(err)) {
                buf[buflen] = '\0';
                *content = buf;
                len = buflen;
        } else {
                len = err;
                FreePool(buf);
        }

        uefi_call_wrapper(handle->Close, 1, handle);
        return len;
}
