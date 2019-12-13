/* SPDX-License-Identifier: LGPL-2.1+ */

#include <efi.h>
#include <efilib.h>

#include "util.h"

/*
 * Allocated random UUID, intended to be shared across tools that implement
 * the (ESP)\loader\entries\<vendor>-<revision>.conf convention and the
 * associated EFI variables.
 */
const EFI_GUID loader_guid = { 0x4a67b082, 0x0a4c, 0x41cf, {0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} };

#ifdef __x86_64__
UINT64 ticks_read(VOID) {
        UINT64 a, d;
        __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
        return (d << 32) | a;
}
#elif defined(__i386__)
UINT64 ticks_read(VOID) {
        UINT64 val;
        __asm__ volatile ("rdtsc" : "=A" (val));
        return val;
}
#else
UINT64 ticks_read(VOID) {
        UINT64 val = 1;
        return val;
}
#endif

/* count TSC ticks during a millisecond delay */
UINT64 ticks_freq(VOID) {
        UINT64 ticks_start, ticks_end;

        ticks_start = ticks_read();
        uefi_call_wrapper(BS->Stall, 1, 1000);
        ticks_end = ticks_read();

        return (ticks_end - ticks_start) * 1000UL;
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

        return 1000UL * 1000UL * ticks / freq;
}

EFI_STATUS parse_boolean(const CHAR8 *v, BOOLEAN *b) {
        if (!v)
                return EFI_INVALID_PARAMETER;

        if (strcmpa(v, (CHAR8 *)"1") == 0 ||
            strcmpa(v, (CHAR8 *)"yes") == 0 ||
            strcmpa(v, (CHAR8 *)"y") == 0 ||
            strcmpa(v, (CHAR8 *)"true") == 0) {
                *b = TRUE;
                return EFI_SUCCESS;
        }

        if (strcmpa(v, (CHAR8 *)"0") == 0 ||
            strcmpa(v, (CHAR8 *)"no") == 0 ||
            strcmpa(v, (CHAR8 *)"n") == 0 ||
            strcmpa(v, (CHAR8 *)"false") == 0) {
                *b = FALSE;
                return EFI_SUCCESS;
        }

        return EFI_INVALID_PARAMETER;
}

EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const CHAR16 *name, const VOID *buf, UINTN size, BOOLEAN persistent) {
        UINT32 flags;

        flags = EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS;
        if (persistent)
                flags |= EFI_VARIABLE_NON_VOLATILE;

        return uefi_call_wrapper(RT->SetVariable, 5, (CHAR16*) name, (EFI_GUID *)vendor, flags, size, (VOID*) buf);
}

EFI_STATUS efivar_set(const CHAR16 *name, const CHAR16 *value, BOOLEAN persistent) {
        return efivar_set_raw(&loader_guid, name, value, value ? (StrLen(value)+1) * sizeof(CHAR16) : 0, persistent);
}

EFI_STATUS efivar_set_int(CHAR16 *name, UINTN i, BOOLEAN persistent) {
        CHAR16 str[32];

        SPrint(str, 32, L"%u", i);
        return efivar_set(name, str, persistent);
}

EFI_STATUS efivar_get(const CHAR16 *name, CHAR16 **value) {
        _cleanup_freepool_ CHAR8 *buf = NULL;
        EFI_STATUS err;
        CHAR16 *val;
        UINTN size;

        err = efivar_get_raw(&loader_guid, name, &buf, &size);
        if (EFI_ERROR(err))
                return err;

        /* Make sure there are no incomplete characters in the buffer */
        if ((size % 2) != 0)
                return EFI_INVALID_PARAMETER;

        if (!value)
                return EFI_SUCCESS;

        /* Return buffer directly if it happens to be NUL terminated already */
        if (size >= 2 && buf[size-2] == 0 && buf[size-1] == 0) {
                *value = (CHAR16*) TAKE_PTR(buf);
                return EFI_SUCCESS;
        }

        /* Make sure a terminating NUL is available at the end */
        val = AllocatePool(size + 2);
        if (!val)
                return EFI_OUT_OF_RESOURCES;

        CopyMem(val, buf, size);
        val[size/2] = 0; /* NUL terminate */

        *value = val;
        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_int(const CHAR16 *name, UINTN *i) {
        _cleanup_freepool_ CHAR16 *val = NULL;
        EFI_STATUS err;

        err = efivar_get(name, &val);
        if (!EFI_ERROR(err) && i)
                *i = Atoi(val);

        return err;
}

EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const CHAR16 *name, CHAR8 **buffer, UINTN *size) {
        _cleanup_freepool_ CHAR8 *buf = NULL;
        UINTN l;
        EFI_STATUS err;

        l = sizeof(CHAR16 *) * EFI_MAXIMUM_VARIABLE_SIZE;
        buf = AllocatePool(l);
        if (!buf)
                return EFI_OUT_OF_RESOURCES;

        err = uefi_call_wrapper(RT->GetVariable, 5, (CHAR16*) name, (EFI_GUID *)vendor, NULL, &l, buf);
        if (!EFI_ERROR(err)) {

                if (buffer)
                        *buffer = TAKE_PTR(buf);

                if (size)
                        *size = l;
        }

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

EFI_STATUS file_read(EFI_FILE_HANDLE dir, const CHAR16 *name, UINTN off, UINTN size, CHAR8 **ret, UINTN *ret_size) {
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE handle = NULL;
        _cleanup_freepool_ CHAR8 *buf = NULL;
        EFI_STATUS err;

        err = uefi_call_wrapper(dir->Open, 5, dir, &handle, (CHAR16*) name, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return err;

        if (size == 0) {
                _cleanup_freepool_ EFI_FILE_INFO *info;

                info = LibFileInfo(handle);
                if (!info)
                        return EFI_OUT_OF_RESOURCES;

                size = info->FileSize+1;
        }

        if (off > 0) {
                err = uefi_call_wrapper(handle->SetPosition, 2, handle, off);
                if (EFI_ERROR(err))
                        return err;
        }

        buf = AllocatePool(size + 1);
        if (!buf)
                return EFI_OUT_OF_RESOURCES;

        err = uefi_call_wrapper(handle->Read, 3, handle, &size, buf);
        if (EFI_ERROR(err))
                return err;

        buf[size] = '\0';

        *ret = TAKE_PTR(buf);
        if (ret_size)
                *ret_size = size;

        return err;
}

EFI_STATUS log_oom(void) {
        Print(L"Out of memory.");
        (void) uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return EFI_OUT_OF_RESOURCES;
}
