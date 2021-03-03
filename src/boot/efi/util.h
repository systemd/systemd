/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <efilib.h>

#include "string-util-fundamental.h"

#define OFFSETOF(x,y) __builtin_offsetof(x,y)

static inline UINTN ALIGN_TO(UINTN l, UINTN ali) {
        return ((l + ali - 1) & ~(ali - 1));
}

EFI_STATUS parse_boolean(const CHAR8 *v, BOOLEAN *b);

UINT64 ticks_read(void);
UINT64 ticks_freq(void);
UINT64 time_usec(void);

EFI_STATUS efivar_set(const EFI_GUID *vendor, const CHAR16 *name, const CHAR16 *value, UINT32 flags);
EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const CHAR16 *name, const VOID *buf, UINTN size, UINT32 flags);
EFI_STATUS efivar_set_uint_string(const EFI_GUID *vendor, CHAR16 *name, UINTN i, UINT32 flags);
EFI_STATUS efivar_set_uint32_le(const EFI_GUID *vendor, CHAR16 *NAME, UINT32 value, UINT32 flags);
EFI_STATUS efivar_set_uint64_le(const EFI_GUID *vendor, CHAR16 *name, UINT64 value, UINT32 flags);
VOID efivar_set_time_usec(const EFI_GUID *vendor, CHAR16 *name, UINT64 usec);

EFI_STATUS efivar_get(const EFI_GUID *vendor, const CHAR16 *name, CHAR16 **value);
EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const CHAR16 *name, CHAR8 **buffer, UINTN *size);
EFI_STATUS efivar_get_uint_string(const EFI_GUID *vendor, const CHAR16 *name, UINTN *i);
EFI_STATUS efivar_get_uint32_le(const EFI_GUID *vendor, const CHAR16 *name, UINT32 *ret);
EFI_STATUS efivar_get_uint64_le(const EFI_GUID *vendor, const CHAR16 *name, UINT64 *ret);
EFI_STATUS efivar_get_boolean_u8(const EFI_GUID *vendor, const CHAR16 *name, BOOLEAN *ret);

CHAR8 *strchra(CHAR8 *s, CHAR8 c);
CHAR16 *stra_to_path(CHAR8 *stra);
CHAR16 *stra_to_str(CHAR8 *stra);

EFI_STATUS file_read(EFI_FILE_HANDLE dir, const CHAR16 *name, UINTN off, UINTN size, CHAR8 **content, UINTN *content_size);

static inline void FreePoolp(void *p) {
        void *q = *(void**) p;

        if (!q)
                return;

        FreePool(q);
}

#define _cleanup_freepool_ _cleanup_(FreePoolp)

static inline void FileHandleClosep(EFI_FILE_HANDLE *handle) {
        if (!*handle)
                return;

        uefi_call_wrapper((*handle)->Close, 1, *handle);
}

/*
 * Allocated random UUID, intended to be shared across tools that implement
 * the (ESP)\loader\entries\<vendor>-<revision>.conf convention and the
 * associated EFI variables.
 */
#define LOADER_GUID \
        &(const EFI_GUID) { 0x4a67b082, 0x0a4c, 0x41cf, { 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f } }
#define EFI_GLOBAL_GUID &(const EFI_GUID) EFI_GLOBAL_VARIABLE

#define UINTN_MAX (~(UINTN)0)
#define INTN_MAX ((INTN)(UINTN_MAX>>1))
#ifndef UINT32_MAX
#define UINT32_MAX ((UINT32) -1)
#endif
#ifndef UINT64_MAX
#define UINT64_MAX ((UINT64) -1)
#endif

EFI_STATUS log_oom(void);
