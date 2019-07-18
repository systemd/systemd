/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <efi.h>
#include <efilib.h>

#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))
#define OFFSETOF(x,y) __builtin_offsetof(x,y)

static inline UINTN ALIGN_TO(UINTN l, UINTN ali) {
        return ((l + ali - 1) & ~(ali - 1));
}

static inline const CHAR16 *yes_no(BOOLEAN b) {
        return b ? L"yes" : L"no";
}

EFI_STATUS parse_boolean(const CHAR8 *v, BOOLEAN *b);

UINT64 ticks_read(void);
UINT64 ticks_freq(void);
UINT64 time_usec(void);

EFI_STATUS efivar_set(const CHAR16 *name, const CHAR16 *value, BOOLEAN persistent);
EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const CHAR16 *name, const VOID *buf, UINTN size, BOOLEAN persistent);
EFI_STATUS efivar_set_int(CHAR16 *name, UINTN i, BOOLEAN persistent);
VOID efivar_set_time_usec(CHAR16 *name, UINT64 usec);

EFI_STATUS efivar_get(const CHAR16 *name, CHAR16 **value);
EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const CHAR16 *name, CHAR8 **buffer, UINTN *size);
EFI_STATUS efivar_get_int(const CHAR16 *name, UINTN *i);

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

#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _cleanup_freepool_ _cleanup_(FreePoolp)

static inline void FileHandleClosep(EFI_FILE_HANDLE *handle) {
        if (!*handle)
                return;

        uefi_call_wrapper((*handle)->Close, 1, *handle);
}

const EFI_GUID loader_guid;

#define UINTN_MAX (~(UINTN)0)
#define INTN_MAX ((INTN)(UINTN_MAX>>1))

#define TAKE_PTR(ptr)                           \
        ({                                      \
                typeof(ptr) _ptr_ = (ptr);      \
                (ptr) = NULL;                   \
                _ptr_;                          \
        })

EFI_STATUS log_oom(void);
