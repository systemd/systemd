/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <efilib.h>

#include "string-util-fundamental.h"

/* This TPM PCR is where most Linux infrastructure extends the kernel command line into, and so do we. We also extend
 * any passed credentials here. */
#define TPM_PCR_INDEX_KERNEL_PARAMETERS 8

/* This TPM PCR is where most Linux infrastructure extends the initrd binary images into, and so do we. */
#define TPM_PCR_INDEX_INITRD 4

#define OFFSETOF(x,y) __builtin_offsetof(x,y)

#define UINTN_MAX (~(UINTN)0)
#define INTN_MAX ((INTN)(UINTN_MAX>>1))
#ifndef UINT32_MAX
#define UINT32_MAX ((UINT32) -1)
#endif
#ifndef UINT64_MAX
#define UINT64_MAX ((UINT64) -1)
#endif

#define assert_alloc_ret(p)     \
        ({                      \
                void *_p = (p); \
                assert(_p);     \
                _p;             \
        })

#define xnew_alloc(type, n, alloc)                                           \
        ({                                                                   \
                UINTN _alloc_size;                                           \
                if (__builtin_mul_overflow(sizeof(type), (n), &_alloc_size)) \
                        assert_not_reached();                                \
                (type *) alloc(_alloc_size);                                 \
        })

#define xallocate_pool(size) assert_alloc_ret(AllocatePool(size))
#define xallocate_zero_pool(size) assert_alloc_ret(AllocateZeroPool(size))
#define xreallocate_pool(p, old_size, new_size) assert_alloc_ret(ReallocatePool((p), (old_size), (new_size)))
#define xpool_print(fmt, ...) ((CHAR16 *) assert_alloc_ret(PoolPrint((fmt), ##__VA_ARGS__)))
#define xstrdup(str) ((CHAR16 *) assert_alloc_ret(StrDuplicate(str)))
#define xnew(type, n) xnew_alloc(type, (n), xallocate_pool)
#define xnew0(type, n) xnew_alloc(type, (n), xallocate_zero_pool)

EFI_STATUS parse_boolean(const CHAR8 *v, BOOLEAN *b);

UINT64 ticks_read(void);
UINT64 ticks_freq(void);
UINT64 time_usec(void);

EFI_STATUS efivar_set(const EFI_GUID *vendor, const CHAR16 *name, const CHAR16 *value, UINT32 flags);
EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const CHAR16 *name, const void *buf, UINTN size, UINT32 flags);
EFI_STATUS efivar_set_uint_string(const EFI_GUID *vendor, const CHAR16 *name, UINTN i, UINT32 flags);
EFI_STATUS efivar_set_uint32_le(const EFI_GUID *vendor, const CHAR16 *NAME, UINT32 value, UINT32 flags);
EFI_STATUS efivar_set_uint64_le(const EFI_GUID *vendor, const CHAR16 *name, UINT64 value, UINT32 flags);
void efivar_set_time_usec(const EFI_GUID *vendor, const CHAR16 *name, UINT64 usec);

EFI_STATUS efivar_get(const EFI_GUID *vendor, const CHAR16 *name, CHAR16 **value);
EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const CHAR16 *name, CHAR8 **buffer, UINTN *size);
EFI_STATUS efivar_get_uint_string(const EFI_GUID *vendor, const CHAR16 *name, UINTN *i);
EFI_STATUS efivar_get_uint32_le(const EFI_GUID *vendor, const CHAR16 *name, UINT32 *ret);
EFI_STATUS efivar_get_uint64_le(const EFI_GUID *vendor, const CHAR16 *name, UINT64 *ret);
EFI_STATUS efivar_get_boolean_u8(const EFI_GUID *vendor, const CHAR16 *name, BOOLEAN *ret);

CHAR8 *strchra(const CHAR8 *s, CHAR8 c);
CHAR16 *xstra_to_path(const CHAR8 *stra);
CHAR16 *xstra_to_str(const CHAR8 *stra);

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

        (*handle)->Close(*handle);
}

/*
 * Allocated random UUID, intended to be shared across tools that implement
 * the (ESP)\loader\entries\<vendor>-<revision>.conf convention and the
 * associated EFI variables.
 */
#define LOADER_GUID \
        &(const EFI_GUID) { 0x4a67b082, 0x0a4c, 0x41cf, { 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f } }
#define EFI_GLOBAL_GUID &(const EFI_GUID) EFI_GLOBAL_VARIABLE

void log_error_stall(const CHAR16 *fmt, ...);
EFI_STATUS log_oom(void);

/* This works just like log_error_errno() from userspace, but requires you
 * to provide err a second time if you want to use %r in the message! */
#define log_error_status_stall(err, fmt, ...) \
        ({ \
                log_error_stall(fmt, ##__VA_ARGS__); \
                err; \
        })

void *memmem_safe(const void *haystack, UINTN haystack_len, const void *needle, UINTN needle_len);

static inline void *mempmem_safe(const void *haystack, UINTN haystack_len, const void *needle, UINTN needle_len) {
        CHAR8 *p = memmem_safe(haystack, haystack_len, needle, needle_len);
        return p ? p + needle_len : NULL;
}

void print_at(UINTN x, UINTN y, UINTN attr, const CHAR16 *str);
void clear_screen(UINTN attr);

typedef INTN (*compare_pointer_func_t)(const void *a, const void *b);
void sort_pointer_array(void **array, UINTN n_members, compare_pointer_func_t compare);

EFI_STATUS get_file_info_harder(EFI_FILE_HANDLE handle, EFI_FILE_INFO **ret, UINTN *ret_size);

EFI_STATUS readdir_harder(EFI_FILE_HANDLE handle, EFI_FILE_INFO **buffer, UINTN *buffer_size);

UINTN strnlena(const CHAR8 *p, UINTN maxlen);
CHAR8 *xstrndup8(const CHAR8 *p, UINTN sz);
INTN strncasecmpa(const CHAR8 *a, const CHAR8 *b, UINTN maxlen);
static inline BOOLEAN strncaseeqa(const CHAR8 *a, const CHAR8 *b, UINTN maxlen) {
        return strncasecmpa(a, b, maxlen) == 0;
}

BOOLEAN is_ascii(const CHAR16 *f);

CHAR16 **strv_free(CHAR16 **l);

static inline void strv_freep(CHAR16 ***p) {
        strv_free(*p);
}

EFI_STATUS open_directory(EFI_FILE_HANDLE root_dir, const CHAR16 *path, EFI_FILE_HANDLE *ret);

/* Conversion between EFI_PHYSICAL_ADDRESS and pointers is not obvious. The former is always 64bit, even on
 * 32bit archs. And gcc complains if we cast a pointer to an integer of a different size. Hence let's do the
 * conversion indirectly: first into UINTN (which is defined by UEFI to have the same size as a pointer), and
 * then extended to EFI_PHYSICAL_ADDRESS. */
static inline EFI_PHYSICAL_ADDRESS POINTER_TO_PHYSICAL_ADDRESS(const void *p) {
        return (EFI_PHYSICAL_ADDRESS) (UINTN) p;
}

static inline void *PHYSICAL_ADDRESS_TO_POINTER(EFI_PHYSICAL_ADDRESS addr) {
#if __SIZEOF_POINTER__ == 4
        /* On 32bit systems the address might not be convertible (as pointers are 32bit but
         * EFI_PHYSICAL_ADDRESS 64bit) */
        assert(addr <= UINT32_MAX);
#elif __SIZEOF_POINTER__ != 8
        #error "Unexpected pointer size"
#endif

        return (void*) (UINTN) addr;
}

UINT64 get_os_indications_supported(void);
