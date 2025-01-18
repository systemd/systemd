/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "efi-string.h"
#include "memory-util-fundamental.h"
#include "string-util-fundamental.h"

#if SD_BOOT

#include "log.h"
#include "proto/file-io.h"

/* This is provided by the linker. */
extern uint8_t __executable_start[];

static inline void free(void *p) {
        if (!p)
                return;

        /* Debugging an invalid free requires trace logging to find the call site or a debugger attached. For
         * release builds it is not worth the bother to even warn when we cannot even print a call stack. */
#ifdef EFI_DEBUG
        assert_se(BS->FreePool(p) == EFI_SUCCESS);
#else
        (void) BS->FreePool(p);
#endif
}

static inline void freep(void *p) {
        free(*(void **) p);
}

#define _cleanup_free_ _cleanup_(freep)

_malloc_ _alloc_(1) _returns_nonnull_ _warn_unused_result_
void *xmalloc(size_t size);

_malloc_ _alloc_(1) _returns_nonnull_ _warn_unused_result_
static inline void *xcalloc(size_t size) {
        void *t = xmalloc(size);
        memzero(t, size);
        return t;
}

_malloc_ _alloc_(1, 2) _returns_nonnull_ _warn_unused_result_
static inline void *xcalloc_multiply(size_t n, size_t size) {
        assert_se(MUL_ASSIGN_SAFE(&size, n));
        return xcalloc(size);
}

_malloc_ _alloc_(1, 2) _returns_nonnull_ _warn_unused_result_
static inline void *xmalloc_multiply(size_t n, size_t size) {
        assert_se(MUL_ASSIGN_SAFE(&size, n));
        return xmalloc(size);
}

/* Use malloc attribute as this never returns p like userspace realloc. */
_malloc_ _alloc_(3) _returns_nonnull_ _warn_unused_result_
static inline void *xrealloc(void *p, size_t old_size, size_t new_size) {
        void *t = xmalloc(new_size);
        new_size = MIN(old_size, new_size);
        if (new_size > 0)
                memcpy(t, p, new_size);
        free(p);
        return t;
}

_malloc_ _alloc_(2) _returns_nonnull_ _warn_unused_result_
static inline void* xmemdup(const void *p, size_t l) {
        return memcpy(xmalloc(l), p, l);
}

#define xnew(type, n) ((type *) xmalloc_multiply((n), sizeof(type)))
#define xnew0(type, n) ((type *) xcalloc_multiply((n), sizeof(type)))

bool free_and_xstrdup16(char16_t **p, const char16_t *s);

typedef struct {
        EFI_PHYSICAL_ADDRESS addr;
        size_t n_pages;
} Pages;

static inline void cleanup_pages(Pages *p) {
        if (p->n_pages == 0)
                return;
#ifdef EFI_DEBUG
        assert_se(BS->FreePages(p->addr, p->n_pages) == EFI_SUCCESS);
#else
        (void) BS->FreePages(p->addr, p->n_pages);
#endif
}

#define _cleanup_pages_ _cleanup_(cleanup_pages)

static inline Pages xmalloc_pages(
                EFI_ALLOCATE_TYPE type, EFI_MEMORY_TYPE memory_type, size_t n_pages, EFI_PHYSICAL_ADDRESS addr) {
        assert_se(BS->AllocatePages(type, memory_type, n_pages, &addr) == EFI_SUCCESS);
        return (Pages) {
                .addr = addr,
                .n_pages = n_pages,
        };
}

static inline Pages xmalloc_initrd_pages(size_t n_pages) {
        /* The original native x86 boot protocol of the Linux kernel was not 64bit safe, hence we allocate
         * memory for the initrds below the 4G boundary on x86, since we don't know early enough which
         * protocol we'll use to ultimately boot the kernel. This restriction is somewhat obsolete, since
         * these days we generally prefer the kernel's newer EFI entrypoint instead, which has no such
         * limitations. On other architectures we do not bother with any restriction on this, in particular
         * as some of them don't even have RAM mapped to such low addresses. */

#if defined(__i386__) || defined(__x86_64__)
        return xmalloc_pages(
                        AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(n_pages),
                        UINT32_MAX /* Below 4G boundary. */);
#else
        return xmalloc_pages(
                        AllocateAnyPages,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(n_pages),
                        0 /* Ignored. */);
#endif
}

void convert_efi_path(char16_t *path);
char16_t *xstr8_to_path(const char *stra);
char16_t *mangle_stub_cmdline(char16_t *cmdline);

EFI_STATUS chunked_read(EFI_FILE *file, size_t *size, void *buf);
EFI_STATUS file_read(EFI_FILE *dir, const char16_t *name, uint64_t offset, size_t size, char **content, size_t *content_size);
EFI_STATUS file_handle_read(EFI_FILE *handle, uint64_t offset, size_t size, char **ret, size_t *ret_size);

static inline void file_closep(EFI_FILE **handle) {
        if (!*handle)
                return;

        (*handle)->Close(*handle);
}

#define _cleanup_file_close_ _cleanup_(file_closep)

static inline void unload_imagep(EFI_HANDLE *image) {
        if (*image)
                (void) BS->UnloadImage(*image);
}

/* Note that GUID is evaluated multiple times! */
#define GUID_FORMAT_STR "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"
#define GUID_FORMAT_VAL(g) (g).Data1, (g).Data2, (g).Data3, (g).Data4[0], (g).Data4[1], \
        (g).Data4[2], (g).Data4[3], (g).Data4[4], (g).Data4[5], (g).Data4[6], (g).Data4[7]

void print_at(size_t x, size_t y, size_t attr, const char16_t *str);
void clear_screen(size_t attr);

typedef int (*compare_pointer_func_t)(const void *a, const void *b);
void sort_pointer_array(void **array, size_t n_members, compare_pointer_func_t compare);

EFI_STATUS get_file_info(EFI_FILE *handle, EFI_FILE_INFO **ret, size_t *ret_size);
EFI_STATUS readdir(EFI_FILE *handle, EFI_FILE_INFO **buffer, size_t *buffer_size);

bool is_ascii(const char16_t *f);

char16_t **strv_free(char16_t **l);

static inline void strv_freep(char16_t ***p) {
        strv_free(*p);
}

#define _cleanup_strv_free_ _cleanup_(strv_freep)

EFI_STATUS open_directory(EFI_FILE *root_dir, const char16_t *path, EFI_FILE **ret);

/* Conversion between EFI_PHYSICAL_ADDRESS and pointers is not obvious. The former is always 64-bit, even on
 * 32-bit archs. And gcc complains if we cast a pointer to an integer of a different size. Hence let's do the
 * conversion indirectly: first into uintptr_t and then extended to EFI_PHYSICAL_ADDRESS. */
static inline EFI_PHYSICAL_ADDRESS POINTER_TO_PHYSICAL_ADDRESS(const void *p) {
        return (EFI_PHYSICAL_ADDRESS) (uintptr_t) p;
}

static inline void *PHYSICAL_ADDRESS_TO_POINTER(EFI_PHYSICAL_ADDRESS addr) {
        /* On 32-bit systems the address might not be convertible (as pointers are 32-bit but
         * EFI_PHYSICAL_ADDRESS 64-bit) */
        assert(addr <= UINTPTR_MAX);
        return (void *) (uintptr_t) addr;
}

/* If EFI_DEBUG, print our name and version and also report the address of the image base so a debugger can
 * be attached. See debug-sd-boot.sh for how this can be done. */
void notify_debugger(const char *identity, bool wait);

/* On x86 the compiler assumes a different incoming stack alignment than what we get.
 * This will cause long long variables to be misaligned when building with
 * '-mlong-double' (for correct struct layouts). Normally, the compiler realigns the
 * stack itself on entry, but we have to do this ourselves here as the compiler does
 * not know that this is our entry point. */
#ifdef __i386__
#  define _realign_stack_ __attribute__((force_align_arg_pointer))
#else
#  define _realign_stack_
#endif

#define DEFINE_EFI_MAIN_FUNCTION(func, identity, wait_for_debugger)                    \
        EFI_SYSTEM_TABLE *ST;                                                          \
        EFI_BOOT_SERVICES *BS;                                                         \
        EFI_RUNTIME_SERVICES *RT;                                                      \
        _realign_stack_                                                                \
        EFIAPI EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table);  \
        EFIAPI EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table) { \
                ST = system_table;                                                     \
                BS = system_table->BootServices;                                       \
                RT = system_table->RuntimeServices;                                    \
                __stack_chk_guard_init();                                              \
                notify_debugger((identity), (wait_for_debugger));                      \
                EFI_STATUS err = func(image);                                          \
                log_wait();                                                            \
                return err;                                                            \
        }

#if defined(__i386__) || defined(__x86_64__)
void beep(unsigned beep_count);
#else
static inline void beep(unsigned beep_count) {}
#endif

EFI_STATUS open_volume(EFI_HANDLE device, EFI_FILE **ret_file);

static inline bool efi_guid_equal(const EFI_GUID *a, const EFI_GUID *b) {
        return memcmp(a, b, sizeof(EFI_GUID)) == 0;
}

void *find_configuration_table(const EFI_GUID *guid);

char16_t *get_extra_dir(const EFI_DEVICE_PATH *file_path);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define be32toh(x) __builtin_bswap32(x)
#else
#  error "Unexpected byte order in EFI mode?"
#endif

#define bswap_16(x) __builtin_bswap16(x)
#define bswap_32(x) __builtin_bswap32(x)

#else

#include "alloc-util.h"

#define xnew0(type, n) ASSERT_PTR(new0(type, n))

#endif
