/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chattr-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"
#include "sync-util.h"
#include "tmpfile-util.h"
#include "utf8.h"

#if ENABLE_EFI

/* Vendor GUID of the variables through which firmware keeping its variable store in a file on the ESP (see
 * "File Format For Storing EFI Variables" in the EBBR specification,
 * https://arm-software.github.io/ebbr/) hands the store over to the OS for persisting. */
#define EFI_VENDOR_VARIABLE_STORE_STR SD_ID128_MAKE_UUID_STR(b2,ac,5f,c9,92,b7,4a,cd,ae,ac,11,e8,18,c3,13,0c)
#define EFI_VARIABLE_STORE_VARIABLE_STR(name) EFI_VENDOR_VARIABLE_STR(EFI_VENDOR_VARIABLE_STORE_STR, name)

static int variable_store_flush(void) {
        _cleanup_free_ void *name_raw = NULL;
        _cleanup_free_ char *name = NULL, *esp_path = NULL, *path = NULL, *blob = NULL;
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        size_t name_size = 0, blob_size = 0;
        int r;

        /* Firmware that has no access to its EFI variable store at runtime (common on EBBR systems, where
         * the store lives in a file on the ESP the firmware cannot safely write to once the OS owns the
         * device) accepts runtime SetVariable() calls into an in-memory store only, and exports a
         * serialized copy of it through the volatile VarToFile variable. For a change to survive a reboot,
         * the OS has to write that blob into the store file — named by the RTStorageVolatile variable —
         * from which the firmware loads the variables on the next boot. The file format is specified in
         * the EBBR specification ("File Format For Storing EFI Variables"); the blob is opaque to us. */

        r = efi_get_variable(EFI_VARIABLE_STORE_VARIABLE_STR("RTStorageVolatile"), NULL, &name_raw, &name_size);
        if (r < 0) {
                /* Be strict only once the mechanism is positively identified: -ENOENT means the
                 * firmware persists variables itself, and any other lookup failure means the
                 * mechanism cannot be confirmed to be in use — either way, don't turn the variable
                 * write that just succeeded into an error over it. */
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read RTStorageVolatile EFI variable, ignoring: %m");
                return 0;
        }

        /* An ASCII file name, possibly NUL-terminated. */
        name = memdup_suffix0(name_raw, name_size);
        if (!name)
                return -ENOMEM;

        if (!filename_is_valid(name) || !ascii_is_valid(name))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "RTStorageVolatile contains an invalid file name, refusing.");

        r = find_esp_and_warn(/* root= */ NULL, /* path= */ NULL, /* unprivileged_mode= */ false,
                              &esp_path, /* ret_fd= */ NULL);
        if (r < 0)
                return r;

        path = path_join(esp_path, name);
        if (!path)
                return -ENOMEM;

        /* The store file is created by the firmware (or when the ESP is assembled); we only ever update
         * it, so that a bogus RTStorageVolatile value cannot make us place new files on the ESP. */
        if (access(path, W_OK) < 0)
                return log_debug_errno(errno,
                                       "EFI variable store file '%s' not accessible, changes will not persist: %m",
                                       path);

        /* The firmware grows VarToFile behind the kernel's back on every SetVariable() call, while
         * efivarfs only refreshes the inode size for writes going through the file system. Hence read the
         * file to EOF instead of trusting st_size the way efi_get_variable() does, which would truncate
         * the blob to the size the variable had when it was first enumerated. */
        r = read_full_file(EFIVAR_PATH(EFI_VARIABLE_STORE_VARIABLE_STR("VarToFile")), &blob, &blob_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to read VarToFile EFI variable: %m");
        if (blob_size < sizeof(uint32_t))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "VarToFile EFI variable is too short, refusing.");

        /* Replace the store file atomically so that a crash in the middle cannot corrupt it. */
        r = tempfn_random(path, NULL, &t);
        if (r < 0)
                return r;

        fd = open(t, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to create '%s': %m", t);

        /* Skip the 4 bytes of variable attributes that efivarfs prepends. */
        r = loop_write(fd, (uint8_t*) blob + sizeof(uint32_t), blob_size - sizeof(uint32_t));
        if (r < 0)
                return log_debug_errno(r, "Failed to write '%s': %m", t);

        r = fsync_full(fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to sync '%s': %m", t);

        if (rename(t, path) < 0)
                return log_debug_errno(errno, "Failed to rename '%s' to '%s': %m", t, path);

        t = mfree(t); /* Renamed away, nothing to unlink anymore. */

        (void) fsync_parent_at(AT_FDCWD, path);
        return 0;
}

static int efi_variable_store_flush(void) {
        int r;

        r = variable_store_flush();
        if (r == -ENOENT)
                /* Never fail with -ENOENT: efi_set_variable() returns that from the removal path when
                 * the variable to remove didn't exist in the first place, and callers rightfully treat
                 * that as success — while a removal that could not be flushed would resurface on the
                 * next boot and hence must be reported. */
                return -ENOMEDIUM;

        return r;
}

static int efi_verify_variable(const char *variable, uint32_t attr, const void *value, size_t size) {
        _cleanup_free_ void *buf = NULL;
        size_t n;
        uint32_t a;
        int r;

        assert(variable);
        assert(value || size == 0);

        r = efi_get_variable(variable, &a, &buf, &n);
        if (r < 0)
                return r;

        return a == attr && memcmp_nn(buf, n, value, size) == 0;
}

int efi_set_variable(const char *variable, const void *value, size_t size) {
        static const uint32_t attr = EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS;

        _cleanup_free_ struct var {
                uint32_t attr;
                char buf[];
        } _packed_ *buf = NULL;
        _cleanup_close_ int fd = -EBADF;
        bool saved_flags_valid = false;
        unsigned saved_flags;
        int r;

        assert(variable);
        assert(value || size == 0);

        /* size 0 means removal, empty variable would not be enough for that */
        if (size > 0 && efi_verify_variable(variable, attr, value, size) > 0) {
                log_debug("Variable '%s' is already in wanted state, skipping write.", variable);
                return 0;
        }

        const char *p = strjoina("/sys/firmware/efi/efivars/", variable);

        /* Newer efivarfs protects variables that are not in an allow list with FS_IMMUTABLE_FL by default,
         * to protect them for accidental removal and modification. We are not changing these variables
         * accidentally however, hence let's unset the bit first. */

        r = chattr_full(AT_FDCWD, p,
                        /* value= */ 0,
                        /* mask= */ FS_IMMUTABLE_FL,
                        /* ret_previous= */ &saved_flags,
                        /* ret_final= */ NULL,
                        /* flags= */ 0);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to drop FS_IMMUTABLE_FL flag from '%s', ignoring: %m", p);

        saved_flags_valid = r >= 0;

        if (size == 0) {
                if (unlink(p) < 0) {
                        r = -errno;
                        goto finish;
                }

                return efi_variable_store_flush();
        }

        fd = open(p, O_WRONLY|O_CREAT|O_NOCTTY|O_CLOEXEC, 0644);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }

        buf = malloc(sizeof(uint32_t) + size);
        if (!buf) {
                r = -ENOMEM;
                goto finish;
        }

        buf->attr = attr;
        memcpy(buf->buf, value, size);

        r = loop_write(fd, buf, sizeof(uint32_t) + size);
        if (r < 0)
                goto finish;

        /* For some reason efivarfs doesn't update mtime automatically. Let's do it manually then. This is
         * useful for processes that cache EFI variables to detect when changes occurred. */
        if (futimens(fd, /* times= */ NULL) < 0)
                log_debug_errno(errno, "Failed to update mtime/atime on %s, ignoring: %m", p);

        r = efi_variable_store_flush();

finish:
        if (saved_flags_valid) {
                int q;

                /* Restore the original flags field, just in case */
                if (fd < 0)
                        q = chattr_path(p, saved_flags, FS_IMMUTABLE_FL);
                else
                        q = chattr_fd(fd, saved_flags, FS_IMMUTABLE_FL);
                if (q < 0)
                        log_debug_errno(q, "Failed to restore FS_IMMUTABLE_FL on '%s', ignoring: %m", p);
        }

        return r;
}

int efi_set_variable_string(const char *variable, const char *value) {
        _cleanup_free_ char16_t *u16 = NULL;

        u16 = utf8_to_utf16(value, SIZE_MAX);
        if (!u16)
                return -ENOMEM;

        return efi_set_variable(variable, u16, (char16_strlen(u16) + 1) * sizeof(char16_t));
}

#endif
