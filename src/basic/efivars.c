/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "macro.h"
#include "memory-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "virt.h"

#if ENABLE_EFI

/* Reads from efivarfs sometimes fail with EINTR. Retry that many times. */
#define EFI_N_RETRIES_NO_DELAY 20
#define EFI_N_RETRIES_TOTAL 25
#define EFI_RETRY_DELAY (50 * USEC_PER_MSEC)

int efi_get_variable(
                const char *variable,
                uint32_t *ret_attribute,
                void **ret_value,
                size_t *ret_size) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ void *buf = NULL;
        struct stat st;
        usec_t begin = 0; /* Unnecessary initialization to appease gcc */
        uint32_t a;
        ssize_t n;

        assert(variable);

        const char *p = strjoina("/sys/firmware/efi/efivars/", variable);

        if (!ret_value && !ret_size && !ret_attribute) {
                /* If caller is not interested in anything, just check if the variable exists and is
                 * readable. */
                if (access(p, R_OK) < 0)
                        return -errno;

                return 0;
        }

        if (DEBUG_LOGGING) {
                log_debug("Reading EFI variable %s.", p);
                begin = now(CLOCK_MONOTONIC);
        }

        fd = open(p, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return log_debug_errno(errno, "open(\"%s\") failed: %m", p);

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "fstat(\"%s\") failed: %m", p);
        if (st.st_size < 4)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "EFI variable %s is shorter than 4 bytes, refusing.", p);
        if (st.st_size > 4*1024*1024 + 4)
                return log_debug_errno(SYNTHETIC_ERRNO(E2BIG), "EFI variable %s is ridiculously large, refusing.", p);

        if (ret_value || ret_attribute) {
                /* The kernel ratelimits reads from the efivarfs because EFI is inefficient, and we'll
                 * occasionally fail with EINTR here. A slowdown is better than a failure for us, so
                 * retry a few times and eventually fail with -EBUSY.
                 *
                 * See https://github.com/torvalds/linux/blob/master/fs/efivarfs/file.c#L75
                 * and
                 * https://github.com/torvalds/linux/commit/bef3efbeb897b56867e271cdbc5f8adaacaeb9cd.
                 */
                for (unsigned try = 0;; try++) {
                        n = read(fd, &a, sizeof(a));
                        if (n >= 0)
                                break;
                        log_debug_errno(errno, "Reading from \"%s\" failed: %m", p);
                        if (errno != EINTR)
                                return -errno;
                        if (try >= EFI_N_RETRIES_TOTAL)
                                return -EBUSY;

                        if (try >= EFI_N_RETRIES_NO_DELAY)
                                (void) usleep_safe(EFI_RETRY_DELAY);
                }

                /* Unfortunately kernel reports EOF if there's an inconsistency between efivarfs var list
                 * and what's actually stored in firmware, c.f. #34304. A zero size env var is not allowed in
                 * efi and hence the variable doesn't really exist in the backing store as long as it is zero
                 * sized, and the kernel calls this "uncommitted". Hence we translate EOF back to ENOENT here,
                 * as with kernel behavior before
                 * https://github.com/torvalds/linux/commit/3fab70c165795431f00ddf9be8b84ddd07bd1f8f
                 *
                 * If the kernel changes behaviour (to flush dentries on resume), we can drop
                 * this at some point in the future. But note that the commit is 11
                 * years old at this point so we'll need to deal with the current behaviour for
                 * a long time.
                 */
                if (n == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "EFI variable %s is uncommitted", p);

                if (n != sizeof(a))
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                               "Read %zi bytes from EFI variable %s, expected %zu.",  n, p, sizeof(a));
        }

        if (ret_value) {
                buf = malloc(st.st_size - 4 + 3);
                if (!buf)
                        return -ENOMEM;

                n = read(fd, buf, (size_t) st.st_size - 4);
                if (n < 0)
                        return log_debug_errno(errno, "Failed to read value of EFI variable %s: %m", p);
                assert(n <= st.st_size - 4);

                /* Always NUL-terminate (3 bytes, to properly protect UTF-16, even if truncated in the middle
                 * of a character) */
                ((char*) buf)[n] = 0;
                ((char*) buf)[n + 1] = 0;
                ((char*) buf)[n + 2] = 0;
        } else
                /* Assume that the reported size is accurate */
                n = st.st_size - 4;

        if (DEBUG_LOGGING) {
                usec_t end = now(CLOCK_MONOTONIC);
                if (end > begin + EFI_RETRY_DELAY)
                        log_debug("Detected slow EFI variable read access on %s: %s",
                                  variable, FORMAT_TIMESPAN(end - begin, 1));
        }

        /* Note that efivarfs interestingly doesn't require ftruncate() to update an existing EFI variable
         * with a smaller value. */

        if (ret_attribute)
                *ret_attribute = a;

        if (ret_value)
                *ret_value = TAKE_PTR(buf);

        if (ret_size)
                *ret_size = n;

        return 0;
}

int efi_get_variable_string(const char *variable, char **ret) {
        _cleanup_free_ void *s = NULL;
        size_t ss = 0;
        char *x;
        int r;

        assert(variable);

        r = efi_get_variable(variable, NULL, &s, &ss);
        if (r < 0)
                return r;

        x = utf16_to_utf8(s, ss);
        if (!x)
                return -ENOMEM;

        if (ret)
                *ret = x;

        return 0;
}

int efi_get_variable_path(const char *variable, char **ret) {
        int r;

        assert(variable);

        r = efi_get_variable_string(variable, ret);
        if (r < 0)
                return r;

        if (ret)
                efi_tilt_backslashes(*ret);

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

        struct var {
                uint32_t attr;
                char buf[];
        } _packed_ * _cleanup_free_ buf = NULL;
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

        r = chattr_path(p, 0, FS_IMMUTABLE_FL, &saved_flags);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to drop FS_IMMUTABLE_FL flag from '%s', ignoring: %m", p);

        saved_flags_valid = r >= 0;

        if (size == 0) {
                if (unlink(p) < 0) {
                        r = -errno;
                        goto finish;
                }

                return 0;
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
        if (futimens(fd, /* times = */ NULL) < 0)
                log_debug_errno(errno, "Failed to update mtime/atime on %s, ignoring: %m", p);

        r = 0;

finish:
        if (saved_flags_valid) {
                int q;

                /* Restore the original flags field, just in case */
                if (fd < 0)
                        q = chattr_path(p, saved_flags, FS_IMMUTABLE_FL, NULL);
                else
                        q = chattr_fd(fd, saved_flags, FS_IMMUTABLE_FL, NULL);
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

bool is_efi_boot(void) {
        static int cache = -1;

        if (cache < 0) {
                if (detect_container() > 0)
                        cache = false;
                else {
                        cache = access("/sys/firmware/efi/", F_OK) >= 0;
                        if (!cache && errno != ENOENT)
                                log_debug_errno(errno, "Unable to test whether /sys/firmware/efi/ exists, assuming EFI not available: %m");
                }
        }

        return cache;
}

static int read_flag(const char *variable) {
        _cleanup_free_ void *v = NULL;
        uint8_t b;
        size_t s;
        int r;

        if (!is_efi_boot()) /* If this is not an EFI boot, assume the queried flags are zero */
                return 0;

        r = efi_get_variable(variable, NULL, &v, &s);
        if (r < 0)
                return r;

        if (s != 1)
                return -EINVAL;

        b = *(uint8_t *)v;
        return !!b;
}

bool is_efi_secure_boot(void) {
        static int cache = -1;
        int r;

        if (cache < 0) {
                r = read_flag(EFI_GLOBAL_VARIABLE_STR("SecureBoot"));
                if (r == -ENOENT)
                        cache = false;
                else if (r < 0)
                        log_debug_errno(r, "Error reading SecureBoot EFI variable, assuming not in SecureBoot mode: %m");
                else
                        cache = r;
        }

        return cache > 0;
}

SecureBootMode efi_get_secure_boot_mode(void) {
        static SecureBootMode cache = _SECURE_BOOT_INVALID;

        if (cache != _SECURE_BOOT_INVALID)
                return cache;

        int secure = read_flag(EFI_GLOBAL_VARIABLE_STR("SecureBoot"));
        if (secure < 0) {
                if (secure != -ENOENT)
                        log_debug_errno(secure, "Error reading SecureBoot EFI variable, assuming not in SecureBoot mode: %m");

                return (cache = SECURE_BOOT_UNSUPPORTED);
        }

        /* We can assume false for all these if they are abscent (AuditMode and
         * DeployedMode may not exist on older firmware). */
        int audit    = read_flag(EFI_GLOBAL_VARIABLE_STR("AuditMode"));
        int deployed = read_flag(EFI_GLOBAL_VARIABLE_STR("DeployedMode"));
        int setup    = read_flag(EFI_GLOBAL_VARIABLE_STR("SetupMode"));
        log_debug("Secure boot variables: SecureBoot=%d AuditMode=%d DeployedMode=%d SetupMode=%d",
                  secure, audit, deployed, setup);

        return (cache = decode_secure_boot_mode(secure, audit > 0, deployed > 0, setup > 0));
}

static int read_efi_options_variable(char **ret) {
        int r;

        /* In SecureBoot mode this is probably not what you want. As your cmdline is cryptographically signed
         * like when using Type #2 EFI Unified Kernel Images (https://uapi-group.org/specifications/specs/boot_loader_specification)
         * The user's intention is then that the cmdline should not be modified. You want to make sure that
         * the system starts up as exactly specified in the signed artifact.
         *
         * (NB: For testing purposes, we still check the $SYSTEMD_EFI_OPTIONS env var before accessing this
         * cache, even when in SecureBoot mode.) */
        if (is_efi_secure_boot()) {
                /* Let's be helpful with the returned error and check if the variable exists at all. If it
                 * does, let's return a recognizable error (EPERM), and if not ENODATA. */

                if (access(EFIVAR_PATH(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions")), F_OK) < 0)
                        return errno == ENOENT ? -ENODATA : -errno;

                return -EPERM;
        }

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions"), ret);
        if (r == -ENOENT)
                return -ENODATA;
        return r;
}

int cache_efi_options_variable(void) {
        _cleanup_free_ char *line = NULL;
        int r;

        r = read_efi_options_variable(&line);
        if (r < 0)
                return r;

        return write_string_file(EFIVAR_CACHE_PATH(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions")), line,
                                 WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755);
}

int systemd_efi_options_variable(char **ret) {
        const char *e;
        int r;

        /* Returns the contents of the variable for current boot from the cache. */

        assert(ret);

        /* For testing purposes it is sometimes useful to be able to override this */
        e = secure_getenv("SYSTEMD_EFI_OPTIONS");
        if (e)
                return strdup_to(ret, e);

        r = read_one_line_file(EFIVAR_CACHE_PATH(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions")), ret);
        if (r == -ENOENT)
                return -ENODATA;
        return r;
}

static int compare_stat_mtime(const struct stat *a, const struct stat *b) {
        return CMP(timespec_load(&a->st_mtim), timespec_load(&b->st_mtim));
}

int systemd_efi_options_efivarfs_if_newer(char **ret) {
        struct stat a = {}, b;
        int r;

        if (stat(EFIVAR_PATH(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions")), &a) < 0 && errno != ENOENT)
                return log_debug_errno(errno, "Failed to stat EFI variable SystemdOptions: %m");

        if (stat(EFIVAR_CACHE_PATH(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions")), &b) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to stat "EFIVAR_CACHE_PATH(EFI_SYSTEMD_VARIABLE_STR("SystemdOptions"))": %m");
        } else if (compare_stat_mtime(&a, &b) > 0)
                log_debug("Variable SystemdOptions in evifarfs is newer than in cache.");
        else {
                log_debug("Variable SystemdOptions in cache is up to date.");
                *ret = NULL;
                return 0;
        }

        r = read_efi_options_variable(ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to read SystemdOptions EFI variable: %m");

        return 0;
}
#endif
