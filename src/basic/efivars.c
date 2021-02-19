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

char* efi_variable_path(sd_id128_t vendor, const char *name) {
        char *p;

        if (asprintf(&p,
                     "/sys/firmware/efi/efivars/%s-" SD_ID128_UUID_FORMAT_STR,
                     name, SD_ID128_FORMAT_VAL(vendor)) < 0)
                return NULL;

        return p;
}

static char* efi_variable_cache_path(sd_id128_t vendor, const char *name) {
        char *p;

        if (asprintf(&p,
                     "/run/systemd/efivars/%s-" SD_ID128_UUID_FORMAT_STR,
                     name, SD_ID128_FORMAT_VAL(vendor)) < 0)
                return NULL;

        return p;
}

int efi_get_variable(
                sd_id128_t vendor,
                const char *name,
                uint32_t *ret_attribute,
                void **ret_value,
                size_t *ret_size) {

        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *p = NULL;
        _cleanup_free_ void *buf = NULL;
        struct stat st;
        usec_t begin;
        uint32_t a;
        ssize_t n;

        assert(name);

        p = efi_variable_path(vendor, name);
        if (!p)
                return -ENOMEM;

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
                                (void) usleep(EFI_RETRY_DELAY);
                }

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

                /* Always NUL terminate (3 bytes, to properly protect UTF-16, even if truncated in the middle of a character) */
                ((char*) buf)[n] = 0;
                ((char*) buf)[n + 1] = 0;
                ((char*) buf)[n + 2] = 0;
        } else
                /* Assume that the reported size is accurate */
                n = st.st_size - 4;

        if (DEBUG_LOGGING) {
                char ts[FORMAT_TIMESPAN_MAX];
                usec_t end;

                end = now(CLOCK_MONOTONIC);
                if (end > begin + EFI_RETRY_DELAY)
                        log_debug("Detected slow EFI variable read access on " SD_ID128_FORMAT_STR "-%s: %s",
                                  SD_ID128_FORMAT_VAL(vendor), name, format_timespan(ts, sizeof(ts), end - begin, 1));
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

int efi_get_variable_string(sd_id128_t vendor, const char *name, char **p) {
        _cleanup_free_ void *s = NULL;
        size_t ss = 0;
        int r;
        char *x;

        r = efi_get_variable(vendor, name, NULL, &s, &ss);
        if (r < 0)
                return r;

        x = utf16_to_utf8(s, ss);
        if (!x)
                return -ENOMEM;

        *p = x;
        return 0;
}

int efi_set_variable(
                sd_id128_t vendor,
                const char *name,
                const void *value,
                size_t size) {

        struct var {
                uint32_t attr;
                char buf[];
        } _packed_ * _cleanup_free_ buf = NULL;
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        bool saved_flags_valid = false;
        unsigned saved_flags;
        int r;

        assert(name);
        assert(value || size == 0);

        p = efi_variable_path(vendor, name);
        if (!p)
                return -ENOMEM;

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

        buf->attr = EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS;
        memcpy(buf->buf, value, size);

        r = loop_write(fd, buf, sizeof(uint32_t) + size, false);
        if (r < 0)
                goto finish;

        /* For some reason efivarfs doesn't update mtime automatically. Let's do it manually then. This is
         * useful for processes that cache EFI variables to detect when changes occurred. */
        if (futimens(fd, (struct timespec[2]) {
                                { .tv_nsec = UTIME_NOW },
                                { .tv_nsec = UTIME_NOW }
                        }) < 0)
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

int efi_set_variable_string(sd_id128_t vendor, const char *name, const char *v) {
        _cleanup_free_ char16_t *u16 = NULL;

        u16 = utf8_to_utf16(v, strlen(v));
        if (!u16)
                return -ENOMEM;

        return efi_set_variable(vendor, name, u16, (char16_strlen(u16) + 1) * sizeof(char16_t));
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

static int read_flag(const char *varname) {
        _cleanup_free_ void *v = NULL;
        uint8_t b;
        size_t s;
        int r;

        if (!is_efi_boot()) /* If this is not an EFI boot, assume the queried flags are zero */
                return 0;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, varname, NULL, &v, &s);
        if (r < 0)
                return r;

        if (s != 1)
                return -EINVAL;

        b = *(uint8_t *)v;
        return !!b;
}

bool is_efi_secure_boot(void) {
        static int cache = -1;

        if (cache < 0)
                cache = read_flag("SecureBoot");

        return cache > 0;
}

bool is_efi_secure_boot_setup_mode(void) {
        static int cache = -1;

        if (cache < 0)
                cache = read_flag("SetupMode");

        return cache > 0;
}

int cache_efi_options_variable(void) {
        _cleanup_free_ char *line = NULL, *cachepath = NULL;
        int r;

        /* In SecureBoot mode this is probably not what you want. As your cmdline is cryptographically signed
         * like when using Type #2 EFI Unified Kernel Images (https://systemd.io/BOOT_LOADER_SPECIFICATION)
         * The user's intention is then that the cmdline should not be modified. You want to make sure that
         * the system starts up as exactly specified in the signed artifact.
         *
         * (NB: For testing purposes, we still check the $SYSTEMD_EFI_OPTIONS env var before accessing this
         * cache, even when in SecureBoot mode.) */
        if (is_efi_secure_boot()) {
                _cleanup_free_ char *k;

                k = efi_variable_path(EFI_VENDOR_SYSTEMD, "SystemdOptions");
                if (!k)
                        return -ENOMEM;

                /* Let's be helpful with the returned error and check if the variable exists at all. If it
                 * does, let's return a recognizable error (EPERM), and if not ENODATA. */

                if (access(k, F_OK) < 0)
                        return errno == ENOENT ? -ENODATA : -errno;

                return -EPERM;
        }

        r = efi_get_variable_string(EFI_VENDOR_SYSTEMD, "SystemdOptions", &line);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        cachepath = efi_variable_cache_path(EFI_VENDOR_SYSTEMD, "SystemdOptions");
        if (!cachepath)
                return -ENOMEM;

        return write_string_file(cachepath, line, WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755);
}

int systemd_efi_options_variable(char **line) {
        const char *e;
        _cleanup_free_ char *cachepath = NULL;
        int r;

        assert(line);

        /* For testing purposes it is sometimes useful to be able to override this */
        e = secure_getenv("SYSTEMD_EFI_OPTIONS");
        if (e) {
                char *m;

                m = strdup(e);
                if (!m)
                        return -ENOMEM;

                *line = m;
                return 0;
        }

        cachepath = efi_variable_cache_path(EFI_VENDOR_SYSTEMD, "SystemdOptions");
        if (!cachepath)
                return -ENOMEM;

        r = read_one_line_file(cachepath, line);
        if (r == -ENOENT)
                return -ENODATA;
        return r;
}
#endif
