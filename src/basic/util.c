/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "alloc-util.h"
#include "build.h"
#include "dirent-util.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "util.h"
#include "virt.h"

int saved_argc = 0;
char **saved_argv = NULL;
static int saved_in_initrd = -1;

bool kexec_loaded(void) {
       _cleanup_free_ char *s = NULL;

       if (read_one_line_file("/sys/kernel/kexec_loaded", &s) < 0)
               return false;

       return s[0] == '1';
}

int prot_from_flags(int flags) {

        switch (flags & O_ACCMODE) {

        case O_RDONLY:
                return PROT_READ;

        case O_WRONLY:
                return PROT_WRITE;

        case O_RDWR:
                return PROT_READ|PROT_WRITE;

        default:
                return -EINVAL;
        }
}

bool in_initrd(void) {
        int r;
        const char *e;
        bool lenient = false;

        if (saved_in_initrd >= 0)
                return saved_in_initrd;

        /* We have two checks here:
         *
         * 1. the flag file /etc/initrd-release must exist
         * 2. the root file system must be a memory file system
         *
         * The second check is extra paranoia, since misdetecting an
         * initrd can have bad consequences due the initrd
         * emptying when transititioning to the main systemd.
         *
         * If env var $SYSTEMD_IN_INITRD is not set or set to "auto",
         * both checks are used. If it's set to "lenient", only check
         * 1 is used. If set to a boolean value, then the boolean
         * value is returned.
         */

        e = secure_getenv("SYSTEMD_IN_INITRD");
        if (e) {
                if (streq(e, "lenient"))
                        lenient = true;
                else if (!streq(e, "auto")) {
                        r = parse_boolean(e);
                        if (r >= 0) {
                                saved_in_initrd = r > 0;
                                return saved_in_initrd;
                        }
                        log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");
                }
        }

        if (!lenient) {
                r = path_is_temporary_fs("/");
                if (r < 0)
                        log_debug_errno(r, "Couldn't determine if / is a temporary file system: %m");

                saved_in_initrd = r > 0;
        }

        r = access("/etc/initrd-release", F_OK);
        if (r >= 0) {
                if (saved_in_initrd == 0)
                        log_debug("/etc/initrd-release exists, but it's not an initrd.");
                else
                        saved_in_initrd = 1;
        } else {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to test if /etc/initrd-release exists: %m");
                saved_in_initrd = 0;
        }

        return saved_in_initrd;
}

void in_initrd_force(bool value) {
        saved_in_initrd = value;
}

int on_ac_power(void) {
        bool found_offline = false, found_online = false;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;

        d = opendir("/sys/class/power_supply");
        if (!d)
                return errno == ENOENT ? true : -errno;

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_close_ int device_fd = -1;
                _cleanup_free_ char *contents = NULL;
                unsigned v;

                device_fd = openat(dirfd(d), de->d_name, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
                if (device_fd < 0) {
                        if (IN_SET(errno, ENOENT, ENOTDIR))
                                continue;

                        return -errno;
                }

                r = read_virtual_file_at(device_fd, "type", SIZE_MAX, &contents, NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                delete_trailing_chars(contents, NEWLINE);

                /* We assume every power source is AC, except for batteries. See
                 * https://github.com/torvalds/linux/blob/4eef766b7d4d88f0b984781bc1bcb574a6eafdc7/include/linux/power_supply.h#L176
                 * for defined power source types. Also see:
                 * https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-power */
                if (streq(contents, "Battery"))
                        continue;

                contents = mfree(contents);

                r = read_virtual_file_at(device_fd, "online", SIZE_MAX, &contents, NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                delete_trailing_chars(contents, NEWLINE);

                r = safe_atou(contents, &v);
                if (r < 0)
                        return r;
                if (v > 0) /* At least 1 and 2 are defined as different types of 'online' */
                        found_online = true;
                else
                        found_offline = true;
        }

        return found_online || !found_offline;
}

int container_get_leader(const char *machine, pid_t *pid) {
        _cleanup_free_ char *s = NULL, *class = NULL;
        const char *p;
        pid_t leader;
        int r;

        assert(machine);
        assert(pid);

        if (streq(machine, ".host")) {
                *pid = 1;
                return 0;
        }

        if (!hostname_is_valid(machine, 0))
                return -EINVAL;

        p = strjoina("/run/systemd/machines/", machine);
        r = parse_env_file(NULL, p,
                           "LEADER", &s,
                           "CLASS", &class);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!s)
                return -EIO;

        if (!streq_ptr(class, "container"))
                return -EIO;

        r = parse_pid(s, &leader);
        if (r < 0)
                return r;
        if (leader <= 1)
                return -EIO;

        *pid = leader;
        return 0;
}

int version(void) {
        printf("systemd " STRINGIFY(PROJECT_VERSION) " (" GIT_VERSION ")\n%s\n",
               systemd_features);
        return 0;
}

/* Turn off core dumps but only if we're running outside of a container. */
void disable_coredumps(void) {
        int r;

        if (detect_container() > 0)
                return;

        r = write_string_file("/proc/sys/kernel/core_pattern", "|/bin/false", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_debug_errno(r, "Failed to turn off coredumps, ignoring: %m");
}
