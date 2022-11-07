/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "alloc-util.h"
#include "build.h"
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

        if (saved_in_initrd >= 0)
                return saved_in_initrd;

        /* If /etc/initrd-release exists, we're in an initrd.
         * This can be overridden by setting SYSTEMD_IN_INITRD=0|1.
         */

        r = getenv_bool_secure("SYSTEMD_IN_INITRD");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: %m");

        if (r >= 0)
                saved_in_initrd = r > 0;
        else
                saved_in_initrd = access("/etc/initrd-release", F_OK) >= 0;

        return saved_in_initrd;
}

void in_initrd_force(bool value) {
        saved_in_initrd = value;
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
