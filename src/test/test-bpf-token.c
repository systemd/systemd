/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBBPF
#include <bpf/bpf.h>
#endif
#include <fcntl.h>
#include <sys/mount.h>

#include "fd-util.h"
#include "strv.h"
#include "tests.h"

static int intro(void) {
        int r;

        /* First, check if fsopen() and fsconfig() for bpffs is supported. */
        _cleanup_close_ int fs_fd = fsopen("bpf", FSOPEN_CLOEXEC);
        if (fs_fd < 0)
                return log_error_errno(errno, "Failed to fsopen bpffs: %m");

        FOREACH_STRING(s, "delegate_cmds", "delegate_maps", "delegate_progs", "delegate_attachs") {
                r = fsconfig(fs_fd, FSCONFIG_SET_STRING, s, "0xffffffffffffffff", /* aux = */ 0);
                if (r < 0)
                        return log_error_errno(errno, "Failed to FSCONFIG_SET_STRING (%s): %m", s);
        }

        r = fsconfig(fs_fd, FSCONFIG_CMD_CREATE, /* key = */ NULL, /* value = */ NULL, /* aux = */ 0);
        if (r < 0)
                return log_error_errno(errno, "Failed to FSCONFIG_CMD_CREATE: %m");

#if HAVE_LIBBPF && __LIBBPF_CURRENT_VERSION_GEQ(1, 5)
        /* Then, check if bpf token can be created. */
        _cleanup_close_ int bpffs_fd = open("/sys/fs/bpf", O_RDONLY);
        if (bpffs_fd < 0)
                return log_error_errno(errno, "Failed to open '/sys/fs/bpf': %m");

        _cleanup_close_ int token_fd = bpf_token_create(bpffs_fd, /* opts = */ NULL);
        if (token_fd < 0)
                return log_error_errno(errno, "Failed to create bpf token: %m");

        return 0;
#else
        return log_tests_skipped("libbpf is not supported or older than v1.5");
#endif
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
