/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <unistd.h>

#include "errno-util.h"
#include "log.h"
#include "ssh-util.h"
#include "string-util.h"
#include "strv.h"
#include "vsock-util.h"

int vsock_open_or_warn(int *ret) {
        int fd = RET_NERRNO(socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fd))
                log_debug_errno(fd, "AF_VSOCK is not available, ignoring: %m");
        else if (fd < 0)
                return log_error_errno(fd, "Unable to test if AF_VSOCK is available: %m");

        if (ret)
                *ret = fd;
        else
                close(fd);

        return fd >= 0;
}

int vsock_get_local_cid_or_warn(unsigned *ret) {
        int r;

        r = vsock_get_local_cid(ret);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r) || r == -EADDRNOTAVAIL) {
                if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                        log_debug_errno(r, "/dev/vsock is not available (even though AF_VSOCK is), ignoring: %m");
                if (ret)
                        *ret = 0;  /* bogus value */
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to query host's AF_VSOCK CID: %m");
        return 1;
}

int sshd_config_dump_get_authorized_keys_file(const char *dump, char **ret) {
        int r;

        assert(dump);
        assert(ret);

        /* Extracts the AuthorizedKeysFile= setting from the effective configuration dumped by "sshd -G". The
         * dump consists of one lowercased configuration key per line, followed by its arguments. Returns 0 if
         * the setting is not mentioned in the dump, > 0 if it is. Note that the returned string is empty if
         * the setting is turned off, i.e. set to "none". */

        _cleanup_strv_free_ char **lines = strv_split_newlines(dump);
        if (!lines)
                return log_oom_debug();

        STRV_FOREACH(i, lines) {
                const char *e = startswith(*i, "authorizedkeysfile");
                if (isempty(e) || !strchr(WHITESPACE, *e)) /* Not our key, or no arguments at all? */
                        continue;

                e = skip_leading_chars(e, /* bad= */ NULL);
                if (streq(e, "none")) /* Authorized keys files explicitly turned off? */
                        e = "";

                r = strdup_to(ret, e);
                if (r < 0)
                        return r;

                return 1;
        }

        *ret = NULL;
        return 0;
}
