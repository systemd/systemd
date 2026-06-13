/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <threads.h>

#include "sd-hwdb.h"

#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "vsock-util.h"

static int smbios_get_modalias(char **ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *modalias = NULL;
        r = read_virtual_file("/sys/devices/virtual/dmi/id/modalias", SIZE_MAX, &modalias, /* ret_size= */ NULL);
        if (r < 0)
                return r;

        truncate_nl(modalias);

        *ret = TAKE_PTR(modalias);
        return 0;
}

static int smbios_get_accepts_any(void) {
        static thread_local int accepts_any = -1;
        int r;

        if (accepts_any >= 0)
                return accepts_any;

        _cleanup_free_ char *modalias = NULL;
        r = smbios_get_modalias(&modalias);
        if (r == -ENOENT)
                return (accepts_any = false);
        if (r < 0)
                return log_debug_errno(r, "Failed to read DMI modalias: %m");

        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        r = sd_hwdb_new(&hwdb);
        if (r < 0)
                return log_debug_errno(r, "Failed to open hwdb: %m");

        const char *value;
        r = sd_hwdb_get(hwdb, modalias, "VSOCK_ACCEPT_VMADDR_CID_ANY", &value);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to get VSOCK_ACCEPT_VMADDR_CID_ANY: %m");
                return (accepts_any = false);
        }
        log_debug("VSOCK_ACCEPT_VMADDR_CID_ANY: %s", value);

        r = parse_boolean(value);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse VSOCK_ACCEPT_VMADDR_CID_ANY: %m");
                return (accepts_any = false);
        }

        return (accepts_any = r);
}

int vsock_get_local_cid(unsigned *ret) {
        _cleanup_close_ int vsock_fd = -EBADF;

        vsock_fd = open("/dev/vsock", O_RDONLY|O_CLOEXEC);
        if (vsock_fd < 0)
                return log_debug_errno(errno, "Failed to open %s: %m", "/dev/vsock");

        unsigned tmp;
        if (ioctl(vsock_fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &tmp) < 0)
                return log_debug_errno(errno, "Failed to query local AF_VSOCK CID: %m");
        log_debug("Local AF_VSOCK CID: %u", tmp);

        /* If ret == NULL, we just want to check if AF_VSOCK is available, so accept any
         * address. Otherwise, filter out special addresses that cannot be used to identify
         * _this_ machine from the outside. */
        if (ret &&
            (IN_SET(tmp, VMADDR_CID_LOCAL, VMADDR_CID_HOST) ||
             (tmp == VMADDR_CID_ANY && smbios_get_accepts_any() <= 0)))
                return log_debug_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                       "IOCTL_VM_SOCKETS_GET_LOCAL_CID returned special value (%u), ignoring.", tmp);

        if (ret)
                *ret = tmp;
        return 0;
}
