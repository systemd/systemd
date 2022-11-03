/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#if HAVE_XENCTRL
#define __XEN_INTERFACE_VERSION__ 0x00040900
#include <xen/xen.h>
#include <xen/kexec.h>
#include <xen/sys/privcmd.h>
#endif

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "proc-cmdline.h"
#include "raw-reboot.h"
#include "reboot-util.h"
#include "string-util.h"
#include "umask-util.h"
#include "virt.h"

int update_reboot_parameter_and_warn(const char *parameter, bool keep) {
        int r;

        if (isempty(parameter)) {
                if (keep)
                        return 0;

                if (unlink("/run/systemd/reboot-param") < 0) {
                        if (errno == ENOENT)
                                return 0;

                        return log_warning_errno(errno, "Failed to unlink reboot parameter file: %m");
                }

                return 0;
        }

        RUN_WITH_UMASK(0022) {
                r = write_string_file("/run/systemd/reboot-param", parameter,
                                      WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
                if (r < 0)
                        return log_warning_errno(r, "Failed to write reboot parameter file: %m");
        }

        return 0;
}

int read_reboot_parameter(char **parameter) {
        int r;

        assert(parameter);

        r = read_one_line_file("/run/systemd/reboot-param", parameter);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to read /run/systemd/reboot-param: %m");

        return 0;
}

int reboot_with_parameter(RebootFlags flags) {
        int r;

        /* Reboots the system with a parameter that is read from /run/systemd/reboot-param. Returns 0 if
         * REBOOT_DRY_RUN was set and the actual reboot operation was hence skipped. If REBOOT_FALLBACK is
         * set and the reboot with parameter doesn't work out a fallback to classic reboot() is attempted. If
         * REBOOT_FALLBACK is not set, 0 is returned instead, which should be considered indication for the
         * caller to fall back to reboot() on its own, or somehow else deal with this. If REBOOT_LOG is
         * specified will log about what it is going to do, as well as all errors. */

        if (detect_container() == 0) {
                _cleanup_free_ char *parameter = NULL;

                r = read_one_line_file("/run/systemd/reboot-param", &parameter);
                if (r < 0 && r != -ENOENT)
                        log_full_errno(flags & REBOOT_LOG ? LOG_WARNING : LOG_DEBUG, r,
                                       "Failed to read reboot parameter file, ignoring: %m");

                if (!isempty(parameter)) {
                        log_full(flags & REBOOT_LOG ? LOG_INFO : LOG_DEBUG,
                                 "Rebooting with argument '%s'.", parameter);

                        if (flags & REBOOT_DRY_RUN)
                                return 0;

                        (void) raw_reboot(LINUX_REBOOT_CMD_RESTART2, parameter);

                        log_full_errno(flags & REBOOT_LOG ? LOG_WARNING : LOG_DEBUG, errno,
                                       "Failed to reboot with parameter, retrying without: %m");
                }
        }

        if (!(flags & REBOOT_FALLBACK))
                return 0;

        log_full(flags & REBOOT_LOG ? LOG_INFO : LOG_DEBUG, "Rebooting.");

        if (flags & REBOOT_DRY_RUN)
                return 0;

        (void) reboot(RB_AUTOBOOT);

        return log_full_errno(flags & REBOOT_LOG ? LOG_ERR : LOG_DEBUG, errno, "Failed to reboot: %m");
}

int shall_restore_state(void) {
        bool ret;
        int r;

        r = proc_cmdline_get_bool("systemd.restore_state", &ret);
        if (r < 0)
                return r;

        return r > 0 ? ret : true;
}

static int xen_kexec_loaded(void) {
#if HAVE_XENCTRL
        _cleanup_close_ int privcmd_fd = -1, buf_fd = -1;
        xen_kexec_status_t *buffer;
        size_t size;
        int r;

        if (access("/proc/xen", F_OK) < 0) {
                if (errno == ENOENT)
                        return -EOPNOTSUPP;
                return log_debug_errno(errno, "Unable to test whether /proc/xen exists: %m");
        }

        size = page_size();
        if (sizeof(xen_kexec_status_t) > size)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "page_size is too small for hypercall");

        privcmd_fd = open("/dev/xen/privcmd", O_RDWR|O_CLOEXEC);
        if (privcmd_fd < 0)
                return log_debug_errno(errno, "Cannot access /dev/xen/privcmd: %m");

        buf_fd = open("/dev/xen/hypercall", O_RDWR|O_CLOEXEC);
        if (buf_fd < 0)
                return log_debug_errno(errno, "Cannot access /dev/xen/hypercall: %m");

        buffer = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, buf_fd, 0);
        if (buffer == MAP_FAILED)
                return log_debug_errno(errno, "Cannot allocate buffer for hypercall: %m");

        *buffer = (xen_kexec_status_t) {
                .type = KEXEC_TYPE_DEFAULT,
        };

        privcmd_hypercall_t call = {
                .op = __HYPERVISOR_kexec_op,
                .arg = {
                        KEXEC_CMD_kexec_status,
                        PTR_TO_UINT64(buffer),
                },
        };

        r = RET_NERRNO(ioctl(privcmd_fd, IOCTL_PRIVCMD_HYPERCALL, &call));
        if (r < 0)
                log_debug_errno(r, "kexec_status failed: %m");

        munmap(buffer, size);

        return r;
#else
        return -EOPNOTSUPP;
#endif
}

bool kexec_loaded(void) {
       _cleanup_free_ char *s = NULL;
       int r;

       r = xen_kexec_loaded();
       if (r >= 0)
               return r;

       r = read_one_line_file("/sys/kernel/kexec_loaded", &s);
       if (r < 0) {
               if (r != -ENOENT)
                       log_debug_errno(r, "Unable to read /sys/kernel/kexec_loaded, ignoring: %m");
               return false;
       }

       return s[0] == '1';
}
