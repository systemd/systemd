/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "alloc-util.h"
#include "bpf-trusted-exec.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "parse-util.h"

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/trusted-exec/trusted-exec-skel.h"

/* The .bss map value must cover the entire .bss section. This static assert catches
 * .bss layout changes (e.g. new globals added to the BPF program) at compile time. */
assert_cc(sizeof(*((struct trusted_exec_bpf *)0)->bss) == sizeof(uint32_t));

static bool dm_verity_require_signatures(void) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = read_one_line_file("/sys/module/dm_verity/parameters/require_signatures", &val);
        if (r == -ENOENT) {
                log_debug("bpf-trusted-exec: dm-verity module not loaded, require_signatures not available.");
                return false;
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-trusted-exec: Failed to read dm-verity require_signatures: %m");
                return false;
        }

        return parse_boolean(val) > 0;
}

static int get_root_s_dev(uint32_t *ret) {
        struct stat st;

        assert(ret);

        if (stat("/", &st) < 0)
                return log_error_errno(errno, "bpf-trusted-exec: Failed to stat root filesystem: %m");

        *ret = STAT_DEV_TO_KERNEL(st.st_dev);
        return 0;
}

static int prepare_trusted_exec_bpf(struct trusted_exec_bpf **ret) {
        _cleanup_(trusted_exec_bpf_freep) struct trusted_exec_bpf *obj = NULL;
        int r;

        assert(ret);

        obj = trusted_exec_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-trusted-exec: Failed to open BPF object: %m");

        r = trusted_exec_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to load BPF object: %m");

        *ret = TAKE_PTR(obj);
        return 0;
}

bool bpf_trusted_exec_supported(void) {
        _cleanup_(trusted_exec_bpf_freep) struct trusted_exec_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;
        if (dlopen_bpf_full(LOG_WARNING) < 0)
                return (supported = false);

        r = lsm_supported("bpf");
        if (r == -ENOPKG) {
                log_debug_errno(r, "bpf-trusted-exec: securityfs not mounted, BPF LSM not available.");
                return (supported = false);
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-trusted-exec: Can't determine whether the BPF LSM module is used: %m");
                return (supported = false);
        }
        if (r == 0) {
                log_info("bpf-trusted-exec: BPF LSM hook not enabled in the kernel, not supported.");
                return (supported = false);
        }

        r = prepare_trusted_exec_bpf(&obj);
        if (r < 0)
                return (supported = false);

        if (!bpf_can_link_lsm_program(obj->progs.trusted_exec_bprm_check)) {
                log_warning("bpf-trusted-exec: Failed to link program; assuming BPF LSM is not available.");
                return (supported = false);
        }

        return (supported = true);
}

int bpf_trusted_exec_setup(Manager *m) {
        _cleanup_(trusted_exec_bpf_freep) struct trusted_exec_bpf *obj = NULL;
        int r;

        assert(m);

        /* Fresh setup: verify BPF LSM is available */
        if (!bpf_trusted_exec_supported())
                return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                         "bpf-trusted-exec: BPF LSM is not available.");

        /* Require dm-verity signature enforcement */
        if (!dm_verity_require_signatures())
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                       "bpf-trusted-exec: dm-verity require_signatures is not enabled. "
                                       "TrustedExec= requires the kernel to enforce dm-verity signatures. "
                                       "Set dm_verity.require_signatures=1 on the kernel command line.");

        r = prepare_trusted_exec_bpf(&obj);
        if (r < 0)
                return r;

        /* If we haven't switched root yet, we're still on the initramfs. Allow
         * execution from the initramfs filesystem by recording its s_dev. After
         * switch_root, PID1 re-execs and this code runs again with
         * m->switching_root == true — at that point we leave initramfs_s_dev at
         * 0 (its default), closing the initramfs trust window. */
        if (!m->switching_root) {
                uint32_t root_dev;

                r = get_root_s_dev(&root_dev);
                if (r < 0)
                        return r;

                obj->bss->initramfs_s_dev = root_dev;
                log_info("bpf-trusted-exec: Initramfs trusted (s_dev=%u:%u)",
                         root_dev >> 20, root_dev & 0xFFFFF);
        }

        r = trusted_exec_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-trusted-exec: Failed to attach BPF programs: %m");

        log_info("bpf-trusted-exec: LSM BPF programs attached");

        m->trusted_exec = TAKE_PTR(obj);
        return 0;
}

void bpf_trusted_exec_destroy(struct trusted_exec_bpf *prog) {
        trusted_exec_bpf__destroy(prog);
}

#else /* ! BPF_FRAMEWORK */

bool bpf_trusted_exec_supported(void) {
        return false;
}

int bpf_trusted_exec_setup(Manager *m) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-trusted-exec: BPF framework is not supported.");
}

void bpf_trusted_exec_destroy(struct trusted_exec_bpf *prog) {
        return;
}

#endif
