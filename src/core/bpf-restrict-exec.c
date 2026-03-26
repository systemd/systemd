/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "alloc-util.h"
#include "bpf-restrict-exec.h"
#include "fd-util.h"
#include "fileio.h"
#include "initrd-util.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "parse-util.h"
#include "string-table.h"

static const char* const restrict_exec_table[_RESTRICT_EXEC_MAX] = {
        [RESTRICT_EXEC_NO]     = "no",
        [RESTRICT_EXEC_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(restrict_exec, RestrictExec, RESTRICT_EXEC_STRICT);

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/restrict-exec/restrict-exec-skel.h"

/* The .bss map value must cover the entire .bss section. This static assert catches
 * .bss layout changes (e.g. new globals added to the BPF program) at compile time. */
assert_cc(sizeof_field(struct restrict_exec_bpf, bss[0]) == sizeof(uint32_t));

static bool dm_verity_require_signatures(void) {
        _cleanup_free_ char *val = NULL;
        int r;

        r = read_one_line_file("/sys/module/dm_verity/parameters/require_signatures", &val);
        if (r == -ENOENT) {
                log_debug("bpf-restrict-exec: dm-verity module not loaded, require_signatures not available.");
                return false;
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-restrict-exec: Failed to read dm-verity require_signatures: %m");
                return false;
        }

        return parse_boolean(val) > 0;
}

static int get_root_s_dev(uint32_t *ret) {
        struct stat st;

        assert(ret);

        /* Stat /usr/ rather than / — executable code lives in /usr/ and we push toward
         * a writable non-executable /. On systems with a separate /usr partition this
         * means / is intentionally not trusted. */
        if (stat("/usr/", &st) < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to stat /usr/ filesystem: %m");

        *ret = STAT_DEV_TO_KERNEL(st.st_dev);
        return 0;
}

static int prepare_restrict_exec_bpf(struct restrict_exec_bpf **ret) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        int r;

        assert(ret);

        obj = restrict_exec_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to open BPF object: %m");

        r = restrict_exec_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to load BPF object: %m");

        *ret = TAKE_PTR(obj);
        return 0;
}

bool bpf_restrict_exec_supported(void) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;
        if (dlopen_bpf_full(LOG_WARNING) < 0)
                return (supported = false);

        r = lsm_supported("bpf");
        if (r == -ENOPKG) {
                log_debug_errno(r, "bpf-restrict-exec: securityfs not mounted, BPF LSM not available.");
                return (supported = false);
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-restrict-exec: Can't determine whether the BPF LSM module is used: %m");
                return (supported = false);
        }
        if (r == 0) {
                log_info("bpf-restrict-exec: BPF LSM hook not enabled in the kernel, not supported.");
                return (supported = false);
        }

        r = prepare_restrict_exec_bpf(&obj);
        if (r < 0)
                return (supported = false);

        if (!bpf_can_link_lsm_program(obj->progs.restrict_exec_bprm_check)) {
                log_warning("bpf-restrict-exec: Failed to link program; assuming BPF LSM is not available.");
                return (supported = false);
        }

        return (supported = true);
}

int bpf_restrict_exec_setup(Manager *m) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(m) || m->restrict_exec <= RESTRICT_EXEC_NO)
                return 0;

        /* Fresh setup: verify BPF LSM is available */
        if (!bpf_restrict_exec_supported())
                return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                         "bpf-restrict-exec: BPF LSM is not available.");

        /* Require dm-verity signature enforcement */
        if (!dm_verity_require_signatures())
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                       "bpf-restrict-exec: dm-verity require_signatures is not enabled. "
                                       "RestrictExec= requires the kernel to enforce dm-verity signatures. "
                                       "Set dm_verity.require_signatures=1 on the kernel command line.");

        r = prepare_restrict_exec_bpf(&obj);
        if (r < 0)
                return r;

        /* If we're still in the initramfs, allow execution from it by recording
         * its s_dev. After switch_root, PID1 re-execs and in_initrd() returns
         * false — initramfs_s_dev stays at 0 (its default), closing the trust
         * window. */
        if (in_initrd()) {
                uint32_t root_dev;

                r = get_root_s_dev(&root_dev);
                if (r < 0)
                        return r;

                obj->bss->initramfs_s_dev = root_dev;
                log_info("bpf-restrict-exec: Initramfs trusted (s_dev=%" PRIu32 ":%" PRIu32 ")",
                         root_dev >> 20, root_dev & 0xFFFFF);
        }

        r = restrict_exec_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to attach BPF programs: %m");

        log_info("bpf-restrict-exec: LSM BPF programs attached");

        m->restrict_exec_bpf = TAKE_PTR(obj);
        return 0;
}

void bpf_restrict_exec_destroy(struct restrict_exec_bpf *prog) {
        restrict_exec_bpf__destroy(prog);
}

#else /* ! BPF_FRAMEWORK */

bool bpf_restrict_exec_supported(void) {
        return false;
}

int bpf_restrict_exec_setup(Manager *m) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-restrict-exec: BPF framework is not supported.");
}

void bpf_restrict_exec_destroy(struct restrict_exec_bpf *prog) {
        return;
}

#endif
