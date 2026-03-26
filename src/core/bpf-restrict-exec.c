/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "bpf-restrict-exec.h"
#include "fileio.h"
#include "initrd-util.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "memory-util.h"
#include "parse-util.h"
#include "string-table.h"

/* DMVERITY_DEVICES_MAX lives in bpf-restrict-exec.h for sharing with tests. */

static const char* const restrict_exec_table[_RESTRICT_EXEC_MAX] = {
        [RESTRICT_EXEC_NO]     = "no",
        [RESTRICT_EXEC_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(restrict_exec, RestrictExec, RESTRICT_EXEC_STRICT);

const char* const restrict_exec_link_names[_RESTRICT_EXEC_LINK_MAX] = {
        [RESTRICT_EXEC_LINK_BDEV_SETINTEGRITY] = "restrict-exec-bdev-setintegrity-link",
        [RESTRICT_EXEC_LINK_BDEV_FREE]         = "restrict-exec-bdev-free-link",
        [RESTRICT_EXEC_LINK_BPRM_CHECK]        = "restrict-exec-bprm-check-link",
        [RESTRICT_EXEC_LINK_MMAP_FILE]         = "restrict-exec-mmap-file-link",
        [RESTRICT_EXEC_LINK_FILE_MPROTECT]     = "restrict-exec-file-mprotect-link",
};

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/restrict-exec/restrict-exec-skel.h"

/* Verify that restrict_exec_bss matches the skeleton's .bss layout */
assert_cc(sizeof(struct restrict_exec_bss) == sizeof_field(struct restrict_exec_bpf, bss[0]));

/* Build the skeleton links array indexed by the link enum. */
#define RESTRICT_EXEC_LINKS(obj) {                                                              \
        [RESTRICT_EXEC_LINK_BDEV_SETINTEGRITY] = (obj)->links.restrict_exec_bdev_setintegrity,   \
        [RESTRICT_EXEC_LINK_BDEV_FREE]         = (obj)->links.restrict_exec_bdev_free,           \
        [RESTRICT_EXEC_LINK_BPRM_CHECK]        = (obj)->links.restrict_exec_bprm_check,         \
        [RESTRICT_EXEC_LINK_MMAP_FILE]         = (obj)->links.restrict_exec_mmap_file,           \
        [RESTRICT_EXEC_LINK_FILE_MPROTECT]     = (obj)->links.restrict_exec_file_mprotect,       \
}

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

        r = sym_bpf_map__set_max_entries(obj->maps.verity_devices, DMVERITY_DEVICES_MAX);
        if (r < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to size hash table: %m");

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

/* Close the initramfs trust window after switch_root by clearing initramfs_s_dev
 * in the BPF .bss map. The .bss is a BPF_F_MMAPABLE array map — mmap it and do
 * a single aligned 4-byte store instead of a full-value read-modify-write via
 * bpf_map_update_elem, which would needlessly rewrite the guard globals too. */
static int restrict_exec_clear_initramfs_trust(int bss_map_fd) {
        void *p;

        assert(bss_map_fd >= 0);
        assert_cc(offsetof(struct restrict_exec_bss, initramfs_s_dev) == 0);

        p = mmap(NULL, page_size(), PROT_READ | PROT_WRITE, MAP_SHARED, bss_map_fd, 0);
        if (p == MAP_FAILED)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to mmap .bss map: %m");

        /* initramfs_s_dev is at offset 0 in the .bss layout. Single aligned
         * 32-bit store is atomic — BPF programs see either the old or new value,
         * no torn reads possible. Guard globals are untouched. */
        *(uint32_t *) p = 0;

        if (munmap(p, page_size()) < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to munmap .bss map: %m");

        log_info("bpf-restrict-exec: Cleared initramfs trust window after switch_root.");
        return 0;
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

        /* Extract owned FDs from the skeleton. These keep the kernel BPF objects
         * alive after the skeleton is destroyed. Destroying the skeleton unmaps
         * the .bss page from our address space so no BPF state is reachable via
         * /proc/1/mem. */
        struct bpf_link *links[] = RESTRICT_EXEC_LINKS(obj);

        FOREACH_ELEMENT(link, links) {
                size_t idx = link - links;

                m->restrict_exec_link_fds[idx] = fcntl(sym_bpf_link__fd(*link), F_DUPFD_CLOEXEC, 3);
                if (m->restrict_exec_link_fds[idx] < 0)
                        return log_error_errno(errno, "bpf-restrict-exec: Failed to dup link FD for %s: %m",
                                               restrict_exec_link_names[idx]);
        }

        m->restrict_exec_bss_map_fd = fcntl(sym_bpf_map__fd(obj->maps.bss), F_DUPFD_CLOEXEC, 3);
        if (m->restrict_exec_bss_map_fd < 0)
                return log_error_errno(errno, "bpf-restrict-exec: Failed to dup .bss map FD: %m");

        return 0;
}

int bpf_restrict_exec_close_initramfs_trust(Manager *m) {
        assert(m);

        /* Clear initramfs_s_dev in the BPF .bss map BEFORE switch_root unmounts
         * the initramfs. This eliminates the dev_t recycling window: the anonymous
         * dev_t is still held by the mounted initramfs superblock, so no other
         * filesystem can recycle it yet. Anonymous dev_t recycling is immediate
         * and lowest-first, so a stale initramfs_s_dev is a near-certain trust
         * bypass — fail closed. */
        if (!in_initrd() || m->restrict_exec_bss_map_fd < 0)
                return 0;

        return restrict_exec_clear_initramfs_trust(m->restrict_exec_bss_map_fd);
}

#else /* ! BPF_FRAMEWORK */

bool bpf_restrict_exec_supported(void) {
        return false;
}

int bpf_restrict_exec_setup(Manager *m) {
        if (!MANAGER_IS_SYSTEM(m) || m->restrict_exec <= RESTRICT_EXEC_NO)
                return 0;

        return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                 "bpf-restrict-exec: RestrictExec= requested but BPF framework is not compiled in.");
}

int bpf_restrict_exec_close_initramfs_trust(Manager *m) {
        return 0;
}

#endif
