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
#include "serialize.h"

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

static bool restrict_exec_have_deserialized_fds(Manager *m) {
        size_t count = 0;

        assert(m);

        /* Check if we have link FDs deserialized from a previous exec */
        for (size_t i = 0; i < ELEMENTSOF(m->restrict_exec_link_fds); i++)
                if (m->restrict_exec_link_fds[i] >= 0)
                        count++;

        if (count > 0 && count < ELEMENTSOF(m->restrict_exec_link_fds))
                log_error("bpf-restrict-exec: Only %zu of %zu link FDs deserialized, enforcement may be incomplete.",
                          count, ELEMENTSOF(m->restrict_exec_link_fds));

        return count > 0;
}

/* Close the initramfs trust window after switch_root by clearing initramfs_s_dev
 * in the BPF .bss map. We must read-modify-write the full .bss to preserve guard
 * globals (protected map/prog/link IDs). */
static int restrict_exec_clear_initramfs_trust(int bss_map_fd) {
        struct restrict_exec_bss bss = {};
        uint32_t key = 0;
        int r;

        assert(bss_map_fd >= 0);

        r = dlopen_bpf_full(LOG_ERR);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to load libbpf for .bss update: %m");

        r = sym_bpf_map_lookup_elem(bss_map_fd, &key, &bss);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to read .bss map: %m");

        bss.initramfs_s_dev = 0;
        r = sym_bpf_map_update_elem(bss_map_fd, &key, &bss, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "bpf-restrict-exec: Failed to clear initramfs_s_dev via .bss map: %m");

        log_info("bpf-restrict-exec: Cleared initramfs trust window after switch_root.");
        return 0;
}

int bpf_restrict_exec_setup(Manager *m) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(m) || m->restrict_exec <= RESTRICT_EXEC_NO)
                return 0;

        /* If we already have link FDs from a previous exec, the BPF programs are still attached in the
         * kernel. Just keep holding the FDs — no need to re-create the skeleton. */
        if (restrict_exec_have_deserialized_fds(m)) {
                log_info("bpf-restrict-exec: Recovered link FDs from previous exec, programs still attached.");

                if (!in_initrd()) {
                        if (m->restrict_exec_bss_map_fd < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADF),
                                                       "bpf-restrict-exec: Cannot clear initramfs trust after switch_root.");
                        r = restrict_exec_clear_initramfs_trust(m->restrict_exec_bss_map_fd);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

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

void bpf_restrict_exec_close_initramfs_trust(Manager *m) {
        assert(m);

        /* Clear initramfs trust via the live skeleton's mmap'd .bss BEFORE
         * switch_root unmounts the initramfs. This eliminates the dev_t recycling
         * window: the anonymous dev_t is still held by the mounted initramfs
         * superblock, so no other filesystem can recycle it yet. After this
         * write, the BPF program immediately stops trusting the initramfs s_dev,
         * and the serialized .bss map FD will already reflect the cleared state. */
        if (!m->restrict_exec_bpf)
                return;

        m->restrict_exec_bpf->bss->initramfs_s_dev = 0;
        log_info("bpf-restrict-exec: Cleared initramfs trust before switch_root.");
}

int bpf_restrict_exec_serialize(Manager *m, FILE *f, FDSet *fds) {
        int r;

        assert(m);
        assert(f);
        assert(fds);

        /* If we have a live skeleton, serialize from its link objects */
        if (m->restrict_exec_bpf) {
                struct bpf_link *links[] = {
                        m->restrict_exec_bpf->links.restrict_exec_bdev_setintegrity,
                        m->restrict_exec_bpf->links.restrict_exec_bdev_free,
                        m->restrict_exec_bpf->links.restrict_exec_bprm_check,
                        m->restrict_exec_bpf->links.restrict_exec_mmap_file,
                        m->restrict_exec_bpf->links.restrict_exec_file_mprotect,
                };

                for (size_t i = 0; i < ELEMENTSOF(links); i++) {
                        r = bpf_serialize_link(f, fds, restrict_exec_link_names[i], links[i]);
                        if (r < 0 && r != -ENOENT)
                                return r;
                }

                r = serialize_fd(f, fds, "restrict-exec-bss-map", sym_bpf_map__fd(m->restrict_exec_bpf->maps.bss));
                if (r < 0)
                        return r;

                return 0;
        }

        /* Otherwise, if we have raw FDs from a previous deserialization, forward those */
        for (size_t i = 0; i < ELEMENTSOF(m->restrict_exec_link_fds); i++) {
                r = serialize_fd(f, fds, restrict_exec_link_names[i], m->restrict_exec_link_fds[i]);
                if (r < 0)
                        return r;
        }

        r = serialize_fd(f, fds, "restrict-exec-bss-map", m->restrict_exec_bss_map_fd);
        if (r < 0)
                return r;

        return 0;
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

void bpf_restrict_exec_close_initramfs_trust(Manager *m) {
}

int bpf_restrict_exec_serialize(Manager *m, FILE *f, FDSet *fds) {
        return 0;
}

#endif
