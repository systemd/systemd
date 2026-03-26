/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Test helper for RestrictExec= BPF enforcement tests.
 *
 * Usage:
 *   test-bpf-restrict-exec attach   — Load, attach, pin BPF links
 *   test-bpf-restrict-exec detach   — Remove pinned BPF links
 *   test-bpf-restrict-exec check    — Check BPF LSM + require_signatures preconditions
 *
 * When "attach" is used, the BPF LSM program is loaded with initramfs_s_dev
 * set to the current rootfs s_dev, so the calling test script (running from
 * the rootfs) continues to work. BPF links are pinned to /sys/fs/bpf/ so
 * they persist after this process exits.
 */

#include <stdio.h>
#include <sys/bpf.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bpf-restrict-exec.h"
#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf/restrict-exec/restrict-exec-skel.h"

#define PIN_PATH_PREFIX "/sys/fs/bpf/test_restrict_exec_"

static int do_attach(void) {
        _cleanup_(restrict_exec_bpf_freep) struct restrict_exec_bpf *obj = NULL;
        struct stat st;
        int r;

        r = dlopen_bpf_full(LOG_ERR);
        if (r < 0)
                return log_error_errno(r, "Failed to dlopen libbpf: %m");

        obj = restrict_exec_bpf__open();
        if (!obj)
                return log_error_errno(errno, "Failed to open BPF object: %m");

        r = restrict_exec_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to load BPF object: %m");

        /* Set initramfs_s_dev to rootfs s_dev so the test script keeps running */
        if (stat("/", &st) < 0)
                return log_error_errno(errno, "Failed to stat /: %m");

        obj->bss->initramfs_s_dev = STAT_DEV_TO_KERNEL(st.st_dev);
        log_info("Set initramfs_s_dev to %u:%u (kernel dev_t=0x%x)",
                 major(st.st_dev), minor(st.st_dev), obj->bss->initramfs_s_dev);

        r = restrict_exec_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to attach BPF programs: %m");

        /* Populate guard globals so the guard protects our BPF objects */
        r = bpf_restrict_exec_populate_guard(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to populate guard globals: %m");

        /* Pin all links so they persist after this process exits */
        r = sym_bpf_link__pin(obj->links.restrict_exec_bdev_setintegrity,
                              PIN_PATH_PREFIX "bdev_setintegrity");
        if (r < 0)
                return log_error_errno(r, "Failed to pin bdev_setintegrity link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_bdev_free,
                              PIN_PATH_PREFIX "bdev_free");
        if (r < 0)
                return log_error_errno(r, "Failed to pin bdev_free link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_bprm_check,
                              PIN_PATH_PREFIX "bprm_check");
        if (r < 0)
                return log_error_errno(r, "Failed to pin bprm_check link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_mmap_file,
                              PIN_PATH_PREFIX "mmap_file");
        if (r < 0)
                return log_error_errno(r, "Failed to pin mmap_file link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_file_mprotect,
                              PIN_PATH_PREFIX "file_mprotect");
        if (r < 0)
                return log_error_errno(r, "Failed to pin file_mprotect link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_ptrace_guard,
                              PIN_PATH_PREFIX "ptrace_guard");
        if (r < 0)
                return log_error_errno(r, "Failed to pin ptrace_guard link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_bpf_map_guard,
                              PIN_PATH_PREFIX "bpf_map_guard");
        if (r < 0)
                return log_error_errno(r, "Failed to pin bpf_map_guard link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_bpf_prog_guard,
                              PIN_PATH_PREFIX "bpf_prog_guard");
        if (r < 0)
                return log_error_errno(r, "Failed to pin bpf_prog_guard link: %m");

        r = sym_bpf_link__pin(obj->links.restrict_exec_bpf_guard,
                              PIN_PATH_PREFIX "bpf_guard");
        if (r < 0)
                return log_error_errno(r, "Failed to pin bpf_guard link: %m");

        log_info("All BPF links pinned to " PIN_PATH_PREFIX "*");

        printf("VERITY_MAP_ID=%u\n", (unsigned) obj->bss->protected_map_id_verity);
        printf("BSS_MAP_ID=%u\n", (unsigned) obj->bss->protected_map_id_bss);

        /* Print comma-separated prog and link IDs for guard tests */
        printf("PROG_IDS=\"");
        for (int i = 0; i < _RESTRICT_EXEC_LINK_MAX; i++)
                printf("%s%u", i > 0 ? "," : "", (unsigned) obj->bss->protected_prog_ids[i]);
        printf("\"\n");

        printf("LINK_IDS=\"");
        for (int i = 0; i < _RESTRICT_EXEC_LINK_MAX; i++)
                printf("%s%u", i > 0 ? "," : "", (unsigned) obj->bss->protected_link_ids[i]);
        printf("\"\n");

        /* Detach links from the skeleton so destroying it doesn't unpin them */
        obj->links.restrict_exec_bdev_setintegrity = NULL;
        obj->links.restrict_exec_bdev_free = NULL;
        obj->links.restrict_exec_bprm_check = NULL;
        obj->links.restrict_exec_mmap_file = NULL;
        obj->links.restrict_exec_file_mprotect = NULL;
        obj->links.restrict_exec_ptrace_guard = NULL;
        obj->links.restrict_exec_bpf_map_guard = NULL;
        obj->links.restrict_exec_bpf_prog_guard = NULL;
        obj->links.restrict_exec_bpf_guard = NULL;

        return 0;
}

/* Open a bpffs pin via BPF_OBJ_GET to obtain a link FD, then unlink the pin
 * and close the FD. Closing the FD goes through bpf_link_release() which uses
 * bpf_link_put_direct() — this calls bpf_link_free() synchronously, detaching
 * the BPF program from the trampoline before returning.
 *
 * Plain unlink() on bpffs goes through bpf_link_put() which always defers via
 * schedule_work(), leaving the BPF program active on the hook after unlink()
 * returns. */
static void detach_pin(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        union bpf_attr attr;

        zero(attr);
        attr.pathname = PTR_TO_UINT64(path);

        fd = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
        if (fd < 0) {
                /* Pin might already be gone or inaccessible — just try unlink */
                (void) unlink(path);
                return;
        }

        /* Remove the pin first (drops one ref via deferred bpf_link_put),
         * then close the FD (drops final ref via synchronous bpf_link_put_direct
         * in bpf_link_release). */
        (void) unlink(path);
        /* fd closed by _cleanup_close_ — triggers synchronous trampoline detach */
}

static int do_detach(void) {
        detach_pin(PIN_PATH_PREFIX "bdev_setintegrity");
        detach_pin(PIN_PATH_PREFIX "bdev_free");
        detach_pin(PIN_PATH_PREFIX "bprm_check");
        detach_pin(PIN_PATH_PREFIX "mmap_file");
        detach_pin(PIN_PATH_PREFIX "file_mprotect");
        detach_pin(PIN_PATH_PREFIX "ptrace_guard");
        detach_pin(PIN_PATH_PREFIX "bpf_map_guard");
        detach_pin(PIN_PATH_PREFIX "bpf_prog_guard");
        detach_pin(PIN_PATH_PREFIX "bpf_guard");

        log_info("All BPF link pins removed");
        return 0;
}

static int do_check(void) {
        if (!bpf_restrict_exec_supported()) {
                log_error("BPF LSM is not available");
                return -EOPNOTSUPP;
        }
        log_info("BPF LSM: supported");

        if (!dm_verity_require_signatures()) {
                log_error("dm-verity require_signatures is not enabled");
                return -ENOKEY;
        }
        log_info("dm-verity require_signatures: enabled");

        return 0;
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        if (argc != 2) {
                log_error("Usage: %s attach|detach|check", program_invocation_short_name);
                return EXIT_FAILURE;
        }

        if (streq(argv[1], "attach"))
                return do_attach() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "detach"))
                return do_detach() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "check"))
                return do_check() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        log_error("Usage: %s attach|detach|check", program_invocation_short_name);
        return EXIT_FAILURE;
}

#else /* ! BPF_FRAMEWORK */

int main(int argc, char *argv[]) {
        log_info("BPF framework not available");
        return 77; /* skip */
}

#endif
