/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Test helper for RestrictFileSystemAccess= BPF enforcement tests.
 *
 * Usage:
 *   test-bpf-restrict-fsaccess attach              — Load, attach, print IDs, then block.
 *                                                Kill the process to detach (synchronous
 *                                                via bpf_link_put_direct on last FD close).
 *   test-bpf-restrict-fsaccess check               — Run PID 1's prerequisite checks and install its
 *                                                ptrace seccomp filter
 *   test-bpf-restrict-fsaccess mmap-exec PATH      — Attempt PROT_READ|PROT_EXEC mmap of PATH
 *   test-bpf-restrict-fsaccess anon-mmap-exec      — Attempt anonymous PROT_READ|PROT_EXEC mmap
 *   test-bpf-restrict-fsaccess mprotect-exec PATH  — mmap PATH PROT_READ, then mprotect to PROT_EXEC
 *   test-bpf-restrict-fsaccess mmap-wx PATH        — PROT_WRITE|PROT_EXEC mmap of PATH (W^X variant A)
 *   test-bpf-restrict-fsaccess mprotect-cow-exec PATH — mmap PROT_WRITE, write, mprotect PROT_EXEC (variant B)
 *   test-bpf-restrict-fsaccess mprotect-wx PATH    — mmap PROT_EXEC, then mprotect +PROT_WRITE (variant C)
 *   test-bpf-restrict-fsaccess procmem-cow PATH    — mmap PROT_EXEC, then rewrite it via /proc/self/mem
 *   test-bpf-restrict-fsaccess poketext            — install ptrace seccomp, verify PTRACE_POKE{TEXT,DATA}
 *                                                are denied
 *
 * The probes exit with 0 if the operation was allowed (the bypass works), 1 if
 * it was refused with the errno the mechanism under test produces, 2 if it
 * could not be attempted and 3 if it was refused with an unexpected errno.
 *
 * When "attach" is used, the BPF LSM program is loaded with initramfs_s_dev
 * set to the current rootfs s_dev, so the calling test script (running from
 * the rootfs) continues to work. The process holds all link FDs and blocks;
 * when killed, close() drops the last reference synchronously.
 */

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bpf-link.h"
#include "bpf-restrict-fsaccess.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "seccomp-util.h"
#include "string-util.h"
#include "tests.h"

/* ---- Probe commands (no BPF dependency) ----
 *
 * Each attempts one operation the hooks are supposed to deny. The exit codes
 * let the test script tell a denial by the mechanism under test from a probe
 * that could not run at all. */
enum {
        PROBE_ALLOWED      = 0, /* the operation succeeded, i.e. the bypass works */
        PROBE_DENIED       = 1, /* refused with the errno the mechanism under test produces */
        PROBE_ERROR        = 2, /* the operation could not be attempted */
        PROBE_DENIED_OTHER = 3, /* refused, but with an unexpected errno (another LSM?) */
};

/* Only the errno the mechanism under test produces counts as a denial. */
static int probe_denied(int error, int expected) {
        assert(error < 0);

        if (error == expected)
                return PROBE_DENIED;

        log_warning("Refused with unexpected error %s, expected %s.", STRERROR(error), STRERROR(expected));
        return PROBE_DENIED_OTHER;
}

static int mmap_probe(const char *path, int prot, const char *what) {
        _cleanup_close_ int fd = -EBADF;
        void *addr;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                log_error_errno(errno, "Failed to open %s: %m", path);
                return PROBE_ERROR;
        }

        addr = mmap(NULL, 4096, prot, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED) {
                r = -errno;
                log_info_errno(r, "%s of %s denied: %m", what, path);
                return probe_denied(r, -EPERM);
        }

        (void) munmap(addr, 4096);
        log_info("%s of %s succeeded", what, path);
        return PROBE_ALLOWED;
}

/* Maps PATH with 'prot', then changes the protection to 'new_prot'. With 'poke' the mapping is written to
 * first, so that the page is a private copy. */
static int mprotect_probe(const char *path, int prot, bool poke, int new_prot, const char *what) {
        _cleanup_close_ int fd = -EBADF;
        void *addr;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                log_error_errno(errno, "Failed to open %s: %m", path);
                return PROBE_ERROR;
        }

        addr = mmap(NULL, 4096, prot, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED) {
                log_error_errno(errno, "Initial mmap of %s failed, cannot probe: %m", path);
                return PROBE_ERROR;
        }

        if (poke)
                *(volatile uint8_t*) addr = 0x90; /* trigger copy-on-write */

        r = RET_NERRNO(mprotect(addr, 4096, new_prot));
        (void) munmap(addr, 4096);

        if (r < 0) {
                log_info_errno(r, "%s on %s denied: %m", what, path);
                return probe_denied(r, -EPERM);
        }

        log_info("%s on %s succeeded", what, path);
        return PROBE_ALLOWED;
}

static int do_mmap_exec(const char *path) {
        return mmap_probe(path, PROT_READ | PROT_EXEC, "PROT_EXEC mmap");
}

static int do_anon_mmap_exec(void) {
        void *addr;
        int r;

        addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
                r = -errno;
                log_info_errno(r, "Anonymous PROT_EXEC mmap denied: %m");
                return probe_denied(r, -EPERM);
        }

        (void) munmap(addr, 4096);
        log_info("Anonymous PROT_EXEC mmap succeeded");
        return PROBE_ALLOWED;
}

/* mmap PROT_READ, then add PROT_EXEC: denied for untrusted files, a positive control for trusted ones. */
static int do_mprotect_exec(const char *path) {
        return mprotect_probe(path, PROT_READ, /* poke= */ false, PROT_READ | PROT_EXEC, "mprotect PROT_EXEC");
}

/* ---- W^X bypass probes (GHSA-q65q-ggpx-fjgp) ----
 *
 * Each tries to get attacker-controlled bytes into an executable page of a
 * trusted file. With the W^X hooks in place they must all be denied; an exit
 * of PROBE_ALLOWED means the bypass still works. */

/* Variant A: a private writable+executable mapping. */
static int do_mmap_wx(const char *path) {
        return mmap_probe(path, PROT_READ | PROT_WRITE | PROT_EXEC, "W+X mmap");
}

/* Variant B: map writable, modify via copy-on-write, then turn executable. */
static int do_mprotect_cow_exec(const char *path) {
        return mprotect_probe(path, PROT_READ | PROT_WRITE, /* poke= */ true, PROT_READ | PROT_EXEC,
                              "mprotect PROT_EXEC after COW write");
}

/* Variant C: map executable, then add write. */
static int do_mprotect_wx(const char *path) {
        return mprotect_probe(path, PROT_READ | PROT_EXEC, /* poke= */ false, PROT_READ | PROT_WRITE | PROT_EXEC,
                              "mprotect PROT_WRITE|PROT_EXEC");
}

/* mmap PROT_EXEC read-only (allowed), then rewrite the page through /proc/self/mem, which the kernel only
 * services with FOLL_FORCE, i.e. unless booted with proc_mem.force_override=never. */
static int do_procmem_cow(const char *path) {
        _cleanup_close_ int fd = -EBADF, mem_fd = -EBADF;
        static const uint8_t byte = 0x90;
        void *addr;
        ssize_t n;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                log_error_errno(errno, "Failed to open %s: %m", path);
                return PROBE_ERROR;
        }

        addr = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED) {
                log_error_errno(errno, "PROT_EXEC mmap of %s failed, cannot probe: %m", path);
                return PROBE_ERROR;
        }

        mem_fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
        if (mem_fd < 0) {
                r = -errno;
                (void) munmap(addr, 4096);
                log_error_errno(r, "Failed to open /proc/self/mem: %m");
                return PROBE_ERROR;
        }

        n = pwrite(mem_fd, &byte, sizeof(byte), (off_t) (uintptr_t) addr);
        r = n < 0 ? -errno : 0;
        (void) munmap(addr, 4096);

        if (r < 0) {
                log_info_errno(r, "/proc/self/mem write to exec page of %s denied: %m", path);
                /* Without FOLL_FORCE access_remote_vm() copies nothing and mem_rw() fails with EIO. */
                return probe_denied(r, -EIO);
        }

        log_info("/proc/self/mem write to exec page of %s succeeded", path);
        return PROBE_ALLOWED;
}

/* Writes one word into the stopped tracee with 'request' (PTRACE_POKETEXT or PTRACE_POKEDATA). */
static int poke(pid_t pid, int request, const char *name) {
        errno = 0;
        if (ptrace(request, pid, (void*) (uintptr_t) &poke, (void*) 0x42) < 0) {
                if (errno == EPERM) {
                        log_info("ptrace(%s) denied by seccomp (EPERM) as expected", name);
                        return PROBE_DENIED;
                }

                log_error_errno(errno, "ptrace(%s) failed unexpectedly: %m", name);
                return PROBE_ERROR;
        }

        log_info("ptrace(%s) succeeded, seccomp NOT enforcing", name);
        return PROBE_ALLOWED;
}

/* Self-contained check of the ptrace() memory-write block (seccomp layer). The
 * filter is installed by PID 1 in production, not by "attach", and seccomp is
 * per-process-tree, so this probe installs it itself and then verifies that
 * PTRACE_POKETEXT and PTRACE_POKEDATA are refused while attaching and reading
 * (PTRACE_PEEKTEXT) still work. */
static int do_poketext_seccomp(void) {
        int status = 0, r;
        pid_t pid;
        long peek;

        r = seccomp_restrict_ptrace();
        if (r < 0) {
                log_error_errno(r, "Failed to install ptrace seccomp filter: %m");
                return PROBE_ERROR;
        }

        pid = fork();
        if (pid < 0) {
                log_error_errno(errno, "fork failed: %m");
                return PROBE_ERROR;
        }
        if (pid == 0) {
                /* Child: invite tracing (PTRACE_TRACEME is not blocked), then stop. */
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
                        _exit(EXIT_FAILURE);
                raise(SIGSTOP);
                _exit(EXIT_SUCCESS);
        }

        /* WUNTRACED: if PTRACE_TRACEME failed (e.g. Yama ptrace_scope=3) the child stops untraced, and
         * without the flag we would wait forever. */
        if (waitpid(pid, &status, WUNTRACED) < 0) {
                log_error_errno(errno, "waitpid failed: %m");
                r = PROBE_ERROR;
                goto reap;
        }
        /* Anything but a stop means waitpid() reaped the child, so there is nothing left to kill. */
        if (WIFEXITED(status)) {
                log_error("PTRACE_TRACEME failed in the child, cannot ptrace in this environment.");
                return PROBE_ERROR;
        }
        if (!WIFSTOPPED(status)) {
                log_error("Child did not stop as expected (status=%i).", status);
                return PROBE_ERROR;
        }

        /* PEEKTEXT (read) must still work: attaching and inspection stay allowed. */
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, pid, (void*) (uintptr_t) &poke, NULL);
        if (peek == -1 && errno != 0) {
                log_error_errno(errno, "ptrace(PTRACE_PEEKTEXT) failed, filter too broad?: %m");
                r = PROBE_ERROR;
                goto reap;
        }

        /* Both writers must be refused. */
        r = poke(pid, PTRACE_POKETEXT, "PTRACE_POKETEXT");
        if (r == PROBE_DENIED)
                r = poke(pid, PTRACE_POKEDATA, "PTRACE_POKEDATA");

reap:
        (void) kill(pid, SIGKILL);
        (void) waitpid(pid, &status, 0);
        return r;
}

static int usage(void) {
        log_error("Usage: %s attach|check|mmap-exec PATH|anon-mmap-exec|mprotect-exec PATH|"
                  "mmap-wx PATH|mprotect-cow-exec PATH|mprotect-wx PATH|procmem-cow PATH|poketext",
                  program_invocation_short_name);
        /* Not EXIT_FAILURE, which is PROBE_DENIED. */
        return PROBE_ERROR;
}

/* The probes need no BPF support. Returns the probe's exit code, or -1 if the verb is not a probe. */
static int dispatch_probe(int argc, char *argv[]) {
        const char *verb = argv[1];

        if (argc == 2) {
                if (streq(verb, "anon-mmap-exec"))
                        return do_anon_mmap_exec();
                if (streq(verb, "poketext"))
                        return do_poketext_seccomp();
                return -1;
        }

        if (argc != 3)
                return -1;

        if (streq(verb, "mmap-exec"))
                return do_mmap_exec(argv[2]);
        if (streq(verb, "mprotect-exec"))
                return do_mprotect_exec(argv[2]);
        if (streq(verb, "mmap-wx"))
                return do_mmap_wx(argv[2]);
        if (streq(verb, "mprotect-cow-exec"))
                return do_mprotect_cow_exec(argv[2]);
        if (streq(verb, "mprotect-wx"))
                return do_mprotect_wx(argv[2]);
        if (streq(verb, "procmem-cow"))
                return do_procmem_cow(argv[2]);

        return -1;
}

#if BPF_FRAMEWORK && HAVE_LSM_INTEGRITY_TYPE
#include "bpf-util.h"
#include "restrict-fsaccess-skel.h"

static struct restrict_fsaccess_bpf *restrict_fsaccess_bpf_free(struct restrict_fsaccess_bpf *obj) {
        restrict_fsaccess_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct restrict_fsaccess_bpf *, restrict_fsaccess_bpf_free);

static int do_attach(void) {
        _cleanup_(restrict_fsaccess_bpf_freep) struct restrict_fsaccess_bpf *obj = NULL;
        struct stat st;
        int r;

        r = dlopen_bpf(LOG_ERR);
        if (r < 0)
                return log_error_errno(r, "Failed to dlopen libbpf: %m");

        r = bpf_restrict_fsaccess_prepare(&obj);
        if (r < 0)
                return r;

        /* Set initramfs_s_dev to rootfs s_dev so the test script keeps running */
        if (stat("/", &st) < 0)
                return log_error_errno(errno, "Failed to stat /: %m");

        obj->bss->initramfs_s_dev = STAT_DEV_TO_KERNEL(st.st_dev);
        log_info("Set initramfs_s_dev to %u:%u (kernel dev_t=0x%x)",
                 major(st.st_dev), minor(st.st_dev), obj->bss->initramfs_s_dev);

        r = restrict_fsaccess_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to attach BPF programs: %m");

        /* Populate guard globals so the guard protects our BPF objects */
        r = bpf_restrict_fsaccess_populate_guard(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to populate guard globals: %m");

        printf("VERITY_MAP_ID=%u\n", (unsigned) obj->bss->protected_map_id_verity);
        printf("BSS_MAP_ID=%u\n", (unsigned) obj->bss->protected_map_id_bss);
        printf("HAVE_REAL_DATA_INODE=%u\n", (unsigned) obj->rodata->have_real_data_inode);

        /* Print comma-separated prog and link IDs for guard tests */
        printf("PROG_IDS=\"");
        for (size_t i = 0; i < _RESTRICT_FILESYSTEM_ACCESS_LINK_MAX; i++)
                printf("%s%u", i > 0 ? "," : "", (unsigned) obj->bss->protected_prog_ids[i]);
        printf("\"\n");

        printf("LINK_IDS=\"");
        for (size_t i = 0; i < _RESTRICT_FILESYSTEM_ACCESS_LINK_MAX; i++)
                printf("%s%u", i > 0 ? "," : "", (unsigned) obj->bss->protected_link_ids[i]);
        printf("\"\n");

        fflush(stdout);

        /* Block until killed. The _cleanup_ destructor holds all link FDs via
         * the skeleton. When this process is killed, close() on the FDs goes
         * through bpf_link_put_direct() which synchronously detaches the
         * trampoline before the process exits. No bpffs pins needed. */
        log_info("BPF programs attached, waiting for signal to detach...");
        for (;;)
                pause();

        /* unreachable — cleanup happens via signal/exit */
}

static int do_check(void) {
        int r;

        r = bpf_restrict_fsaccess_check_prerequisites();
        if (r < 0)
                return r;

        /* PID 1 refuses the policy without the ptrace filter, mirror that. */
        r = seccomp_restrict_ptrace();
        if (r < 0)
                return log_error_errno(r, "Failed to install the ptrace seccomp filter: %m");
        log_info("ptrace seccomp filter: installed");

        /* Last: linking attaches bprm_check for an instant with an empty trust map, during which every
         * execve() on the system is denied. Keep that window out of the cheap failure paths above. */
        _cleanup_(restrict_fsaccess_bpf_freep) struct restrict_fsaccess_bpf *obj = NULL;
        r = bpf_restrict_fsaccess_prepare(&obj);
        if (r < 0)
                return r;

        if (!bpf_can_link_lsm_program(obj->progs.restrict_fsaccess_bprm_check))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "bpf-restrict-fsaccess: Failed to link program.");

        return 0;
}

int main(int argc, char *argv[]) {
        int r;

        test_setup_logging(LOG_DEBUG);

        if (argc < 2)
                return usage();

        if (streq(argv[1], "attach"))
                return do_attach() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (streq(argv[1], "check"))
                return do_check() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        r = dispatch_probe(argc, argv);
        if (r >= 0)
                return r;

        return usage();
}

#else /* ! BPF_FRAMEWORK || ! HAVE_LSM_INTEGRITY_TYPE */

int main(int argc, char *argv[]) {
        int r;

        test_setup_logging(LOG_DEBUG);

        if (argc < 2)
                return usage();

        if (STR_IN_SET(argv[1], "attach", "check")) {
                log_info("BPF framework not available, attach/check not supported");
                return 77; /* skip */
        }

        r = dispatch_probe(argc, argv);
        if (r >= 0)
                return r;

        return usage();
}

#endif
