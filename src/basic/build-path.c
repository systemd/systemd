/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <link.h>
#include <sys/auxv.h>

#include "build-path.h"
#include "errno-list.h"
#include "errno-util.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "unistd.h"

static int get_runpath_from_dynamic(const ElfW(Dyn) *d, ElfW(Addr) bias, const char **ret) {
        size_t runpath_index = SIZE_MAX, rpath_index = SIZE_MAX;
        const char *strtab = NULL;

        assert(d);

        /* Iterates through the PT_DYNAMIC section to find the DT_RUNPATH/DT_RPATH entries */

        for (; d->d_tag != DT_NULL; d++) {

                switch (d->d_tag) {

                case DT_RUNPATH:
                        runpath_index = (size_t) d->d_un.d_val;
                        break;

                case DT_RPATH:
                        rpath_index = (size_t) d->d_un.d_val;
                        break;

                case DT_STRTAB:
                        /* On MIPS and RISC-V DT_STRTAB records an offset, not a valid address, so it has to be adjusted
                         * using the bias calculated earlier. */
                        if (d->d_un.d_val != 0)
                                strtab = (const char *) ((uintptr_t) d->d_un.d_val
#if defined(__mips__) || defined(__riscv)
                                         + bias
#endif
                                );
                        break;
                }

                /* runpath wins, hence if we have the table and runpath we can exit the loop early */
                if (strtab && runpath_index != SIZE_MAX)
                        break;
        }

        if (!strtab)
                return -ENOTRECOVERABLE;

        /* According to ld.so runpath wins if both runpath and rpath are defined. */
        if (runpath_index != SIZE_MAX) {
                if (ret)
                        *ret = strtab + runpath_index;
                return 1;
        }

        if (rpath_index != SIZE_MAX) {
                if (ret)
                        *ret = strtab + rpath_index;
                return 1;
        }

        if (ret)
                *ret = NULL;

        return 0;
}

static int get_runpath(const char **ret) {
        unsigned long phdr, phent, phnum;

        /* Finds the rpath/runpath in the program headers of the main executable we are running in */

        phdr = getauxval(AT_PHDR);      /* Start offset of phdr */
        if (phdr == 0)
                return -ENOTRECOVERABLE;

        phnum = getauxval(AT_PHNUM);    /* Number of entries in phdr */
        if (phnum == 0)
                return -ENOTRECOVERABLE;

        phent = getauxval(AT_PHENT);    /* Size of entries in phdr */
        if (phent < sizeof(ElfW(Phdr))) /* Safety check, that our idea of the structure matches the file */
                return -ENOTRECOVERABLE;

        ElfW(Addr) bias = 0, dyn = 0;
        bool found_bias = false, found_dyn = false;

        /* Iterate through the Phdr structures to find the PT_PHDR and PT_DYNAMIC sections */
        for (unsigned long i = 0; i < phnum; i++) {
                const ElfW(Phdr) *p = (const ElfW(Phdr)*) (phdr + (i * phent));

                switch (p->p_type) {

                case PT_PHDR:
                        if (p->p_vaddr > phdr) /* safety overflow check */
                                return -ENOTRECOVERABLE;

                        bias = (ElfW(Addr)) phdr - p->p_vaddr;
                        found_bias = true;
                        break;

                case PT_DYNAMIC:
                        dyn = p->p_vaddr;
                        found_dyn = true;
                        break;
                }

                if (found_bias && found_dyn)
                        break;
        }

        if (!found_dyn)
                return -ENOTRECOVERABLE;

        return get_runpath_from_dynamic((const ElfW(Dyn)*) (bias + dyn), bias, ret);
}

int get_build_exec_dir(char **ret) {
        int r;

        /* Returns the build execution directory if we are invoked in a build environment. Specifically, this
         * checks if the main program binary has an rpath/runpath set (i.e. an explicit directory where to
         * look for shared libraries) to $ORIGIN. If so we know that this is not a regular installed binary,
         * but one which shall acquire its libraries from below a directory it is located in, i.e. a build
         * directory or similar. In that case it typically makes sense to also search for our auxiliary
         * executables we fork() off in a directory close to our main program binary, rather than in the
         * system.
         *
         * This function is supposed to be used when looking for "callout" binaries that are closely related
         * to the main program (i.e. speak a specific protocol between each other). And where it's generally
         * a good idea to use the binary from the build tree (if there is one) instead of the system.
         *
         * Note that this does *not* actually return the rpath/runpath but the instead the directory the main
         * executable was found in. This follows the logic that the result is supposed to be used for
         * executable binaries (i.e. stuff in bindir), not for shared libraries (i.e. stuff in libdir), and
         * hence the literal shared library path would just be wrong.
         *
         * TLDR: if we look for callouts in this dir first, running binaries from the meson build tree
         * automatically uses the right callout.
         *
         * Returns:
         *     -ENOEXEC         → We are not running in an rpath/runpath $ORIGIN environment
         *     -ENOENT          → We don't know our own binary path
         *     -NOTRECOVERABLE  → Dynamic binary information missing?
         */

        static int runpath_cached = -ERRNO_MAX-1;
        if (runpath_cached == -ERRNO_MAX-1) {
                const char *runpath = NULL;

                runpath_cached = get_runpath(&runpath);

                /* We only care if the runpath starts with $ORIGIN/ */
                if (runpath_cached > 0 && !startswith(runpath, "$ORIGIN/"))
                        runpath_cached = 0;
        }
        if (runpath_cached < 0)
                return runpath_cached;
        if (runpath_cached == 0)
                return -ENOEXEC;

        _cleanup_free_ char *exe = NULL;
        r = get_process_exe(0, &exe);
        if (r < 0)
                return runpath_cached = r;

        return path_extract_directory(exe, ret);
}

static int find_build_dir_binary(const char *fn, char **ret) {
        int r;

        assert(fn);
        assert(ret);

        _cleanup_free_ char *build_dir = NULL;
        r = get_build_exec_dir(&build_dir);
        if (r < 0)
                return r;

        _cleanup_free_ char *np = path_join(build_dir, fn);
        if (!np)
                return -ENOMEM;

        *ret = TAKE_PTR(np);
        return 0;
}

static int find_environment_binary(const char *fn, const char **ret) {

        /* If a path such as /usr/lib/systemd/systemd-foobar is specified, then this will check for an
         * environment variable SYSTEMD_FOOBAR_PATH and return it if set. */

        _cleanup_free_ char *s = strdup(fn);
        if (!s)
                return -ENOMEM;

        ascii_strupper(s);
        string_replace_char(s, '-', '_');

        if (!strextend(&s, "_PATH"))
                return -ENOMEM;

        const char *e;
        e = secure_getenv(s);
        if (!e)
                return -ENXIO;

        *ret = e;
        return 0;
}

int invoke_callout_binary(const char *path, char *const argv[]) {
        int r;

        assert(path);

        /* Just like execv(), but tries to execute the specified binary in the build dir instead, if known */

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;
        if (r == O_DIRECTORY) /* Uh? */
                return -EISDIR;

        const char *e;
        if (find_environment_binary(fn, &e) >= 0) {
                /* If there's an explicit environment variable set for this binary, prefer it */
                execv(e, argv);
                return -errno; /* The environment variable counts, let's fail otherwise */
        }

        _cleanup_free_ char *np = NULL;
        if (find_build_dir_binary(fn, &np) >= 0)
                execv(np, argv);

        execv(path, argv);
        return -errno;
}

int pin_callout_binary(const char *path) {
        int r;

        assert(path);

        /* Similar to invoke_callout_binary(), but pins (i.e. O_PATH opens) the binary instead of executing it. */

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;
        if (r == O_DIRECTORY) /* Uh? */
                return -EISDIR;

        const char *e;
        if (find_environment_binary(fn, &e) >= 0)
                return RET_NERRNO(open(e, O_CLOEXEC|O_PATH));

        _cleanup_free_ char *np = NULL;
        if (find_build_dir_binary(fn, &np) >= 0) {
                r = RET_NERRNO(open(np, O_CLOEXEC|O_PATH));
                if (r >= 0)
                        return r;
        }

        return RET_NERRNO(open(path, O_CLOEXEC|O_PATH));
}
