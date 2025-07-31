/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#include "alloc-util.h"
#include "base-filesystem.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "umask-util.h"
#include "user-util.h"

typedef enum BaseFilesystemFlags {
        BASE_FILESYSTEM_IGNORE_ON_FAILURE = 1 << 0,
        BASE_FILESYSTEM_EMPTY_MARKER      = 1 << 1, /* If this is missing, then we are booting on an empty filesystem - see comment below */
        BASE_FILESYSTEM_EMPTY_ONLY        = 1 << 2, /* If booting on an empty filesystem create this, otherwise skip it - see comment below */
} BaseFilesystemFlags;

typedef struct BaseFilesystem {
        const char *dir;      /* directory or symlink to create */
        mode_t mode;
        const char *target;   /* if non-NULL create as symlink to this target */
        const char *exists;   /* conditionalize this entry on existence of this file */
        BaseFilesystemFlags flags; /* various modifiers for behaviour on creation */
} BaseFilesystem;

/* Note that as entries are processed in order, entries with BASE_FILESYSTEM_EMPTY_MARKER must be listed
 * before entries with BASE_FILESYSTEM_EMPTY_ONLY. */
static const BaseFilesystem table[] = {
        { "bin",      0, "usr/bin\0",                  NULL,                        BASE_FILESYSTEM_EMPTY_MARKER      },
        { "lib",      0, "usr/lib\0",                  NULL,                        BASE_FILESYSTEM_EMPTY_MARKER      },
        { "root",  0750, NULL,                         NULL,                        BASE_FILESYSTEM_IGNORE_ON_FAILURE },
        { "sbin",     0, "usr/sbin\0",                 NULL,                        BASE_FILESYSTEM_EMPTY_MARKER      },
        { "usr",   0755, NULL,                         NULL },
        { "var",   0755, NULL,                         NULL },
        { "etc",   0755, NULL,                         NULL },
        { "proc",  0555, NULL,                         NULL,                        BASE_FILESYSTEM_IGNORE_ON_FAILURE },
        { "sys",   0555, NULL,                         NULL,                        BASE_FILESYSTEM_IGNORE_ON_FAILURE },
        { "dev",   0555, NULL,                         NULL,                        BASE_FILESYSTEM_IGNORE_ON_FAILURE },
        { "run",   0555, NULL,                         NULL,                        BASE_FILESYSTEM_IGNORE_ON_FAILURE },
        /* We don't add /tmp/ here for now (even though it's necessary for regular operation), because we
         * want to support both cases where /tmp/ is a mount of its own (in which case we probably should set
         * the mode to 1555, to indicate that no one should write to it, not even root) and when it's part of
         * the rootfs (in which case we should set mode 1777), and we simply don't know what's right. */

        /* Various architecture ABIs define the path to the dynamic loader via the /lib64/ subdirectory of
         * the root directory. When booting from an otherwise empty root file system (where only /usr/ has
         * been mounted into) it is thus necessary to create a symlink pointing to the right subdirectory of
         * /usr/ first — otherwise we couldn't invoke any dynamic binary. Let's detect this case here, and
         * create the symlink as needed should it be missing. We prefer doing this consistently with Debian's
         * multiarch logic, but support Fedora-style and Arch-style multilib too. */
#if defined(__aarch64__)
        /* aarch64 ELF ABI actually says dynamic loader is in /lib/, but Fedora puts it in /lib64/ anyway and
         * just symlinks /lib/ld-linux-aarch64.so.1 to ../lib64/ld-linux-aarch64.so.1. For this to work
         * correctly, /lib64/ must be symlinked to /usr/lib64/. On the flip side, we must not create /lib64/
         * on Debian and derivatives as they expect the target to be different from what Fedora et al. use,
         * which is problematic for example when nspawn from some other distribution boots a Debian
         * container with only /usr/, so we only create this symlink when at least one other symlink is
         * missing, and let the image builder/package manager worry about not creating incomplete persistent
         * filesystem hierarchies instead. The key purpose of this code is to ensure we can bring up a system
         * with a volatile root filesystem after all. */
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld-linux-aarch64.so.1",       BASE_FILESYSTEM_EMPTY_ONLY        },
#  define KNOW_LIB64_DIRS 1
#elif defined(__alpha__)
#elif defined(__arc__) || defined(__tilegx__)
#elif defined(__arm__)
        /* No /lib64 on arm. The linker is /lib/ld-linux-armhf.so.3. */
#  define KNOW_LIB64_DIRS 1
#elif defined(__i386__) || defined(__x86_64__)
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld-linux-x86-64.so.2" },
#  define KNOW_LIB64_DIRS 1
#elif defined(__ia64__)
#elif defined(__loongarch_lp64)
#  define KNOW_LIB64_DIRS 1
#  if defined(__loongarch_double_float)
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld-linux-loongarch-lp64d.so.1" },
#  elif defined(__loongarch_single_float)
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld-linux-loongarch-lp64f.so.1" },
#  elif defined(__loongarch_soft_float)
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld-linux-loongarch-lp64s.so.1" },
#  else
#    error "Unknown LoongArch ABI"
#  endif
#elif defined(__m68k__)
        /* No link needed. */
#  define KNOW_LIB64_DIRS 1
#elif defined(_MIPS_SIM)
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#  else
#    error "Unknown MIPS ABI"
#  endif
#elif defined(__powerpc__)
#  if defined(__PPC64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld64.so.2" },
#    define KNOW_LIB64_DIRS 1
#  elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        /* powerpc64-linux-gnu */
#  else
        /* powerpc-linux-gnu */
#  endif
#elif defined(__riscv)
#  if __riscv_xlen == 32
#  elif __riscv_xlen == 64
        /* Same situation as for aarch64 */
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld-linux-riscv64-lp64d.so.1", BASE_FILESYSTEM_EMPTY_ONLY        },
#    define KNOW_LIB64_DIRS 1
#  else
#    error "Unknown RISC-V ABI"
#  endif
#elif defined(__s390x__)
        /* Same situation as for aarch64 */
        { "lib64",    0, "usr/lib64\0"
                         "usr/lib\0",                "ld-lsb-s390x.so.3",           BASE_FILESYSTEM_EMPTY_ONLY        },
#    define KNOW_LIB64_DIRS 1
#elif defined(__s390__)
        /* s390-linux-gnu */
#elif defined(__sparc__)
#endif
        /* gcc doesn't allow pragma to be used within constructs, hence log about this separately below */
};

#ifndef KNOW_LIB64_DIRS
#  pragma message "Please add an entry above specifying whether your architecture uses /lib64/, /lib32/, or no such links."
#endif

int base_filesystem_create_fd(int fd, const char *root, uid_t uid, gid_t gid) {
        bool empty_fs = false;
        int r;

        assert(fd >= 0);
        assert(root);

        /* The "root" parameter is decoration only – it's only used as part of log messages */

        FOREACH_ELEMENT(i, table) {
                if (FLAGS_SET(i->flags, BASE_FILESYSTEM_EMPTY_ONLY) && !empty_fs)
                        continue;

                if (faccessat(fd, i->dir, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                        continue;

                if (FLAGS_SET(i->flags, BASE_FILESYSTEM_EMPTY_MARKER))
                        empty_fs = true;

                if (i->target) { /* Create as symlink? */
                        const char *target = NULL;

                        /* check if one of the targets exists */
                        NULSTR_FOREACH(s, i->target) {
                                if (faccessat(fd, s, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                                        continue;

                                /* check if a specific file exists at the target path */
                                if (i->exists) {
                                        _cleanup_free_ char *p = NULL;

                                        p = path_join(s, i->exists);
                                        if (!p)
                                                return log_oom();

                                        if (faccessat(fd, p, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                                                continue;
                                }

                                target = s;
                                break;
                        }

                        if (!target)
                                continue;

                        r = RET_NERRNO(symlinkat(target, fd, i->dir));
                } else {
                        /* Create as directory. */
                        WITH_UMASK(0000)
                                r = RET_NERRNO(mkdirat(fd, i->dir, i->mode));
                }
                if (r < 0) {
                        bool ignore = IN_SET(r, -EEXIST, -EROFS) || FLAGS_SET(i->flags, BASE_FILESYSTEM_IGNORE_ON_FAILURE);
                        log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r,
                                       "Failed to create %s/%s: %m", root, i->dir);
                        if (ignore)
                                continue;

                        return r;
                }

                if (uid_is_valid(uid) || gid_is_valid(gid))
                        if (fchownat(fd, i->dir, uid, gid, AT_SYMLINK_NOFOLLOW) < 0)
                                return log_error_errno(errno, "Failed to chown %s/%s: %m", root, i->dir);
        }

        return 0;
}

int base_filesystem_create(const char *root, uid_t uid, gid_t gid) {
        _cleanup_close_ int fd = -EBADF;

        fd = open(ASSERT_PTR(root), O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open root file system: %m");

        return base_filesystem_create_fd(fd, root, uid, gid);
}
