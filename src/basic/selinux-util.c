/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <syslog.h>

#if HAVE_SELINUX
#include <selinux/context.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#endif

#include "alloc-util.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "selinux-util.h"
#include "stdio-util.h"
#include "time-util.h"
#include "util.h"

#if HAVE_SELINUX
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, freecon);
DEFINE_TRIVIAL_CLEANUP_FUNC(context_t, context_free);

#define _cleanup_freecon_ _cleanup_(freeconp)
#define _cleanup_context_free_ _cleanup_(context_freep)

static int cached_use = -1;
static struct selabel_handle *label_hnd = NULL;

#define log_enforcing(...) log_full(security_getenforce() == 1 ? LOG_ERR : LOG_DEBUG, __VA_ARGS__)
#define log_enforcing_errno(r, ...) log_full_errno(security_getenforce() == 1 ? LOG_ERR : LOG_DEBUG, r, __VA_ARGS__)
#endif

bool mac_selinux_use(void) {
#if HAVE_SELINUX
        if (cached_use < 0)
                cached_use = is_selinux_enabled() > 0;

        return cached_use;
#else
        return false;
#endif
}

void mac_selinux_retest(void) {
#if HAVE_SELINUX
        cached_use = -1;
#endif
}

int mac_selinux_init(void) {
        int r = 0;

#if HAVE_SELINUX
        usec_t before_timestamp, after_timestamp;
        struct mallinfo before_mallinfo, after_mallinfo;

        if (label_hnd)
                return 0;

        if (!mac_selinux_use())
                return 0;

        before_mallinfo = mallinfo();
        before_timestamp = now(CLOCK_MONOTONIC);

        label_hnd = selabel_open(SELABEL_CTX_FILE, NULL, 0);
        if (!label_hnd) {
                log_enforcing_errno(errno, "Failed to initialize SELinux context: %m");
                r = security_getenforce() == 1 ? -errno : 0;
        } else  {
                char timespan[FORMAT_TIMESPAN_MAX];
                int l;

                after_timestamp = now(CLOCK_MONOTONIC);
                after_mallinfo = mallinfo();

                l = after_mallinfo.uordblks > before_mallinfo.uordblks ? after_mallinfo.uordblks - before_mallinfo.uordblks : 0;

                log_debug("Successfully loaded SELinux database in %s, size on heap is %iK.",
                          format_timespan(timespan, sizeof(timespan), after_timestamp - before_timestamp, 0),
                          (l+1023)/1024);
        }
#endif

        return r;
}

void mac_selinux_finish(void) {

#if HAVE_SELINUX
        if (!label_hnd)
                return;

        selabel_close(label_hnd);
        label_hnd = NULL;
#endif
}

int mac_selinux_fix(const char *path, LabelFixFlags flags) {

#if HAVE_SELINUX
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        _cleanup_freecon_ char* fcon = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;
        int r;

        assert(path);

        /* if mac_selinux_init() wasn't called before we are a NOOP */
        if (!label_hnd)
                return 0;

        /* Open the file as O_PATH, to pin it while we determine and adjust the label */
        fd = open(path, O_NOFOLLOW|O_CLOEXEC|O_PATH);
        if (fd < 0) {
                if ((flags & LABEL_IGNORE_ENOENT) && errno == ENOENT)
                        return 0;

                return -errno;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        if (selabel_lookup_raw(label_hnd, &fcon, path, st.st_mode) < 0) {
                r = -errno;

                /* If there's no label to set, then exit without warning */
                if (r == -ENOENT)
                        return 0;

                goto fail;
        }

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);
        if (setfilecon_raw(procfs_path, fcon) < 0) {
                _cleanup_freecon_ char *oldcon = NULL;

                r = -errno;

                /* If the FS doesn't support labels, then exit without warning */
                if (r == -EOPNOTSUPP)
                        return 0;

                /* It the FS is read-only and we were told to ignore failures caused by that, suppress error */
                if (r == -EROFS && (flags & LABEL_IGNORE_EROFS))
                        return 0;

                /* If the old label is identical to the new one, suppress any kind of error */
                if (getfilecon_raw(procfs_path, &oldcon) >= 0 && streq(fcon, oldcon))
                        return 0;

                goto fail;
        }

        return 0;

fail:
        log_enforcing_errno(r, "Unable to fix SELinux security context of %s: %m", path);
        if (security_getenforce() == 1)
                return r;
#endif

        return 0;
}

int mac_selinux_apply(const char *path, const char *label) {

#if HAVE_SELINUX
        if (!mac_selinux_use())
                return 0;

        assert(path);
        assert(label);

        if (setfilecon(path, label) < 0) {
                log_enforcing_errno(errno, "Failed to set SELinux security context %s on path %s: %m", label, path);
                if (security_getenforce() > 0)
                        return -errno;
        }
#endif
        return 0;
}

int mac_selinux_get_create_label_from_exe(const char *exe, char **label) {
        int r = -EOPNOTSUPP;

#if HAVE_SELINUX
        _cleanup_freecon_ char *mycon = NULL, *fcon = NULL;
        security_class_t sclass;

        assert(exe);
        assert(label);

        if (!mac_selinux_use())
                return -EOPNOTSUPP;

        r = getcon_raw(&mycon);
        if (r < 0)
                return -errno;

        r = getfilecon_raw(exe, &fcon);
        if (r < 0)
                return -errno;

        sclass = string_to_security_class("process");
        r = security_compute_create_raw(mycon, fcon, sclass, label);
        if (r < 0)
                return -errno;
#endif

        return r;
}

int mac_selinux_get_our_label(char **label) {
        int r = -EOPNOTSUPP;

        assert(label);

#if HAVE_SELINUX
        if (!mac_selinux_use())
                return -EOPNOTSUPP;

        r = getcon_raw(label);
        if (r < 0)
                return -errno;
#endif

        return r;
}

int mac_selinux_get_child_mls_label(int socket_fd, const char *exe, const char *exec_label, char **label) {
        int r = -EOPNOTSUPP;

#if HAVE_SELINUX
        _cleanup_freecon_ char *mycon = NULL, *peercon = NULL, *fcon = NULL;
        _cleanup_context_free_ context_t pcon = NULL, bcon = NULL;
        security_class_t sclass;
        const char *range = NULL;

        assert(socket_fd >= 0);
        assert(exe);
        assert(label);

        if (!mac_selinux_use())
                return -EOPNOTSUPP;

        r = getcon_raw(&mycon);
        if (r < 0)
                return -errno;

        r = getpeercon_raw(socket_fd, &peercon);
        if (r < 0)
                return -errno;

        if (!exec_label) {
                /* If there is no context set for next exec let's use context
                   of target executable */
                r = getfilecon_raw(exe, &fcon);
                if (r < 0)
                        return -errno;
        }

        bcon = context_new(mycon);
        if (!bcon)
                return -ENOMEM;

        pcon = context_new(peercon);
        if (!pcon)
                return -ENOMEM;

        range = context_range_get(pcon);
        if (!range)
                return -errno;

        r = context_range_set(bcon, range);
        if (r)
                return -errno;

        freecon(mycon);
        mycon = strdup(context_str(bcon));
        if (!mycon)
                return -ENOMEM;

        sclass = string_to_security_class("process");
        r = security_compute_create_raw(mycon, fcon, sclass, label);
        if (r < 0)
                return -errno;
#endif

        return r;
}

char* mac_selinux_free(char *label) {

#if HAVE_SELINUX
        if (!label)
                return NULL;

        if (!mac_selinux_use())
                return NULL;

        freecon(label);
#endif

        return NULL;
}

#if HAVE_SELINUX
static int selinux_create_file_prepare_abspath(const char *abspath, mode_t mode) {
        _cleanup_freecon_ char *filecon = NULL;
        int r;

        assert(abspath);
        assert(path_is_absolute(abspath));

        r = selabel_lookup_raw(label_hnd, &filecon, abspath, mode);
        if (r < 0) {
                /* No context specified by the policy? Proceed without setting it. */
                if (errno == ENOENT)
                        return 0;

                log_enforcing_errno(errno, "Failed to determine SELinux security context for %s: %m", abspath);
        } else {
                if (setfscreatecon_raw(filecon) >= 0)
                        return 0; /* Success! */

                log_enforcing_errno(errno, "Failed to set SELinux security context %s for %s: %m", filecon, abspath);
        }

        if (security_getenforce() > 0)
                return -errno;

        return 0;
}
#endif

int mac_selinux_create_file_prepare_at(int dirfd, const char *path, mode_t mode) {
        int r = 0;

#if HAVE_SELINUX
        _cleanup_free_ char *abspath = NULL;

        assert(path);

        if (!label_hnd)
                return 0;

        if (!path_is_absolute(path)) {
                _cleanup_free_ char *p = NULL;

                if (dirfd == AT_FDCWD)
                        r = safe_getcwd(&p);
                else
                        r = fd_get_path(dirfd, &p);
                if (r < 0)
                        return r;

                abspath = path_join(NULL, p, path);
                if (!abspath)
                        return -ENOMEM;

                path = abspath;
        }

        r = selinux_create_file_prepare_abspath(path, mode);
#endif
        return r;
}

int mac_selinux_create_file_prepare(const char *path, mode_t mode) {
        int r = 0;

#if HAVE_SELINUX
        _cleanup_free_ char *abspath = NULL;

        assert(path);

        if (!label_hnd)
                return 0;

        r = path_make_absolute_cwd(path, &abspath);
        if (r < 0)
                return r;

        r = selinux_create_file_prepare_abspath(abspath, mode);
#endif
        return r;
}

void mac_selinux_create_file_clear(void) {

#if HAVE_SELINUX
        PROTECT_ERRNO;

        if (!mac_selinux_use())
                return;

        setfscreatecon_raw(NULL);
#endif
}

int mac_selinux_create_socket_prepare(const char *label) {

#if HAVE_SELINUX
        if (!mac_selinux_use())
                return 0;

        assert(label);

        if (setsockcreatecon(label) < 0) {
                log_enforcing_errno(errno, "Failed to set SELinux security context %s for sockets: %m", label);

                if (security_getenforce() == 1)
                        return -errno;
        }
#endif

        return 0;
}

void mac_selinux_create_socket_clear(void) {

#if HAVE_SELINUX
        PROTECT_ERRNO;

        if (!mac_selinux_use())
                return;

        setsockcreatecon_raw(NULL);
#endif
}

int mac_selinux_bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {

        /* Binds a socket and label its file system object according to the SELinux policy */

#if HAVE_SELINUX
        _cleanup_freecon_ char *fcon = NULL;
        const struct sockaddr_un *un;
        bool context_changed = false;
        char *path;
        int r;

        assert(fd >= 0);
        assert(addr);
        assert(addrlen >= sizeof(sa_family_t));

        if (!label_hnd)
                goto skipped;

        /* Filter out non-local sockets */
        if (addr->sa_family != AF_UNIX)
                goto skipped;

        /* Filter out anonymous sockets */
        if (addrlen < offsetof(struct sockaddr_un, sun_path) + 1)
                goto skipped;

        /* Filter out abstract namespace sockets */
        un = (const struct sockaddr_un*) addr;
        if (un->sun_path[0] == 0)
                goto skipped;

        path = strndupa(un->sun_path, addrlen - offsetof(struct sockaddr_un, sun_path));

        if (path_is_absolute(path))
                r = selabel_lookup_raw(label_hnd, &fcon, path, S_IFSOCK);
        else {
                _cleanup_free_ char *newpath = NULL;

                r = path_make_absolute_cwd(path, &newpath);
                if (r < 0)
                        return r;

                r = selabel_lookup_raw(label_hnd, &fcon, newpath, S_IFSOCK);
        }

        if (r < 0) {
                /* No context specified by the policy? Proceed without setting it */
                if (errno == ENOENT)
                        goto skipped;

                log_enforcing_errno(errno, "Failed to determine SELinux security context for %s: %m", path);
                if (security_getenforce() > 0)
                        return -errno;

        } else {
                if (setfscreatecon_raw(fcon) < 0) {
                        log_enforcing_errno(errno, "Failed to set SELinux security context %s for %s: %m", fcon, path);
                        if (security_getenforce() > 0)
                                return -errno;
                } else
                        context_changed = true;
        }

        r = bind(fd, addr, addrlen) < 0 ? -errno : 0;

        if (context_changed)
                setfscreatecon_raw(NULL);

        return r;

skipped:
#endif
        if (bind(fd, addr, addrlen) < 0)
                return -errno;

        return 0;
}
