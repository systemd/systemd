/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>

#if HAVE_SELINUX
#include <selinux/avc.h>
#include <selinux/context.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#endif

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "selinux-util.h"
#include "stdio-util.h"
#include "time-util.h"

#if HAVE_SELINUX
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(context_t, context_free, NULL);
#define _cleanup_context_free_ _cleanup_(context_freep)

static int mac_selinux_reload(int seqno);

static int cached_use = -1;
static bool initialized = false;
static int (*enforcing_status_func)(void) = security_getenforce;
static int last_policyload = 0;
static struct selabel_handle *label_hnd = NULL;

#define log_enforcing(...)                                              \
        log_full(mac_selinux_enforcing() ? LOG_ERR : LOG_WARNING, __VA_ARGS__)

#define log_enforcing_errno(error, ...)                                 \
        ({                                                              \
                bool _enforcing = mac_selinux_enforcing();              \
                int _level = _enforcing ? LOG_ERR : LOG_WARNING;        \
                int _e = (error);                                       \
                                                                        \
                int _r = (log_get_max_level() >= LOG_PRI(_level))       \
                        ? log_internal(_level, _e, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
                _enforcing ? _r : 0;                                    \
        })
#endif

bool mac_selinux_use(void) {
#if HAVE_SELINUX
        if (_unlikely_(cached_use < 0)) {
                cached_use = is_selinux_enabled() > 0;
                log_debug("SELinux enabled state cached to: %s", cached_use ? "enabled" : "disabled");
        }

        return cached_use;
#else
        return false;
#endif
}

bool mac_selinux_enforcing(void) {
#if HAVE_SELINUX
        return enforcing_status_func() != 0;
#else
        return false;
#endif
}

void mac_selinux_retest(void) {
#if HAVE_SELINUX
        cached_use = -1;
#endif
}

#if HAVE_SELINUX
#  if HAVE_MALLINFO
static struct mallinfo mallinfo_nowarn(void) {
        /* glibc has deprecated mallinfo(), but the replacement malloc_info() returns an XML blob ;=[ */
DISABLE_WARNING_DEPRECATED_DECLARATIONS
        return mallinfo();
REENABLE_WARNING
}
#  else
#    warning "mallinfo() is missing, add mallinfo2() supported instead."
#  endif

static int open_label_db(void) {
        struct selabel_handle *hnd;
        usec_t before_timestamp, after_timestamp;
        char timespan[FORMAT_TIMESPAN_MAX];

#  if HAVE_MALLINFO
        struct mallinfo before_mallinfo = mallinfo_nowarn();
#  endif
        before_timestamp = now(CLOCK_MONOTONIC);

        hnd = selabel_open(SELABEL_CTX_FILE, NULL, 0);
        if (!hnd)
                return log_enforcing_errno(errno, "Failed to initialize SELinux labeling handle: %m");

        after_timestamp = now(CLOCK_MONOTONIC);
#  if HAVE_MALLINFO
        struct mallinfo after_mallinfo = mallinfo_nowarn();
        int l = after_mallinfo.uordblks > before_mallinfo.uordblks ? after_mallinfo.uordblks - before_mallinfo.uordblks : 0;
        log_debug("Successfully loaded SELinux database in %s, size on heap is %iK.",
                  format_timespan(timespan, sizeof(timespan), after_timestamp - before_timestamp, 0),
                  DIV_ROUND_UP(l, 1024));
#  else
        log_debug("Successfully loaded SELinux database in %s.",
                  format_timespan(timespan, sizeof(timespan), after_timestamp - before_timestamp, 0));
#  endif

        /* release memory after measurement */
        if (label_hnd)
                selabel_close(label_hnd);
        label_hnd = TAKE_PTR(hnd);

        return 0;
}
#endif

int mac_selinux_init(void) {
#if HAVE_SELINUX
        int r;
        bool have_status_page = false;

        if (initialized)
                return 0;

        if (!mac_selinux_use())
                return 0;

        r = selinux_status_open(/* netlink fallback */ 1);
        if (r < 0) {
                if (!ERRNO_IS_PRIVILEGE(errno))
                        return log_enforcing_errno(errno, "Failed to open SELinux status page: %m");
                log_warning_errno(errno, "selinux_status_open() with netlink fallback failed, not checking for policy reloads: %m");
        } else if (r == 1)
                log_warning("selinux_status_open() failed to open the status page, using the netlink fallback.");
        else
                have_status_page = true;

        r = open_label_db();
        if (r < 0) {
                selinux_status_close();
                return r;
        }

        /* Save the current policyload sequence number, so mac_selinux_maybe_reload() does not trigger on
         * first call without any actual change. */
        last_policyload = selinux_status_policyload();

        if (have_status_page)
                /* Now that the SELinux status page has been successfully opened, retrieve the enforcing
                 * status over it (to avoid system calls in security_getenforce()). */
                enforcing_status_func = selinux_status_getenforce;

        initialized = true;
#endif
        return 0;
}

void mac_selinux_maybe_reload(void) {
#if HAVE_SELINUX
        int r;

        if (!initialized)
                return;

        r = selinux_status_updated();
        if (r < 0)
                log_debug_errno(errno, "Failed to update SELinux from status page: %m");
        if (r > 0) {
                int policyload;

                log_debug("SELinux status page update");

                /* from libselinux > 3.1 callbacks gets automatically called, see
                   https://github.com/SELinuxProject/selinux/commit/05bdc03130d741e53e1fb45a958d0a2c184be503 */

                /* only reload on policy changes, not enforcing status changes */
                policyload = selinux_status_policyload();
                if (policyload != last_policyload) {
                        mac_selinux_reload(policyload);
                        last_policyload = policyload;
                }
        }
#endif
}

void mac_selinux_finish(void) {

#if HAVE_SELINUX
        if (label_hnd) {
                selabel_close(label_hnd);
                label_hnd = NULL;
        }

        enforcing_status_func = security_getenforce;

        selinux_status_close();

        initialized = false;
#endif
}

#if HAVE_SELINUX
static int mac_selinux_reload(int seqno) {
        log_debug("SELinux reload %d", seqno);

        (void) open_label_db();

        return 0;
}
#endif

int mac_selinux_fix_container(const char *path, const char *inside_path, LabelFixFlags flags) {

        assert(path);
        assert(inside_path);

#if HAVE_SELINUX
        _cleanup_close_ int fd = -1;

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

        return mac_selinux_fix_container_fd(fd, path, inside_path, flags);
#endif

        return 0;
}

int mac_selinux_fix_container_fd(int fd, const char *path, const char *inside_path, LabelFixFlags flags) {

        assert(fd >= 0);
        assert(inside_path);

#if HAVE_SELINUX
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        _cleanup_freecon_ char* fcon = NULL;
        struct stat st;
        int r;

        /* if mac_selinux_init() wasn't called before we are a NOOP */
        if (!label_hnd)
                return 0;

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Check for policy reload so 'label_hnd' is kept up-to-date by callbacks */
        mac_selinux_maybe_reload();
        if (!label_hnd)
                return 0;

        if (selabel_lookup_raw(label_hnd, &fcon, inside_path, st.st_mode) < 0) {
                /* If there's no label to set, then exit without warning */
                if (errno == ENOENT)
                        return 0;

                r = -errno;
                goto fail;
        }

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);
        if (setfilecon_raw(procfs_path, fcon) < 0) {
                _cleanup_freecon_ char *oldcon = NULL;

                /* If the FS doesn't support labels, then exit without warning */
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return 0;

                /* It the FS is read-only and we were told to ignore failures caused by that, suppress error */
                if (errno == EROFS && (flags & LABEL_IGNORE_EROFS))
                        return 0;

                r = -errno;

                /* If the old label is identical to the new one, suppress any kind of error */
                if (getfilecon_raw(procfs_path, &oldcon) >= 0 && streq(fcon, oldcon))
                        return 0;

                goto fail;
        }

        return 0;

fail:
        return log_enforcing_errno(r, "Unable to fix SELinux security context of %s (%s): %m", strna(path), strna(inside_path));
#endif

        return 0;
}

int mac_selinux_apply(const char *path, const char *label) {

        assert(path);

#if HAVE_SELINUX
        if (!mac_selinux_use())
                return 0;

        assert(label);

        if (setfilecon(path, label) < 0)
                return log_enforcing_errno(errno, "Failed to set SELinux security context %s on path %s: %m", label, path);
#endif
        return 0;
}

int mac_selinux_apply_fd(int fd, const char *path, const char *label) {

        assert(fd >= 0);

#if HAVE_SELINUX
        if (!mac_selinux_use())
                return 0;

        assert(label);

        if (fsetfilecon(fd, label) < 0)
                return log_enforcing_errno(errno, "Failed to set SELinux security context %s on path %s: %m", label, strna(path));
#endif
        return 0;
}

int mac_selinux_get_create_label_from_exe(const char *exe, char **label) {
#if HAVE_SELINUX
        _cleanup_freecon_ char *mycon = NULL, *fcon = NULL;
        security_class_t sclass;
        int r;

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
        if (sclass == 0)
                return -ENOSYS;

        r = security_compute_create_raw(mycon, fcon, sclass, label);
        if (r < 0)
                return -errno;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int mac_selinux_get_our_label(char **label) {
#if HAVE_SELINUX
        int r;

        assert(label);

        if (!mac_selinux_use())
                return -EOPNOTSUPP;

        r = getcon_raw(label);
        if (r < 0)
                return -errno;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int mac_selinux_get_child_mls_label(int socket_fd, const char *exe, const char *exec_label, char **label) {
#if HAVE_SELINUX
        _cleanup_freecon_ char *mycon = NULL, *peercon = NULL, *fcon = NULL;
        _cleanup_context_free_ context_t pcon = NULL, bcon = NULL;
        security_class_t sclass;
        const char *range = NULL;
        int r;

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
        if (sclass == 0)
                return -ENOSYS;

        r = security_compute_create_raw(mycon, fcon, sclass, label);
        if (r < 0)
                return -errno;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

char* mac_selinux_free(char *label) {

#if HAVE_SELINUX
        freecon(label);
#else
        assert(!label);
#endif

        return NULL;
}

#if HAVE_SELINUX
static int selinux_create_file_prepare_abspath(const char *abspath, mode_t mode) {
        _cleanup_freecon_ char *filecon = NULL;
        int r;

        assert(abspath);
        assert(path_is_absolute(abspath));

        /* Check for policy reload so 'label_hnd' is kept up-to-date by callbacks */
        mac_selinux_maybe_reload();
        if (!label_hnd)
                return 0;

        r = selabel_lookup_raw(label_hnd, &filecon, abspath, mode);
        if (r < 0) {
                /* No context specified by the policy? Proceed without setting it. */
                if (errno == ENOENT)
                        return 0;

                return log_enforcing_errno(errno, "Failed to determine SELinux security context for %s: %m", abspath);
        }

        if (setfscreatecon_raw(filecon) < 0)
                return log_enforcing_errno(errno, "Failed to set SELinux security context %s for %s: %m", filecon, abspath);

        return 0;
}
#endif

int mac_selinux_create_file_prepare_at(int dirfd, const char *path, mode_t mode) {
#if HAVE_SELINUX
        _cleanup_free_ char *abspath = NULL;
        int r;

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

                path = abspath = path_join(p, path);
                if (!path)
                        return -ENOMEM;
        }

        return selinux_create_file_prepare_abspath(path, mode);
#else
        return 0;
#endif
}

int mac_selinux_create_file_prepare(const char *path, mode_t mode) {
#if HAVE_SELINUX
        int r;

        _cleanup_free_ char *abspath = NULL;

        assert(path);

        if (!label_hnd)
                return 0;

        r = path_make_absolute_cwd(path, &abspath);
        if (r < 0)
                return r;

        return selinux_create_file_prepare_abspath(abspath, mode);
#else
        return 0;
#endif
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
        assert(label);

        if (!mac_selinux_use())
                return 0;

        if (setsockcreatecon(label) < 0)
                return log_enforcing_errno(errno, "Failed to set SELinux security context %s for sockets: %m", label);
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

        /* Check for policy reload so 'label_hnd' is kept up-to-date by callbacks */
        mac_selinux_maybe_reload();
        if (!label_hnd)
                goto skipped;

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

                r = log_enforcing_errno(errno, "Failed to determine SELinux security context for %s: %m", path);
                if (r < 0)
                        return r;
        } else {
                if (setfscreatecon_raw(fcon) < 0) {
                        r = log_enforcing_errno(errno, "Failed to set SELinux security context %s for %s: %m", fcon, path);
                        if (r < 0)
                                return r;
                } else
                        context_changed = true;
        }

        r = bind(fd, addr, addrlen) < 0 ? -errno : 0;

        if (context_changed)
                (void) setfscreatecon_raw(NULL);

        return r;

skipped:
#endif
        if (bind(fd, addr, addrlen) < 0)
                return -errno;

        return 0;
}
