/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include "label.h"
#include "label-util.h"
#include "log.h"
#include "path-util.h"
#include "selinux-util.h"
#include "string-util.h"
#include "time-util.h"

#if HAVE_SELINUX
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(context_t, sym_context_free, context_freep, NULL);

typedef enum Initialized {
        UNINITIALIZED,
        INITIALIZED,
        LAZY_INITIALIZED,
} Initialized;

static int cached_use = -1;
static Initialized initialized = UNINITIALIZED;
static int last_policyload = 0;
static struct selabel_handle *label_hnd = NULL;
static bool have_status_page = false;

static int mac_selinux_label_pre(int dir_fd, const char *path, mode_t mode) {
        return mac_selinux_create_file_prepare_at(dir_fd, path, mode);
}

static int mac_selinux_label_post(int dir_fd, const char *path, bool created) {
        mac_selinux_create_file_clear();
        return 0;
}

static void *libselinux_dl = NULL;

DLSYM_PROTOTYPE(avc_open) = NULL;
DLSYM_PROTOTYPE(context_free) = NULL;
DLSYM_PROTOTYPE(context_new) = NULL;
DLSYM_PROTOTYPE(context_range_get) = NULL;
DLSYM_PROTOTYPE(context_range_set) = NULL;
DLSYM_PROTOTYPE(context_str) = NULL;
DLSYM_PROTOTYPE(fgetfilecon_raw) = NULL;
DLSYM_PROTOTYPE(fini_selinuxmnt) = NULL;
DLSYM_PROTOTYPE(freecon) = NULL;
DLSYM_PROTOTYPE(getcon_raw) = NULL;
DLSYM_PROTOTYPE(getfilecon_raw) = NULL;
DLSYM_PROTOTYPE(getpeercon_raw) = NULL;
DLSYM_PROTOTYPE(getpidcon_raw) = NULL;
DLSYM_PROTOTYPE(is_selinux_enabled) = NULL;
DLSYM_PROTOTYPE(security_compute_create_raw) = NULL;
DLSYM_PROTOTYPE(security_getenforce) = NULL;
DLSYM_PROTOTYPE(selabel_close) = NULL;
DLSYM_PROTOTYPE(selabel_lookup_raw) = NULL;
DLSYM_PROTOTYPE(selabel_open) = NULL;
DLSYM_PROTOTYPE(selinux_check_access) = NULL;
DLSYM_PROTOTYPE(selinux_getenforcemode) = NULL;
DLSYM_PROTOTYPE(selinux_init_load_policy) = NULL;
DLSYM_PROTOTYPE(selinux_path) = NULL;
DLSYM_PROTOTYPE(selinux_set_callback) = NULL;
DLSYM_PROTOTYPE(selinux_status_close) = NULL;
DLSYM_PROTOTYPE(selinux_status_getenforce) = NULL;
DLSYM_PROTOTYPE(selinux_status_open) = NULL;
DLSYM_PROTOTYPE(selinux_status_policyload) = NULL;
DLSYM_PROTOTYPE(setcon_raw) = NULL;
DLSYM_PROTOTYPE(setexeccon_raw) = NULL;
DLSYM_PROTOTYPE(setfilecon_raw) = NULL;
DLSYM_PROTOTYPE(setfscreatecon_raw) = NULL;
DLSYM_PROTOTYPE(setsockcreatecon_raw) = NULL;
DLSYM_PROTOTYPE(string_to_security_class) = NULL;

int dlopen_libselinux(void) {
        ELF_NOTE_DLOPEN("selinux",
                        "Support for SELinux",
                        ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED,
                        "libselinux.so.1");

        return dlopen_many_sym_or_warn(
                        &libselinux_dl,
                        "libselinux.so.1",
                        LOG_DEBUG,
                        DLSYM_ARG(avc_open),
                        DLSYM_ARG(context_free),
                        DLSYM_ARG(context_new),
                        DLSYM_ARG(context_range_get),
                        DLSYM_ARG(context_range_set),
                        DLSYM_ARG(context_str),
                        DLSYM_ARG(fgetfilecon_raw),
                        DLSYM_ARG(fini_selinuxmnt),
                        DLSYM_ARG(freecon),
                        DLSYM_ARG(getcon_raw),
                        DLSYM_ARG(getfilecon_raw),
                        DLSYM_ARG(getpeercon_raw),
                        DLSYM_ARG(getpidcon_raw),
                        DLSYM_ARG(is_selinux_enabled),
                        DLSYM_ARG(security_compute_create_raw),
                        DLSYM_ARG(security_getenforce),
                        DLSYM_ARG(selabel_close),
                        DLSYM_ARG(selabel_lookup_raw),
                        DLSYM_ARG(selabel_open),
                        DLSYM_ARG(selinux_check_access),
                        DLSYM_ARG(selinux_getenforcemode),
                        DLSYM_ARG(selinux_init_load_policy),
                        DLSYM_ARG(selinux_path),
                        DLSYM_ARG(selinux_set_callback),
                        DLSYM_ARG(selinux_status_close),
                        DLSYM_ARG(selinux_status_getenforce),
                        DLSYM_ARG(selinux_status_open),
                        DLSYM_ARG(selinux_status_policyload),
                        DLSYM_ARG(setcon_raw),
                        DLSYM_ARG(setexeccon_raw),
                        DLSYM_ARG(setfilecon_raw),
                        DLSYM_ARG(setfscreatecon_raw),
                        DLSYM_ARG(setsockcreatecon_raw),
                        DLSYM_ARG(string_to_security_class));
}
#endif

bool mac_selinux_use(void) {
#if HAVE_SELINUX
        if (_unlikely_(cached_use < 0)) {
                if (dlopen_libselinux() < 0)
                        return (cached_use = false);

                cached_use = sym_is_selinux_enabled() > 0;
                log_trace("SELinux enabled state cached to: %s", enabled_disabled(cached_use));
        }

        return cached_use;
#else
        return false;
#endif
}

bool mac_selinux_enforcing(void) {
        int r = 0;
#if HAVE_SELINUX

        /* If the SELinux status page has been successfully opened, retrieve the enforcing
         * status over it to avoid system calls in security_getenforce(). */

        if (dlopen_libselinux() < 0)
                return false;

        if (have_status_page)
                r = sym_selinux_status_getenforce();
        else
                r = sym_security_getenforce();

#endif
        return r != 0;
}

void mac_selinux_retest(void) {
#if HAVE_SELINUX
        cached_use = -1;
#endif
}

#if HAVE_SELINUX
static int open_label_db(void) {
        struct selabel_handle *hnd;
        /* Avoid maybe-uninitialized false positives */
        usec_t before_timestamp = USEC_INFINITY, after_timestamp = USEC_INFINITY;
        struct mallinfo2 before_mallinfo = {};
        int r;

        r = dlopen_libselinux();
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                before_mallinfo = mallinfo2();
                before_timestamp = now(CLOCK_MONOTONIC);
        }

        hnd = sym_selabel_open(SELABEL_CTX_FILE, NULL, 0);
        if (!hnd)
                return log_selinux_enforcing_errno(errno, "Failed to initialize SELinux labeling handle: %m");

        if (DEBUG_LOGGING) {
                after_timestamp = now(CLOCK_MONOTONIC);
                struct mallinfo2 after_mallinfo = mallinfo2();
                size_t l = LESS_BY(after_mallinfo.uordblks, before_mallinfo.uordblks);
                log_debug("Successfully loaded SELinux database in %s, size on heap is %zuK.",
                          FORMAT_TIMESPAN(after_timestamp - before_timestamp, 0),
                          DIV_ROUND_UP(l, 1024));
        }

        /* release memory after measurement */
        if (label_hnd)
                sym_selabel_close(label_hnd);
        label_hnd = TAKE_PTR(hnd);

        return 0;
}
#endif

static int selinux_init(bool force) {
#if HAVE_SELINUX
        static const LabelOps label_ops = {
                .pre = mac_selinux_label_pre,
                .post = mac_selinux_label_post,
        };
        int r;

        if (!mac_selinux_use())
                return 0;

        if (initialized == INITIALIZED)
                return 1;

        /* Internal call from this module? Unless we were explicitly configured to allow lazy initialization
         * bail out immediately. Pretend all is good, we do not want callers to abort here, for example at
         * early boot when the policy is being initialised. */
        if (!force && initialized != LAZY_INITIALIZED)
                return 1;

        mac_selinux_disable_logging();

        r = sym_selinux_status_open(/* netlink fallback= */ 1);
        if (r < 0) {
                if (!ERRNO_IS_PRIVILEGE(errno))
                        return log_selinux_enforcing_errno(errno, "Failed to open SELinux status page: %m");
                log_warning_errno(errno, "selinux_status_open() with netlink fallback failed, not checking for policy reloads: %m");
        } else if (r == 1)
                log_warning("selinux_status_open() failed to open the status page, using the netlink fallback.");
        else
                have_status_page = true;

        r = open_label_db();
        if (r < 0) {
                sym_selinux_status_close();
                return r;
        }

        r = label_ops_set(&label_ops);
        if (r < 0)
                return r;

        /* Save the current policyload sequence number, so mac_selinux_maybe_reload() does not trigger on
         * first call without any actual change. */
        last_policyload = sym_selinux_status_policyload();

        initialized = INITIALIZED;
        return 1;
#else
        return 0;
#endif
}

int mac_selinux_init(void) {
        return selinux_init(/* force= */ true);
}

int mac_selinux_init_lazy(void) {
#if HAVE_SELINUX
        if (initialized == UNINITIALIZED)
                initialized = LAZY_INITIALIZED; /* We'll be back later */
#endif

        return 0;
}

#if HAVE_SELINUX
static int mac_selinux_reload(int seqno) {
        log_debug("SELinux reload %d", seqno);

        (void) open_label_db();

        return 0;
}
#endif

void mac_selinux_maybe_reload(void) {
#if HAVE_SELINUX
        int policyload;

        if (!initialized)
                return;

        if (dlopen_libselinux() < 0)
                return;

        /* Do not use selinux_status_updated(3), cause since libselinux 3.2 selinux_check_access(3),
         * called in core and user instances, does also use it under the hood.
         * That can cause changes to be consumed by selinux_check_access(3) and not being visible here.
         * Also do not use selinux callbacks, selinux_set_callback(3), cause they are only automatically
         * invoked since libselinux 3.2 by selinux_status_updated(3).
         * Relevant libselinux commit: https://github.com/SELinuxProject/selinux/commit/05bdc03130d741e53e1fb45a958d0a2c184be503
         * Debian Bullseye is going to ship libselinux 3.1, so stay compatible for backports. */
        policyload = sym_selinux_status_policyload();
        if (policyload < 0) {
                log_debug_errno(errno, "Failed to get SELinux policyload from status page: %m");
                return;
        }

        if (policyload != last_policyload) {
                mac_selinux_reload(policyload);
                last_policyload = policyload;
        }
#endif
}

void mac_selinux_finish(void) {

#if HAVE_SELINUX
        if (label_hnd) {
                sym_selabel_close(label_hnd);
                label_hnd = NULL;
        }

        if (sym_selinux_status_close)
                sym_selinux_status_close();

        have_status_page = false;

        initialized = false;
#endif
}

#if HAVE_SELINUX
_printf_(2,3)
static int selinux_log_glue(int type, const char *fmt, ...) {
        return 0;
}
#endif

void mac_selinux_disable_logging(void) {
#if HAVE_SELINUX
        /* Turn off all of SELinux' own logging, we want to do that ourselves */
        if (dlopen_libselinux() < 0)
                return;

        sym_selinux_set_callback(SELINUX_CB_LOG, (const union selinux_callback) { .func_log = selinux_log_glue });
#endif
}

#if HAVE_SELINUX
static int selinux_fix_fd(
                int fd,
                const char *label_path,
                LabelFixFlags flags) {

        _cleanup_freecon_ char* fcon = NULL;
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(label_path);
        assert(path_is_absolute(label_path));

        if (fstat(fd, &st) < 0)
                return -errno;

        /* Check for policy reload so 'label_hnd' is kept up-to-date by callbacks */
        mac_selinux_maybe_reload();
        if (!label_hnd)
                return 0;

        if (sym_selabel_lookup_raw(label_hnd, &fcon, label_path, st.st_mode) < 0) {
                /* If there's no label to set, then exit without warning */
                if (errno == ENOENT)
                        return 0;

                return log_selinux_enforcing_errno(errno, "Unable to lookup intended SELinux security context of %s: %m", label_path);
        }

        r = RET_NERRNO(sym_setfilecon_raw(FORMAT_PROC_FD_PATH(fd), fcon));
        if (r < 0) {
                /* If the FS doesn't support labels, then exit without warning */
                if (ERRNO_IS_NOT_SUPPORTED(r))
                        return 0;

                /* It the FS is read-only and we were told to ignore failures caused by that, suppress error */
                if (r == -EROFS && (flags & LABEL_IGNORE_EROFS))
                        return 0;

                /* If the old label is identical to the new one, suppress any kind of error */
                _cleanup_freecon_ char *oldcon = NULL;
                if (sym_getfilecon_raw(FORMAT_PROC_FD_PATH(fd), &oldcon) >= 0 && streq_ptr(fcon, oldcon))
                        return 0;

                return log_selinux_enforcing_errno(r, "Unable to fix SELinux security context of %s: %m", label_path);
        }

        return 0;
}
#endif

int mac_selinux_fix_full(
                int atfd,
                const char *inode_path,
                const char *label_path,
                LabelFixFlags flags) {

        assert(atfd >= 0 || atfd == AT_FDCWD);
        assert(atfd >= 0 || inode_path);

#if HAVE_SELINUX
        _cleanup_close_ int opened_fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int inode_fd, r;

        r = selinux_init(/* force= */ false);
        if (r <= 0)
                return r;

        if (!label_hnd)
                return 0;

        if (inode_path) {
                opened_fd = openat(atfd, inode_path, O_NOFOLLOW|O_CLOEXEC|O_PATH);
                if (opened_fd < 0) {
                        if ((flags & LABEL_IGNORE_ENOENT) && errno == ENOENT)
                                return 0;

                        return -errno;
                }

                inode_fd = opened_fd;
        } else
                inode_fd = atfd;

        if (!label_path) {
                if (path_is_absolute(inode_path))
                        label_path = inode_path;
                else {
                        r = fd_get_path(inode_fd, &p);
                        if (r < 0)
                                return r;

                        label_path = p;
                }
        }

        return selinux_fix_fd(inode_fd, label_path, flags);
#else
        return 0;
#endif
}

int mac_selinux_apply(const char *path, const char *label) {

        assert(path);

#if HAVE_SELINUX
        int r;

        r = selinux_init(/* force= */ false);
        if (r <= 0)
                return r;

        assert(label);

        if (sym_setfilecon_raw(path, label) < 0)
                return log_selinux_enforcing_errno(errno, "Failed to set SELinux security context %s on path %s: %m", label, path);
#endif
        return 0;
}

int mac_selinux_apply_fd(int fd, const char *path, const char *label) {

        assert(fd >= 0);

#if HAVE_SELINUX
        int r;

        r = selinux_init(/* force= */ false);
        if (r <= 0)
                return r;

        assert(label);

        if (sym_setfilecon_raw(FORMAT_PROC_FD_PATH(fd), label) < 0)
                return log_selinux_enforcing_errno(errno, "Failed to set SELinux security context %s on path %s: %m", label, strna(path));
#endif
        return 0;
}

int mac_selinux_get_create_label_from_exe(const char *exe, char **ret_label) {
#if HAVE_SELINUX
        _cleanup_freecon_ char *mycon = NULL, *fcon = NULL;
        security_class_t sclass;
        int r;

        assert(exe);
        assert(ret_label);

        r = selinux_init(/* force= */ false);
        if (r < 0)
                return r;
        if (r == 0)
                return -EOPNOTSUPP;

        if (sym_getcon_raw(&mycon) < 0)
                return -errno;
        if (!mycon)
                return -EOPNOTSUPP;

        if (sym_getfilecon_raw(exe, &fcon) < 0)
                return -errno;
        if (!fcon)
                return -EOPNOTSUPP;

        sclass = sym_string_to_security_class("process");
        if (sclass == 0)
                return -ENOSYS;

        return RET_NERRNO(sym_security_compute_create_raw(mycon, fcon, sclass, ret_label));
#else
        return -EOPNOTSUPP;
#endif
}

int mac_selinux_get_our_label(char **ret_label) {
        assert(ret_label);

#if HAVE_SELINUX
        int r;

        r = selinux_init(/* force= */ false);
        if (r < 0)
                return r;
        if (r == 0)
                return -EOPNOTSUPP;

        _cleanup_freecon_ char *con = NULL;
        if (sym_getcon_raw(&con) < 0)
                return -errno;
        if (!con)
                return -EOPNOTSUPP;

        *ret_label = TAKE_PTR(con);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int mac_selinux_get_peer_label(int socket_fd, char **ret_label) {
        assert(socket_fd >= 0);
        assert(ret_label);

#if HAVE_SELINUX
        int r;

        r = selinux_init(/* force= */ false);
        if (r < 0)
                return r;
        if (r == 0)
                return -EOPNOTSUPP;

        _cleanup_freecon_ char *con = NULL;
        if (sym_getpeercon_raw(socket_fd, &con) < 0)
                return -errno;
        if (!con)
                return -EOPNOTSUPP;

        *ret_label = TAKE_PTR(con);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int mac_selinux_get_child_mls_label(int socket_fd, const char *exe, const char *exec_label, char **ret_label) {
#if HAVE_SELINUX
        _cleanup_freecon_ char *mycon = NULL, *peercon = NULL, *fcon = NULL;
        _cleanup_(context_freep) context_t pcon = NULL, bcon = NULL;
        const char *range = NULL, *bcon_str = NULL;
        security_class_t sclass;
        int r;

        assert(socket_fd >= 0);
        assert(exe);
        assert(ret_label);

        r = selinux_init(/* force= */ false);
        if (r < 0)
                return r;
        if (r == 0)
                return -EOPNOTSUPP;

        if (sym_getcon_raw(&mycon) < 0)
                return -errno;
        if (!mycon)
                return -EOPNOTSUPP;

        if (sym_getpeercon_raw(socket_fd, &peercon) < 0)
                return -errno;
        if (!peercon)
                return -EOPNOTSUPP;

        if (!exec_label) { /* If there is no context set for next exec let's use context of target executable */
                if (sym_getfilecon_raw(exe, &fcon) < 0)
                        return -errno;
                if (!fcon)
                        return -EOPNOTSUPP;
        }

        bcon = sym_context_new(mycon);
        if (!bcon)
                return -ENOMEM;

        pcon = sym_context_new(peercon);
        if (!pcon)
                return -ENOMEM;

        range = sym_context_range_get(pcon);
        if (!range)
                return -errno;

        if (sym_context_range_set(bcon, range) != 0)
                return -errno;

        bcon_str = sym_context_str(bcon);
        if (!bcon_str)
                return -ENOMEM;

        sclass = sym_string_to_security_class("process");
        if (sclass == 0)
                return -ENOSYS;

        return RET_NERRNO(sym_security_compute_create_raw(bcon_str, fcon, sclass, ret_label));
#else
        return -EOPNOTSUPP;
#endif
}

#if HAVE_SELINUX
static int selinux_create_file_prepare_abspath(const char *abspath, mode_t mode) {
        _cleanup_freecon_ char *filecon = NULL;
        int r;

        assert(abspath);
        assert(path_is_absolute(abspath));

        r = selinux_init(/* force= */ false);
        if (r <= 0)
                return r;

        /* Check for policy reload so 'label_hnd' is kept up-to-date by callbacks */
        mac_selinux_maybe_reload();
        if (!label_hnd)
                return 0;

        r = sym_selabel_lookup_raw(label_hnd, &filecon, abspath, mode);
        if (r < 0) {
                /* No context specified by the policy? Proceed without setting it. */
                if (errno == ENOENT)
                        return 0;

                return log_selinux_enforcing_errno(errno, "Failed to determine SELinux security context for %s: %m", abspath);
        }

        if (sym_setfscreatecon_raw(filecon) < 0)
                return log_selinux_enforcing_errno(errno, "Failed to set SELinux security context %s for %s: %m", filecon, abspath);

        return 0;
}
#endif

int mac_selinux_create_file_prepare_at(
                int dir_fd,
                const char *path,
                mode_t mode) {

#if HAVE_SELINUX
        _cleanup_free_ char *abspath = NULL;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        r = selinux_init(/* force= */ false);
        if (r <= 0)
                return r;

        if (!label_hnd)
                return 0;

        if (isempty(path) || !path_is_absolute(path)) {
                r = fd_get_path(dir_fd, &abspath);
                if (r < 0)
                        return r;

                if (!isempty(path) && !path_extend(&abspath, path))
                        return -ENOMEM;

                path = abspath;
        }

        return selinux_create_file_prepare_abspath(path, mode);
#else
        return 0;
#endif
}

int mac_selinux_create_file_prepare_label(const char *path, const char *label) {
#if HAVE_SELINUX
        int r;

        if (!label)
                return 0;

        r = selinux_init(/* force= */ false);
        if (r <= 0)
                return r;

        if (sym_setfscreatecon_raw(label) < 0)
                return log_selinux_enforcing_errno(errno, "Failed to set specified SELinux security context '%s' for '%s': %m", label, strna(path));
#endif
        return 0;
}

void mac_selinux_create_file_clear(void) {

#if HAVE_SELINUX
        PROTECT_ERRNO;

        if (selinux_init(/* force= */ false) <= 0)
                return;

        (void) sym_setfscreatecon_raw(NULL);
#endif
}

int mac_selinux_create_socket_prepare(const char *label) {

#if HAVE_SELINUX
        int r;

        assert(label);

        r = selinux_init(/* force= */ false);
        if (r <= 0)
                return r;

        if (sym_setsockcreatecon_raw(label) < 0)
                return log_selinux_enforcing_errno(errno, "Failed to set SELinux security context %s for sockets: %m", label);
#endif

        return 0;
}

void mac_selinux_create_socket_clear(void) {

#if HAVE_SELINUX
        PROTECT_ERRNO;

        if (selinux_init(/* force= */ false) <= 0)
                return;

        (void) sym_setsockcreatecon_raw(NULL);
#endif
}

int mac_selinux_bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {

        /* Binds a socket and label its file system object according to the SELinux policy */

#if HAVE_SELINUX
        _cleanup_freecon_ char *fcon = NULL;
        const struct sockaddr_un *un;
        bool context_changed = false;
        size_t sz;
        char *path;
        int r;

        assert(fd >= 0);
        assert(addr);
        assert(addrlen >= sizeof(sa_family_t));

        if (selinux_init(/* force= */ false) <= 0)
                goto skipped;

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

        sz = addrlen - offsetof(struct sockaddr_un, sun_path);
        if (sz > PATH_MAX)
                goto skipped;
        path = strndupa_safe(un->sun_path, sz);

        /* Check for policy reload so 'label_hnd' is kept up-to-date by callbacks */
        mac_selinux_maybe_reload();
        if (!label_hnd)
                goto skipped;

        if (path_is_absolute(path))
                r = sym_selabel_lookup_raw(label_hnd, &fcon, path, S_IFSOCK);
        else {
                _cleanup_free_ char *newpath = NULL;

                r = path_make_absolute_cwd(path, &newpath);
                if (r < 0)
                        return r;

                r = sym_selabel_lookup_raw(label_hnd, &fcon, newpath, S_IFSOCK);
        }

        if (r < 0) {
                /* No context specified by the policy? Proceed without setting it */
                if (errno == ENOENT)
                        goto skipped;

                r = log_selinux_enforcing_errno(errno, "Failed to determine SELinux security context for %s: %m", path);
                if (r < 0)
                        return r;
        } else {
                if (sym_setfscreatecon_raw(fcon) < 0) {
                        r = log_selinux_enforcing_errno(errno, "Failed to set SELinux security context %s for %s: %m", fcon, path);
                        if (r < 0)
                                return r;
                } else
                        context_changed = true;
        }

        r = RET_NERRNO(bind(fd, addr, addrlen));

        if (context_changed)
                (void) sym_setfscreatecon_raw(NULL);

        return r;

skipped:
#endif
        return RET_NERRNO(bind(fd, addr, addrlen));
}
