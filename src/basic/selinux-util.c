/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <malloc.h>
#include <sys/un.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/context.h>
#endif

#include "strv.h"
#include "path-util.h"
#include "selinux-util.h"

#ifdef HAVE_SELINUX
DEFINE_TRIVIAL_CLEANUP_FUNC(security_context_t, freecon);
DEFINE_TRIVIAL_CLEANUP_FUNC(context_t, context_free);

#define _cleanup_security_context_free_ _cleanup_(freeconp)
#define _cleanup_context_free_ _cleanup_(context_freep)

static int cached_use = -1;
static struct selabel_handle *label_hnd = NULL;

#define log_enforcing(...) log_full(security_getenforce() == 1 ? LOG_ERR : LOG_DEBUG, __VA_ARGS__)
#endif

bool mac_selinux_use(void) {
#ifdef HAVE_SELINUX
        if (cached_use < 0)
                cached_use = is_selinux_enabled() > 0;

        return cached_use;
#else
        return false;
#endif
}

void mac_selinux_retest(void) {
#ifdef HAVE_SELINUX
        cached_use = -1;
#endif
}

int mac_selinux_init(const char *prefix) {
        int r = 0;

#ifdef HAVE_SELINUX
        usec_t before_timestamp, after_timestamp;
        struct mallinfo before_mallinfo, after_mallinfo;

        if (!mac_selinux_use())
                return 0;

        if (label_hnd)
                return 0;

        before_mallinfo = mallinfo();
        before_timestamp = now(CLOCK_MONOTONIC);

        if (prefix) {
                struct selinux_opt options[] = {
                        { .type = SELABEL_OPT_SUBSET, .value = prefix },
                };

                label_hnd = selabel_open(SELABEL_CTX_FILE, options, ELEMENTSOF(options));
        } else
                label_hnd = selabel_open(SELABEL_CTX_FILE, NULL, 0);

        if (!label_hnd) {
                log_enforcing("Failed to initialize SELinux context: %m");
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

#ifdef HAVE_SELINUX
        if (!label_hnd)
                return;

        selabel_close(label_hnd);
        label_hnd = NULL;
#endif
}

int mac_selinux_fix(const char *path, bool ignore_enoent, bool ignore_erofs) {

#ifdef HAVE_SELINUX
        struct stat st;
        int r;

        assert(path);

        /* if mac_selinux_init() wasn't called before we are a NOOP */
        if (!label_hnd)
                return 0;

        r = lstat(path, &st);
        if (r >= 0) {
                _cleanup_security_context_free_ security_context_t fcon = NULL;

                r = selabel_lookup_raw(label_hnd, &fcon, path, st.st_mode);

                /* If there's no label to set, then exit without warning */
                if (r < 0 && errno == ENOENT)
                        return 0;

                if (r >= 0) {
                        r = lsetfilecon(path, fcon);

                        /* If the FS doesn't support labels, then exit without warning */
                        if (r < 0 && errno == EOPNOTSUPP)
                                return 0;
                }
        }

        if (r < 0) {
                /* Ignore ENOENT in some cases */
                if (ignore_enoent && errno == ENOENT)
                        return 0;

                if (ignore_erofs && errno == EROFS)
                        return 0;

                log_enforcing("Unable to fix SELinux security context of %s: %m", path);
                if (security_getenforce() == 1)
                        return -errno;
        }
#endif

        return 0;
}

int mac_selinux_apply(const char *path, const char *label) {

#ifdef HAVE_SELINUX
        assert(path);
        assert(label);

        if (!mac_selinux_use())
                return 0;

        if (setfilecon(path, (security_context_t) label) < 0) {
                log_enforcing("Failed to set SELinux security context %s on path %s: %m", label, path);
                if (security_getenforce() == 1)
                        return -errno;
        }
#endif
        return 0;
}

int mac_selinux_get_create_label_from_exe(const char *exe, char **label) {
        int r = -EOPNOTSUPP;

#ifdef HAVE_SELINUX
        _cleanup_security_context_free_ security_context_t mycon = NULL, fcon = NULL;
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
        r = security_compute_create(mycon, fcon, sclass, (security_context_t *) label);
        if (r < 0)
                return -errno;
#endif

        return r;
}

int mac_selinux_get_our_label(char **label) {
        int r = -EOPNOTSUPP;

        assert(label);

#ifdef HAVE_SELINUX
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

#ifdef HAVE_SELINUX
        _cleanup_security_context_free_ security_context_t mycon = NULL, peercon = NULL, fcon = NULL;
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

        r = getpeercon(socket_fd, &peercon);
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
        r = security_compute_create(mycon, fcon, sclass, (security_context_t *) label);
        if (r < 0)
                return -errno;
#endif

        return r;
}

void mac_selinux_free(char *label) {

#ifdef HAVE_SELINUX
        if (!mac_selinux_use())
                return;

        freecon((security_context_t) label);
#endif
}

int mac_selinux_create_file_prepare(const char *path, mode_t mode) {
        int r = 0;

#ifdef HAVE_SELINUX
        _cleanup_security_context_free_ security_context_t filecon = NULL;

        assert(path);

        if (!label_hnd)
                return 0;

        if (path_is_absolute(path))
                r = selabel_lookup_raw(label_hnd, &filecon, path, mode);
        else {
                _cleanup_free_ char *newpath;

                newpath = path_make_absolute_cwd(path);
                if (!newpath)
                        return -ENOMEM;

                r = selabel_lookup_raw(label_hnd, &filecon, newpath, mode);
        }

        /* No context specified by the policy? Proceed without setting it. */
        if (r < 0 && errno == ENOENT)
                return 0;

        if (r < 0)
                r = -errno;
        else {
                r = setfscreatecon(filecon);
                if (r < 0) {
                        log_enforcing("Failed to set SELinux security context %s for %s: %m", filecon, path);
                        r = -errno;
                }
        }

        if (r < 0 && security_getenforce() == 0)
                r = 0;
#endif

        return r;
}

void mac_selinux_create_file_clear(void) {

#ifdef HAVE_SELINUX
        PROTECT_ERRNO;

        if (!mac_selinux_use())
                return;

        setfscreatecon(NULL);
#endif
}

int mac_selinux_create_socket_prepare(const char *label) {

#ifdef HAVE_SELINUX
        if (!mac_selinux_use())
                return 0;

        assert(label);

        if (setsockcreatecon((security_context_t) label) < 0) {
                log_enforcing("Failed to set SELinux security context %s for sockets: %m", label);

                if (security_getenforce() == 1)
                        return -errno;
        }
#endif

        return 0;
}

void mac_selinux_create_socket_clear(void) {

#ifdef HAVE_SELINUX
        PROTECT_ERRNO;

        if (!mac_selinux_use())
                return;

        setsockcreatecon(NULL);
#endif
}

int mac_selinux_bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {

        /* Binds a socket and label its file system object according to the SELinux policy */

#ifdef HAVE_SELINUX
        _cleanup_security_context_free_ security_context_t fcon = NULL;
        const struct sockaddr_un *un;
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
        if (addrlen < sizeof(sa_family_t) + 1)
                goto skipped;

        /* Filter out abstract namespace sockets */
        un = (const struct sockaddr_un*) addr;
        if (un->sun_path[0] == 0)
                goto skipped;

        path = strndupa(un->sun_path, addrlen - offsetof(struct sockaddr_un, sun_path));

        if (path_is_absolute(path))
                r = selabel_lookup_raw(label_hnd, &fcon, path, S_IFSOCK);
        else {
                _cleanup_free_ char *newpath;

                newpath = path_make_absolute_cwd(path);
                if (!newpath)
                        return -ENOMEM;

                r = selabel_lookup_raw(label_hnd, &fcon, newpath, S_IFSOCK);
        }

        if (r == 0)
                r = setfscreatecon(fcon);

        if (r < 0 && errno != ENOENT) {
                log_enforcing("Failed to set SELinux security context %s for %s: %m", fcon, path);

                if (security_getenforce() == 1) {
                        r = -errno;
                        goto finish;
                }
        }

        r = bind(fd, addr, addrlen);
        if (r < 0)
                r = -errno;

finish:
        setfscreatecon(NULL);
        return r;

skipped:
#endif
        return bind(fd, addr, addrlen) < 0 ? -errno : 0;
}
