/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "label.h"
#include "util.h"

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>

static struct selabel_handle *label_hnd = NULL;

static inline bool use_selinux(void) {
        static int use_selinux_ind = -1;

        if (use_selinux_ind < 0)
                use_selinux_ind = is_selinux_enabled() > 0;

        return use_selinux_ind;
}

static int label_get_file_label_from_path(
                const char *label,
                const char *path,
                const char *class,
                security_context_t *fcon) {

        security_context_t dir_con = NULL;
        security_class_t sclass;
        int r = 0;

        r = getfilecon(path, &dir_con);
        if (r >= 0) {
                r = -1;
                errno = EINVAL;

                if ((sclass = string_to_security_class(class)) != 0)
                        r = security_compute_create((security_context_t) label, dir_con, sclass, fcon);
        }
        if (r < 0)
                r = -errno;

        freecon(dir_con);
        return r;
}

#endif

int label_init(void) {
        int r = 0;

#ifdef HAVE_SELINUX

        if (!use_selinux())
                return 0;

        label_hnd = selabel_open(SELABEL_CTX_FILE, NULL, 0);
        if (!label_hnd) {
                log_full(security_getenforce() == 1 ? LOG_ERR : LOG_DEBUG,
                         "Failed to initialize SELinux context: %m");
                r = (security_getenforce() == 1) ? -errno : 0;
        }
#endif

        return r;
}

int label_fix(const char *path) {
        int r = 0;

#ifdef HAVE_SELINUX
        struct stat st;
        security_context_t fcon;

        if (!use_selinux() || !label_hnd)
                return 0;

        r = lstat(path, &st);
        if (r == 0) {
                r = selabel_lookup_raw(label_hnd, &fcon, path, st.st_mode);

                if (r == 0) {
                        r = setfilecon(path, fcon);
                        freecon(fcon);
                }
        }
        if (r < 0) {
                log_full(security_getenforce() == 1 ? LOG_ERR : LOG_DEBUG,
                         "Unable to fix label of %s: %m", path);
                r = (security_getenforce() == 1) ? -errno : 0;
        }
#endif

        return r;
}

void label_finish(void) {

#ifdef HAVE_SELINUX
        if (use_selinux() && label_hnd)
                selabel_close(label_hnd);
#endif
}

int label_get_socket_label_from_exe(const char *exe, char **label) {

        int r = 0;

#ifdef HAVE_SELINUX
        security_context_t mycon = NULL, fcon = NULL;
        security_class_t sclass;

        if (!use_selinux()) {
                *label = NULL;
                return 0;
        }

        r = getcon(&mycon);
        if (r < 0)
                goto fail;

        r = getfilecon(exe, &fcon);
        if (r < 0)
                goto fail;

        sclass = string_to_security_class("process");
        r = security_compute_create(mycon, fcon, sclass, (security_context_t *) label);
        if (r == 0)
                log_debug("SELinux Socket context for %s will be set to %s", exe, *label);

fail:
        if (r < 0 && security_getenforce() == 1)
                r = -errno;

        freecon(mycon);
        freecon(fcon);
#endif

        return r;
}

int label_fifofile_set(const char *label, const char *path) {
        int r = 0;

#ifdef HAVE_SELINUX
        security_context_t filecon = NULL;

        if (!use_selinux() || !label)
                return 0;

        if (((r = label_get_file_label_from_path(label, path, "fifo_file", &filecon)) == 0)) {
                if ((r = setfscreatecon(filecon)) < 0) {
                        log_error("Failed to set SELinux file context (%s) on %s: %m", label, path);
                        r = -errno;
                }

                freecon(filecon);
        }

        if (r < 0 && security_getenforce() == 0)
                r = 0;
#endif

        return r;
}

int label_socket_set(const char *label) {

#ifdef HAVE_SELINUX
        if (!use_selinux())
                return 0;

        if (setsockcreatecon((security_context_t) label) < 0) {
                log_full(security_getenforce() == 1 ? LOG_ERR : LOG_DEBUG,
                         "Failed to set SELinux context (%s) on socket: %m", label);

                if (security_getenforce() == 1)
                        return -errno;
        }
#endif

        return 0;
}

void label_file_clear(void) {

#ifdef HAVE_SELINUX
        if (!use_selinux())
                return;

        setfscreatecon(NULL);
#endif
}

void label_socket_clear(void) {

#ifdef HAVE_SELINUX
        if (!use_selinux())
                return;

        setsockcreatecon(NULL);
#endif
}

void label_free(const char *label) {

#ifdef HAVE_SELINUX
        if (!use_selinux())
                return;

        freecon((security_context_t) label);
#endif
}

int label_mkdir(
        const char *path,
        mode_t mode) {

        /* Creates a directory and labels it according to the SELinux policy */

#ifdef HAVE_SELINUX
        int r;
        security_context_t fcon = NULL;

        if (use_selinux() && label_hnd) {

                if (path[0] == '/')
                        r = selabel_lookup_raw(label_hnd, &fcon, path, mode);
                else {
                        char *cwd = NULL, *newpath = NULL;

                        cwd = get_current_dir_name();

                        if (cwd || asprintf(&newpath, "%s/%s", cwd, path) < 0) {
                                free(cwd);
                                return -errno;
                        }

                        r = selabel_lookup_raw(label_hnd, &fcon, newpath, mode);
                        free(cwd);
                        free(newpath);
                }

                if (r == 0)
                        r = setfscreatecon(fcon);

                if (r < 0 && errno != ENOENT) {
                        log_error("Failed to set security context %s for %s: %m", fcon, path);
                        r = -errno;

                        if (security_getenforce() == 1)
                                goto finish;
                }
        }

        if ((r = mkdir(path, mode)) < 0)
                r = -errno;

finish:
        if (use_selinux() && label_hnd) {
                setfscreatecon(NULL);
                freecon(fcon);
        }

        return r;
#else
        return mkdir(path, mode);
#endif
}
