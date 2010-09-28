/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>

#include "log.h"
#include "util.h"
#include "strv.h"
#include "label.h"

/* This reads all files listed in /etc/tempfiles.d/?*.conf and creates
 * them in the file system. This is intended to be used to create
 * properly owned directories beneath /tmp, /var/tmp, /var/run and
 * /var/lock which are volatile and hence need to be recreated on
 * bootup. */

static int process_line(const char *fname, unsigned line, const char *buffer, const char *prefix) {
        char type;
        char *path = NULL;
        unsigned mode;
        char *user = NULL, *group = NULL;
        uid_t uid;
        gid_t gid;
        bool uid_set = false, gid_set = false;
        int n, fd = -1, r;

        assert(fname);
        assert(line >= 1);
        assert(buffer);

        if ((n = sscanf(buffer,
                        "%c "
                        "%ms "
                        "%o "
                        "%ms "
                        "%ms ",
                        &type,
                        &path,
                        &mode,
                        &user,
                        &group)) < 2) {
                log_error("[%s:%u] Syntax error.", fname, line);
                r = -EIO;
                goto finish;
        }

        if (type != 'f' && type != 'd') {
                log_error("[%s:%u] Unknown file type '%c'.", fname, line, type);
                r = -EBADMSG;
                goto finish;
        }

        if (prefix && !path_startswith(path, prefix)) {
                r = 0;
                goto finish;
        }

        if (user && !streq(user, "-")) {
                unsigned long lu;
                struct passwd *p;

                if (streq(user, "root") || streq(user, "0"))
                        uid = 0;
                else if (safe_atolu(user, &lu) >= 0)
                        uid = (uid_t) lu;
                else if ((p = getpwnam(user)))
                        uid = p->pw_uid;
                else {
                        log_error("[%s:%u] Unknown user '%s'.", fname, line, user);
                        r = -ENOENT;
                        goto finish;
                }

                uid_set = true;
        }

        if (group && !streq(group, "-")) {
                unsigned long lu;
                struct group *g;

                if (streq(group, "root") || streq(group, "0"))
                        gid = 0;
                else if (safe_atolu(group, &lu) >= 0)
                        gid = (gid_t) lu;
                else if ((g = getgrnam(group)))
                        gid = g->gr_gid;
                else {
                        log_error("[%s:%u] Unknown group '%s'.", fname, line, group);
                        r = -ENOENT;
                        goto finish;
                }

                gid_set = true;
        }

        if (n < 3)
                mode = type == 'f' ? 0644 : 0755;

        if (type == 'f') {
                mode_t u;
                struct stat st;

                u = umask(0);
                fd = open(path, O_CREAT|O_NDELAY|O_CLOEXEC|O_WRONLY|O_NOCTTY|O_NOFOLLOW, mode);
                umask(u);

                if (fd < 0) {
                        log_error("Failed to create file %s: %m", path);
                        r = -errno;
                        goto finish;
                }

                if (fstat(fd, &st) < 0) {
                        log_error("stat(%s) failed: %m", path);
                        r = -errno;
                        goto finish;
                }

                if (!S_ISREG(st.st_mode)) {
                        log_error("%s is not a file.", path);
                        r = -EEXIST;
                        goto finish;
                }

                if (fchmod(fd, mode) < 0) {
                        log_error("chmod(%s) failed: %m", path);
                        r = -errno;
                        goto finish;
                }

                if (uid_set || gid_set) {

                        if (fchown(fd,
                                   uid_set ? uid : (uid_t) -1,
                                   gid_set ? gid : (gid_t) -1) < 0) {
                                log_error("chown(%s) failed: %m", path);
                                r = -errno;
                                goto finish;
                        }
                }

        } else if (type == 'd') {
                mode_t u;
                struct stat st;

                u = umask(0);
                r = mkdir(path, mode);
                umask(u);

                if (r < 0 && errno != EEXIST) {
                        log_error("Failed to create directory %s: %m", path);
                        r = -errno;
                        goto finish;
                }

                if (stat(path, &st) < 0) {
                        log_error("stat(%s) failed: %m", path);
                        r = -errno;
                        goto finish;
                }

                if (!S_ISDIR(st.st_mode)) {
                        log_error("%s is not a directory.", path);
                        r = -EEXIST;
                        goto finish;
                }

                if (chmod(path, mode) < 0) {
                        log_error("chmod(%s) failed: %m", path);
                        r = -errno;
                        goto finish;
                }

                if (uid_set || gid_set) {

                        if (chown(path,
                                   uid_set ? uid : (uid_t) -1,
                                   gid_set ? gid : (gid_t) -1) < 0) {
                                log_error("chown(%s) failed: %m", path);
                                r = -errno;
                                goto finish;
                        }
                }
        }

        if ((r = label_fix(path)) < 0)
                goto finish;

        log_debug("%s created successfully.", path);
        r = 0;

finish:
        free(path);
        free(user);
        free(group);

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

static int scandir_filter(const struct dirent *d) {
        assert(d);

        if (ignore_file(d->d_name))
                return 0;

        if (d->d_type != DT_REG &&
            d->d_type != DT_LNK)
                return 0;

        return endswith(d->d_name, ".conf");
}

int main(int argc, char *argv[]) {
        struct dirent **de = NULL;
        int r = EXIT_FAILURE, n, i;
        const char *prefix = NULL;

        if (argc > 2) {
                log_error("This program takes no more than one argument.");
                return EXIT_FAILURE;
        } else if (argc > 1)
                prefix = argv[1];
        else
                prefix = "/";

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        label_init();

        if ((n = scandir("/etc/tmpfiles.d/", &de, scandir_filter, alphasort)) < 0) {

                if (errno == ENOENT)
                        r = EXIT_SUCCESS;
                else
                        log_error("Failed to enumerate /etc/tmpfiles.d/ files: %m");

                goto finish;
        }

        r = EXIT_SUCCESS;

        for (i = 0; i < n; i++) {
                int k;
                char *fn;
                FILE *f;
                unsigned j;

                k = asprintf(&fn, "/etc/tmpfiles.d/%s", de[i]->d_name);
                free(de[i]);

                if (k < 0) {
                        log_error("Failed to allocate file name.");
                        r = EXIT_FAILURE;
                        continue;
                }

                if (!(f = fopen(fn, "re"))) {
                        log_error("Failed to open %s: %m", fn);
                        free(fn);
                        r = EXIT_FAILURE;
                        continue;
                }

                j = 0;
                for (;;) {
                        char line[LINE_MAX], *l;

                        if (!(fgets(line, sizeof(line), f)))
                                break;

                        j++;

                        l = strstrip(line);
                        if (*l == '#' || *l == 0)
                                continue;

                        if (process_line(fn, j, l, prefix) < 0)
                                r = EXIT_FAILURE;
                }

                if (ferror(f)) {
                        r = EXIT_FAILURE;
                        log_error("Failed to read from file %s: %m", fn);
                }

                free(fn);

                fclose(f);
        }

        free(de);

finish:

        return r;
}
