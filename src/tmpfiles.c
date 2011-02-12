/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering, Kay Sievers

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
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <glob.h>
#include <fnmatch.h>

#include "log.h"
#include "util.h"
#include "strv.h"
#include "label.h"
#include "set.h"

/* This reads all files listed in /etc/tmpfiles.d/?*.conf and creates
 * them in the file system. This is intended to be used to create
 * properly owned directories beneath /tmp, /var/tmp, /var/run and
 * /var/lock which are volatile and hence need to be recreated on
 * bootup. */

enum {
        /* These ones take file names */
        CREATE_FILE = 'f',
        TRUNCATE_FILE = 'F',
        CREATE_DIRECTORY = 'd',
        TRUNCATE_DIRECTORY = 'D',

        /* These ones take globs */
        IGNORE_PATH = 'x',
        REMOVE_PATH = 'r',
        RECURSIVE_REMOVE_PATH = 'R'
};

typedef struct Item {
        char type;

        char *path;
        uid_t uid;
        gid_t gid;
        mode_t mode;
        usec_t age;

        bool uid_set:1;
        bool gid_set:1;
        bool mode_set:1;
        bool age_set:1;
} Item;

static Hashmap *items = NULL, *globs = NULL;

static bool arg_create = false;
static bool arg_clean = false;
static bool arg_remove = false;

#define MAX_DEPTH 256

static bool needs_glob(int t) {
        return t == IGNORE_PATH || t == REMOVE_PATH || t == RECURSIVE_REMOVE_PATH;
}

static struct Item* find_glob(Hashmap *h, const char *match) {
        Item *j;
        Iterator i;

        HASHMAP_FOREACH(j, h, i)
                if (fnmatch(j->path, match, FNM_PATHNAME|FNM_PERIOD) == 0)
                        return j;

        return NULL;
}

static int dir_cleanup(
                const char *p,
                DIR *d,
                const struct stat *ds,
                usec_t cutoff,
                dev_t rootdev,
                bool mountpoint,
                int maxdepth)
{
        struct dirent *dent;
        struct timespec times[2];
        bool deleted = false;
        char *sub_path = NULL;
        int r = 0;

        while ((dent = readdir(d))) {
                struct stat s;
                usec_t age;

                if (streq(dent->d_name, ".") ||
                    streq(dent->d_name, ".."))
                        continue;

                if (fstatat(dirfd(d), dent->d_name, &s, AT_SYMLINK_NOFOLLOW) < 0) {

                        if (errno != ENOENT) {
                                log_error("stat(%s/%s) failed: %m", p, dent->d_name);
                                r = -errno;
                        }

                        continue;
                }

                /* Stay on the same filesystem */
                if (s.st_dev != rootdev)
                        continue;

                /* Do not delete read-only files owned by root */
                if (s.st_uid == 0 && !(s.st_mode & S_IWUSR))
                        continue;

                free(sub_path);
                sub_path = NULL;

                if (asprintf(&sub_path, "%s/%s", p, dent->d_name) < 0) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                /* Is there an item configured for this path? */
                if (hashmap_get(items, sub_path))
                        continue;

                if (find_glob(globs, sub_path))
                        continue;

                if (S_ISDIR(s.st_mode)) {

                        if (mountpoint &&
                            streq(dent->d_name, "lost+found") &&
                            s.st_uid == 0)
                                continue;

                        if (maxdepth <= 0)
                                log_warning("Reached max depth on %s.", sub_path);
                        else {
                                DIR *sub_dir;
                                int q;

                                sub_dir = xopendirat(dirfd(d), dent->d_name, O_NOFOLLOW);
                                if (sub_dir == NULL) {
                                        if (errno != ENOENT) {
                                                log_error("opendir(%s/%s) failed: %m", p, dent->d_name);
                                                r = -errno;
                                        }

                                        continue;
                                }

                                q = dir_cleanup(sub_path, sub_dir, &s, cutoff, rootdev, false, maxdepth-1);
                                closedir(sub_dir);

                                if (q < 0)
                                        r = q;
                        }

                        /* Ignore ctime, we change it when deleting */
                        age = MAX(timespec_load(&s.st_mtim),
                                  timespec_load(&s.st_atim));
                        if (age >= cutoff)
                                continue;

                        log_debug("rmdir '%s'\n", sub_path);

                        if (unlinkat(dirfd(d), dent->d_name, AT_REMOVEDIR) < 0) {
                                if (errno != ENOENT && errno != ENOTEMPTY) {
                                        log_error("rmdir(%s): %m", sub_path);
                                        r = -errno;
                                }
                        }

                } else {
                        /* Skip files for which the sticky bit is
                         * set. These are semantics we define, and are
                         * unknown elsewhere. See XDG_RUNTIME_DIR
                         * specification for details. */
                        if (s.st_mode & S_ISVTX)
                                continue;

                        if (mountpoint) {
                                if (streq(dent->d_name, ".journal") &&
                                    s.st_uid == 0)
                                        continue;

                                if (streq(dent->d_name, "aquota.user") ||
                                    streq(dent->d_name, "aquota.group"))
                                        continue;
                        }

                        age = MAX3(timespec_load(&s.st_mtim),
                                   timespec_load(&s.st_atim),
                                   timespec_load(&s.st_ctim));

                        if (age >= cutoff)
                                continue;

                        log_debug("unlink '%s'\n", sub_path);

                        if (unlinkat(dirfd(d), dent->d_name, 0) < 0) {
                                if (errno != ENOENT) {
                                        log_error("unlink(%s): %m", sub_path);
                                        r = -errno;
                                }
                        }

                        deleted = true;
                }
        }

finish:
        if (deleted) {
                /* Restore original directory timestamps */
                times[0] = ds->st_atim;
                times[1] = ds->st_mtim;

                if (futimens(dirfd(d), times) < 0)
                        log_error("utimensat(%s): %m", p);
        }

        free(sub_path);

        return r;
}

static int clean_item(Item *i) {
        DIR *d;
        struct stat s, ps;
        bool mountpoint;
        int r;
        usec_t cutoff, n;

        assert(i);

        if (i->type != CREATE_DIRECTORY &&
            i->type != TRUNCATE_DIRECTORY &&
            i->type != IGNORE_PATH)
                return 0;

        if (!i->age_set || i->age <= 0)
                return 0;

        n = now(CLOCK_REALTIME);
        if (n < i->age)
                return 0;

        cutoff = n - i->age;

        d = opendir(i->path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open directory %s: %m", i->path);
                return -errno;
        }

        if (fstat(dirfd(d), &s) < 0) {
                log_error("stat(%s) failed: %m", i->path);
                r = -errno;
                goto finish;
        }

        if (!S_ISDIR(s.st_mode)) {
                log_error("%s is not a directory.", i->path);
                r = -ENOTDIR;
                goto finish;
        }

        if (fstatat(dirfd(d), "..", &ps, AT_SYMLINK_NOFOLLOW) != 0) {
                log_error("stat(%s/..) failed: %m", i->path);
                r = -errno;
                goto finish;
        }

        mountpoint = s.st_dev != ps.st_dev ||
                     (s.st_dev == ps.st_dev && s.st_ino == ps.st_ino);

        r = dir_cleanup(i->path, d, &s, cutoff, s.st_dev, mountpoint, MAX_DEPTH);

finish:
        if (d)
                closedir(d);

        return r;
}

static int create_item(Item *i) {
        int fd = -1, r;
        mode_t u;
        struct stat st;

        assert(i);

        switch (i->type) {

        case IGNORE_PATH:
        case REMOVE_PATH:
        case RECURSIVE_REMOVE_PATH:
                return 0;

        case CREATE_FILE:
        case TRUNCATE_FILE:

                u = umask(0);
                fd = open(i->path, O_CREAT|O_NDELAY|O_CLOEXEC|O_WRONLY|O_NOCTTY|O_NOFOLLOW|
                          (i->type == TRUNCATE_FILE ? O_TRUNC : 0), i->mode);
                umask(u);

                if (fd < 0) {
                        log_error("Failed to create file %s: %m", i->path);
                        r = -errno;
                        goto finish;
                }

                if (fstat(fd, &st) < 0) {
                        log_error("stat(%s) failed: %m", i->path);
                        r = -errno;
                        goto finish;
                }

                if (!S_ISREG(st.st_mode)) {
                        log_error("%s is not a file.", i->path);
                        r = -EEXIST;
                        goto finish;
                }

                if (i->mode_set)
                        if (fchmod(fd, i->mode) < 0) {
                                log_error("chmod(%s) failed: %m", i->path);
                                r = -errno;
                                goto finish;
                        }

                if (i->uid_set || i->gid_set)
                        if (fchown(fd,
                                   i->uid_set ? i->uid : (uid_t) -1,
                                   i->gid_set ? i->gid : (gid_t) -1) < 0) {
                                log_error("chown(%s) failed: %m", i->path);
                                r = -errno;
                                goto finish;
                        }

                break;

        case TRUNCATE_DIRECTORY:
        case CREATE_DIRECTORY:

                u = umask(0);
                r = mkdir(i->path, i->mode);
                umask(u);

                if (r < 0 && errno != EEXIST) {
                        log_error("Failed to create directory %s: %m", i->path);
                        r = -errno;
                        goto finish;
                }

                if (stat(i->path, &st) < 0) {
                        log_error("stat(%s) failed: %m", i->path);
                        r = -errno;
                        goto finish;
                }

                if (!S_ISDIR(st.st_mode)) {
                        log_error("%s is not a directory.", i->path);
                        r = -EEXIST;
                        goto finish;
                }

                if (i->mode_set)
                        if (chmod(i->path, i->mode) < 0) {
                                log_error("chmod(%s) failed: %m", i->path);
                                r = -errno;
                                goto finish;
                        }

                if (i->uid_set || i->gid_set)
                        if (chown(i->path,
                                  i->uid_set ? i->uid : (uid_t) -1,
                                  i->gid_set ? i->gid : (gid_t) -1) < 0) {

                                log_error("chown(%s) failed: %m", i->path);
                                r = -errno;
                                goto finish;
                        }

                break;
        }

        if ((r = label_fix(i->path)) < 0)
                goto finish;

        log_debug("%s created successfully.", i->path);

finish:
        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}

static int remove_item(Item *i, const char *instance) {
        int r;

        assert(i);

        switch (i->type) {

        case CREATE_FILE:
        case TRUNCATE_FILE:
        case CREATE_DIRECTORY:
        case IGNORE_PATH:
                break;

        case REMOVE_PATH:
                if (remove(instance) < 0 && errno != ENOENT) {
                        log_error("remove(%s): %m", instance);
                        return -errno;
                }

                break;

        case TRUNCATE_DIRECTORY:
        case RECURSIVE_REMOVE_PATH:
                if ((r = rm_rf(instance, false, i->type == RECURSIVE_REMOVE_PATH)) < 0 &&
                    r != -ENOENT) {
                        log_error("rm_rf(%s): %s", instance, strerror(-r));
                        return r;
                }

                break;
        }

        return 0;
}

static int remove_item_glob(Item *i) {
        assert(i);

        switch (i->type) {

        case CREATE_FILE:
        case TRUNCATE_FILE:
        case CREATE_DIRECTORY:
        case IGNORE_PATH:
                break;

        case REMOVE_PATH:
        case TRUNCATE_DIRECTORY:
        case RECURSIVE_REMOVE_PATH: {
                int r = 0, k;
                glob_t g;
                char **fn;

                zero(g);

                errno = 0;
                if ((k = glob(i->path, GLOB_NOSORT|GLOB_BRACE, NULL, &g)) != 0) {

                        if (k != GLOB_NOMATCH) {
                                if (errno != 0)
                                        errno = EIO;

                                log_error("glob(%s) failed: %m", i->path);
                                return -errno;
                        }
                }

                STRV_FOREACH(fn, g.gl_pathv)
                        if ((k = remove_item(i, *fn)) < 0)
                                r = k;

                globfree(&g);
                return r;
        }
        }

        return 0;
}

static int process_item(Item *i) {
        int r, q, p;

        assert(i);

        r = arg_create ? create_item(i) : 0;
        q = arg_remove ? remove_item_glob(i) : 0;
        p = arg_clean ? clean_item(i) : 0;

        if (r < 0)
                return r;

        if (q < 0)
                return q;

        return p;
}

static void item_free(Item *i) {
        assert(i);

        free(i->path);
        free(i);
}

static int parse_line(const char *fname, unsigned line, const char *buffer, const char *prefix) {
        Item *i;
        char *mode = NULL, *user = NULL, *group = NULL, *age = NULL;
        int r;

        assert(fname);
        assert(line >= 1);
        assert(buffer);

        if (!(i = new0(Item, 1))) {
                log_error("Out of memory");
                return -ENOMEM;
        }

        if (sscanf(buffer,
                   "%c "
                   "%ms "
                   "%ms "
                   "%ms "
                   "%ms "
                   "%ms",
                   &i->type,
                   &i->path,
                   &mode,
                   &user,
                   &group,
                   &age) < 2) {
                log_error("[%s:%u] Syntax error.", fname, line);
                r = -EIO;
                goto finish;
        }

        if (i->type != CREATE_FILE &&
            i->type != TRUNCATE_FILE &&
            i->type != CREATE_DIRECTORY &&
            i->type != TRUNCATE_DIRECTORY &&
            i->type != IGNORE_PATH &&
            i->type != REMOVE_PATH &&
            i->type != RECURSIVE_REMOVE_PATH) {
                log_error("[%s:%u] Unknown file type '%c'.", fname, line, i->type);
                r = -EBADMSG;
                goto finish;
        }

        if (!path_is_absolute(i->path)) {
                log_error("[%s:%u] Path '%s' not absolute.", fname, line, i->path);
                r = -EBADMSG;
                goto finish;
        }

        path_kill_slashes(i->path);

        if (prefix && !path_startswith(i->path, prefix)) {
                r = 0;
                goto finish;
        }

        if (user && !streq(user, "-")) {
                unsigned long lu;
                struct passwd *p;

                if (streq(user, "root") || streq(user, "0"))
                        i->uid = 0;
                else if (safe_atolu(user, &lu) >= 0)
                        i->uid = (uid_t) lu;
                else if ((p = getpwnam(user)))
                        i->uid = p->pw_uid;
                else {
                        log_error("[%s:%u] Unknown user '%s'.", fname, line, user);
                        r = -ENOENT;
                        goto finish;
                }

                i->uid_set = true;
        }

        if (group && !streq(group, "-")) {
                unsigned long lu;
                struct group *g;

                if (streq(group, "root") || streq(group, "0"))
                        i->gid = 0;
                else if (safe_atolu(group, &lu) >= 0)
                        i->gid = (gid_t) lu;
                else if ((g = getgrnam(group)))
                        i->gid = g->gr_gid;
                else {
                        log_error("[%s:%u] Unknown group '%s'.", fname, line, group);
                        r = -ENOENT;
                        goto finish;
                }

                i->gid_set = true;
        }

        if (mode && !streq(mode, "-")) {
                unsigned m;

                if (sscanf(mode, "%o", &m) != 1) {
                        log_error("[%s:%u] Invalid mode '%s'.", fname, line, mode);
                        r = -ENOENT;
                        goto finish;
                }

                i->mode = m;
                i->mode_set = true;
        } else
                i->mode = i->type == CREATE_DIRECTORY ? 0755 : 0644;

        if (age && !streq(age, "-")) {
                if (parse_usec(age, &i->age) < 0) {
                        log_error("[%s:%u] Invalid age '%s'.", fname, line, age);
                        r = -EBADMSG;
                        goto finish;
                }

                i->age_set = true;
        }

        if ((r = hashmap_put(needs_glob(i->type) ? globs : items, i->path, i)) < 0) {
                if (r == -EEXIST) {
                        log_warning("Two or more conflicting lines for %s configured, ignoring.", i->path);
                        r = 0;
                        goto finish;
                }

                log_error("Failed to insert item %s: %s", i->path, strerror(-r));
                goto finish;
        }

        i = NULL;
        r = 0;

finish:
        free(user);
        free(group);
        free(mode);
        free(age);

        if (i)
                item_free(i);

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

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Create and clean up temporary directories.\n\n"
               "  -h --help             Show this help\n"
               "     --create           Create marked files/directories\n"
               "     --clean            Clean up marked directories\n"
               "     --remove           Remove marked files/directories\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_CREATE,
                ARG_CLEAN,
                ARG_REMOVE
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "create",    no_argument,       NULL, ARG_CREATE    },
                { "clean",     no_argument,       NULL, ARG_CLEAN     },
                { "remove",    no_argument,       NULL, ARG_REMOVE    },
                { NULL,        0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_CREATE:
                        arg_create = true;
                        break;

                case ARG_CLEAN:
                        arg_clean = true;
                        break;

                case ARG_REMOVE:
                        arg_remove = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (!arg_clean && !arg_create && !arg_remove) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        struct dirent **de = NULL;
        int r, n, j;
        const char *prefix = NULL;
        Item *i;
        Iterator iterator;

        if ((r = parse_argv(argc, argv)) <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        if (optind < argc)
                prefix = argv[optind];
        else
                prefix = "/";

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        label_init();

        items = hashmap_new(string_hash_func, string_compare_func);
        globs = hashmap_new(string_hash_func, string_compare_func);

        if (!items || !globs) {
                log_error("Out of memory");
                r = EXIT_FAILURE;
                goto finish;
        }

        if ((n = scandir("/etc/tmpfiles.d/", &de, scandir_filter, alphasort)) < 0) {

                if (errno == ENOENT)
                        r = EXIT_SUCCESS;
                else {
                        log_error("Failed to enumerate /etc/tmpfiles.d/ files: %m");
                        r = EXIT_FAILURE;
                }

                goto finish;
        }

        r = EXIT_SUCCESS;

        for (j = 0; j < n; j++) {
                int k;
                char *fn;
                FILE *f;
                unsigned v;

                k = asprintf(&fn, "/etc/tmpfiles.d/%s", de[j]->d_name);
                free(de[j]);

                if (k < 0) {
                        log_error("Failed to allocate file name.");
                        r = EXIT_FAILURE;
                        continue;
                }

                if (!(f = fopen(fn, "re"))) {

                        if (errno != ENOENT) {
                                log_error("Failed to open %s: %m", fn);
                                r = EXIT_FAILURE;
                        }

                        free(fn);
                        continue;
                }

                v = 0;
                for (;;) {
                        char line[LINE_MAX], *l;

                        if (!(fgets(line, sizeof(line), f)))
                                break;

                        v++;

                        l = strstrip(line);
                        if (*l == '#' || *l == 0)
                                continue;

                        if (parse_line(fn, v, l, prefix) < 0)
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

        HASHMAP_FOREACH(i, globs, iterator)
                if (process_item(i) < 0)
                        r = EXIT_FAILURE;

        HASHMAP_FOREACH(i, items, iterator)
                if (process_item(i) < 0)
                        r = EXIT_FAILURE;

finish:
        while ((i = hashmap_steal_first(items)))
                item_free(i);

        hashmap_free(items);
        hashmap_free(globs);

        label_finish();

        return r;
}
