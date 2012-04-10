/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty <of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <fnmatch.h>

#include "util.h"
#include "mkdir.h"
#include "hashmap.h"
#include "set.h"
#include "path-lookup.h"
#include "strv.h"
#include "unit-name.h"
#include "install.h"
#include "conf-parser.h"

typedef struct {
        char *name;
        char *path;

        char **aliases;
        char **wanted_by;
} InstallInfo;

typedef struct {
        Hashmap *will_install;
        Hashmap *have_installed;
} InstallContext;

static int lookup_paths_init_from_scope(LookupPaths *paths, UnitFileScope scope) {
        assert(paths);
        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        zero(*paths);

        return lookup_paths_init(paths,
                                 scope == UNIT_FILE_SYSTEM ? MANAGER_SYSTEM : MANAGER_USER,
                                 scope == UNIT_FILE_USER);
}

static int get_config_path(UnitFileScope scope, bool runtime, const char *root_dir, char **ret) {
        char *p = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(ret);

        switch (scope) {

        case UNIT_FILE_SYSTEM:

                if (root_dir && runtime)
                        asprintf(&p, "%s/run/systemd/system", root_dir);
                else if (runtime)
                        p = strdup("/run/systemd/system");
                else if (root_dir)
                        asprintf(&p, "%s/%s", root_dir, SYSTEM_CONFIG_UNIT_PATH);
                else
                        p = strdup(SYSTEM_CONFIG_UNIT_PATH);

                break;

        case UNIT_FILE_GLOBAL:

                if (root_dir)
                        return -EINVAL;

                if (runtime)
                        p = strdup("/run/systemd/user");
                else
                        p = strdup(USER_CONFIG_UNIT_PATH);
                break;

        case UNIT_FILE_USER:

                if (root_dir || runtime)
                        return -EINVAL;

                r = user_config_home(&p);
                if (r <= 0)
                        return r < 0 ? r : -ENOENT;

                break;

        default:
                assert_not_reached("Bad scope");
        }

        if (!p)
                return -ENOMEM;

        *ret = p;
        return 0;
}

static int add_file_change(
                UnitFileChange **changes,
                unsigned *n_changes,
                UnitFileChangeType type,
                const char *path,
                const char *source) {

        UnitFileChange *c;
        unsigned i;

        assert(path);
        assert(!changes == !n_changes);

        if (!changes)
                return 0;

        c = realloc(*changes, (*n_changes + 1) * sizeof(UnitFileChange));
        if (!c)
                return -ENOMEM;

        *changes = c;
        i = *n_changes;

        c[i].type = type;
        c[i].path = strdup(path);
        if (!c[i].path)
                return -ENOMEM;

        if (source) {
                c[i].source = strdup(source);
                if (!c[i].source) {
                        free(c[i].path);
                        return -ENOMEM;
                }
        } else
                c[i].source = NULL;

        *n_changes = i+1;
        return 0;
}

static int mark_symlink_for_removal(
                Set **remove_symlinks_to,
                const char *p) {

        char *n;
        int r;

        assert(p);

        r = set_ensure_allocated(remove_symlinks_to, string_hash_func, string_compare_func);
        if (r < 0)
                return r;

        n = strdup(p);
        if (!n)
                return -ENOMEM;

        path_kill_slashes(n);

        r = set_put(*remove_symlinks_to, n);
        if (r < 0) {
                free(n);
                return r == -EEXIST ? 0 : r;
        }

        return 0;
}

static int remove_marked_symlinks_fd(
                Set *remove_symlinks_to,
                int fd,
                const char *path,
                const char *config_path,
                bool *deleted,
                UnitFileChange **changes,
                unsigned *n_changes) {

        int r = 0;
        DIR *d;
        struct dirent buffer, *de;

        assert(remove_symlinks_to);
        assert(fd >= 0);
        assert(path);
        assert(config_path);
        assert(deleted);

        d = fdopendir(fd);
        if (!d) {
                close_nointr_nofail(fd);
                return -errno;
        }

        rewinddir(d);

        for (;;) {
                int k;

                k = readdir_r(d, &buffer, &de);
                if (k != 0) {
                        r = -errno;
                        break;
                }

                if (!de)
                        break;

                if (ignore_file(de->d_name))
                        continue;

                dirent_ensure_type(d, de);

                if (de->d_type == DT_DIR) {
                        int nfd, q;
                        char *p;

                        nfd = openat(fd, de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                        if (nfd < 0) {
                                if (errno == ENOENT)
                                        continue;

                                if (r == 0)
                                        r = -errno;
                                continue;
                        }

                        p = path_make_absolute(de->d_name, path);
                        if (!p) {
                                close_nointr_nofail(nfd);
                                r = -ENOMEM;
                                break;
                        }

                        /* This will close nfd, regardless whether it succeeds or not */
                        q = remove_marked_symlinks_fd(remove_symlinks_to, nfd, p, config_path, deleted, changes, n_changes);
                        free(p);

                        if (r == 0)
                                r = q;

                } else if (de->d_type == DT_LNK) {
                        char *p, *dest;
                        int q;
                        bool found;

                        p = path_make_absolute(de->d_name, path);
                        if (!p) {
                                r = -ENOMEM;
                                break;
                        }

                        q = readlink_and_canonicalize(p, &dest);
                        if (q < 0) {
                                free(p);

                                if (q == -ENOENT)
                                        continue;

                                if (r == 0)
                                        r = q;
                                continue;
                        }

                        found =
                                set_get(remove_symlinks_to, dest) ||
                                set_get(remove_symlinks_to, file_name_from_path(dest));

                        if (found) {

                                if (unlink(p) < 0 && errno != ENOENT) {

                                        if (r == 0)
                                                r = -errno;
                                } else {
                                        rmdir_parents(p, config_path);
                                        path_kill_slashes(p);

                                        add_file_change(changes, n_changes, UNIT_FILE_UNLINK, p, NULL);

                                        if (!set_get(remove_symlinks_to, p)) {

                                                q = mark_symlink_for_removal(&remove_symlinks_to, p);
                                                if (q < 0) {
                                                        if (r == 0)
                                                                r = q;
                                                } else
                                                        *deleted = true;
                                        }
                                }
                        }

                        free(p);
                        free(dest);
                }
        }

        closedir(d);

        return r;
}

static int remove_marked_symlinks(
                Set *remove_symlinks_to,
                const char *config_path,
                UnitFileChange **changes,
                unsigned *n_changes) {

        int fd, r = 0;
        bool deleted;

        assert(config_path);

        if (set_size(remove_symlinks_to) <= 0)
                return 0;

        fd = open(config_path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        do {
                int q, cfd;
                deleted = false;

                cfd = dup(fd);
                if (cfd < 0) {
                        r = -errno;
                        break;
                }

                /* This takes possession of cfd and closes it */
                q = remove_marked_symlinks_fd(remove_symlinks_to, cfd, config_path, config_path, &deleted, changes, n_changes);
                if (r == 0)
                        r = q;
        } while (deleted);

        close_nointr_nofail(fd);

        return r;
}

static int find_symlinks_fd(
                const char *name,
                int fd,
                const char *path,
                const char *config_path,
                bool *same_name_link) {

        int r = 0;
        DIR *d;
        struct dirent buffer, *de;

        assert(name);
        assert(fd >= 0);
        assert(path);
        assert(config_path);
        assert(same_name_link);

        d = fdopendir(fd);
        if (!d) {
                close_nointr_nofail(fd);
                return -errno;
        }

        for (;;) {
                int k;

                k = readdir_r(d, &buffer, &de);
                if (k != 0) {
                        r = -errno;
                        break;
                }

                if (!de)
                        break;

                if (ignore_file(de->d_name))
                        continue;

                dirent_ensure_type(d, de);

                if (de->d_type == DT_DIR) {
                        int nfd, q;
                        char *p;

                        nfd = openat(fd, de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                        if (nfd < 0) {
                                if (errno == ENOENT)
                                        continue;

                                if (r == 0)
                                        r = -errno;
                                continue;
                        }

                        p = path_make_absolute(de->d_name, path);
                        if (!p) {
                                close_nointr_nofail(nfd);
                                r = -ENOMEM;
                                break;
                        }

                        /* This will close nfd, regardless whether it succeeds or not */
                        q = find_symlinks_fd(name, nfd, p, config_path, same_name_link);
                        free(p);

                        if (q > 0) {
                                r = 1;
                                break;
                        }

                        if (r == 0)
                                r = q;

                } else if (de->d_type == DT_LNK) {
                        char *p, *dest;
                        bool found_path, found_dest, b = false;
                        int q;

                        /* Acquire symlink name */
                        p = path_make_absolute(de->d_name, path);
                        if (!p) {
                                r = -ENOMEM;
                                break;
                        }

                        /* Acquire symlink destination */
                        q = readlink_and_canonicalize(p, &dest);
                        if (q < 0) {
                                free(p);

                                if (q == -ENOENT)
                                        continue;

                                if (r == 0)
                                        r = q;
                                continue;
                        }

                        /* Check if the symlink itself matches what we
                         * are looking for */
                        if (path_is_absolute(name))
                                found_path = path_equal(p, name);
                        else
                                found_path = streq(de->d_name, name);

                        /* Check if what the symlink points to
                         * matches what we are looking for */
                        if (path_is_absolute(name))
                                found_dest = path_equal(dest, name);
                        else
                                found_dest = streq(file_name_from_path(dest), name);

                        free(dest);

                        if (found_path && found_dest) {
                                char *t;

                                /* Filter out same name links in the main
                                 * config path */
                                t = path_make_absolute(name, config_path);
                                if (!t) {
                                        free(p);
                                        r = -ENOMEM;
                                        break;
                                }

                                b = path_equal(t, p);
                                free(t);
                        }

                        free(p);

                        if (b)
                                *same_name_link = true;
                        else if (found_path || found_dest) {
                                r = 1;
                                break;
                        }
                }
        }

        closedir(d);

        return r;
}

static int find_symlinks(
                const char *name,
                const char *config_path,
                bool *same_name_link) {

        int fd;

        assert(name);
        assert(config_path);
        assert(same_name_link);

        fd = open(config_path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        /* This takes possession of fd and closes it */
        return find_symlinks_fd(name, fd, config_path, config_path, same_name_link);
}

static int find_symlinks_in_scope(
                UnitFileScope scope,
                const char *root_dir,
                const char *name,
                UnitFileState *state) {

        int r;
        char *path;
        bool same_name_link_runtime = false, same_name_link = false;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        if (scope == UNIT_FILE_SYSTEM || scope == UNIT_FILE_GLOBAL) {

                /* First look in runtime config path */
                r = get_config_path(scope, true, root_dir, &path);
                if (r < 0)
                        return r;

                r = find_symlinks(name, path, &same_name_link_runtime);
                free(path);

                if (r < 0)
                        return r;
                else if (r > 0) {
                        *state = UNIT_FILE_ENABLED_RUNTIME;
                        return r;
                }
        }

        /* Then look in the normal config path */
        r = get_config_path(scope, false, root_dir, &path);
        if (r < 0)
                return r;

        r = find_symlinks(name, path, &same_name_link);
        free(path);

        if (r < 0)
                return r;
        else if (r > 0) {
                *state = UNIT_FILE_ENABLED;
                return r;
        }

        /* Hmm, we didn't find it, but maybe we found the same name
         * link? */
        if (same_name_link_runtime) {
                *state = UNIT_FILE_LINKED_RUNTIME;
                return 1;
        } else if (same_name_link) {
                *state = UNIT_FILE_LINKED;
                return 1;
        }

        return 0;
}

int unit_file_mask(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char *files[],
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        char **i, *prefix;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = get_config_path(scope, runtime, root_dir, &prefix);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                char *path;

                if (!unit_name_is_valid_no_type(*i, true)) {
                        if (r == 0)
                                r = -EINVAL;
                        continue;
                }

                path = path_make_absolute(*i, prefix);
                if (!path) {
                        r = -ENOMEM;
                        break;
                }

                if (symlink("/dev/null", path) >= 0) {
                        add_file_change(changes, n_changes, UNIT_FILE_SYMLINK, path, "/dev/null");

                        free(path);
                        continue;
                }

                if (errno == EEXIST) {

                        if (null_or_empty_path(path) > 0) {
                                free(path);
                                continue;
                        }

                        if (force) {
                                unlink(path);

                                if (symlink("/dev/null", path) >= 0) {

                                        add_file_change(changes, n_changes, UNIT_FILE_UNLINK, path, NULL);
                                        add_file_change(changes, n_changes, UNIT_FILE_SYMLINK, path, "/dev/null");

                                        free(path);
                                        continue;
                                }
                        }

                        if (r == 0)
                                r = -EEXIST;
                } else {
                        if (r == 0)
                                r = -errno;
                }

                free(path);
        }

        free(prefix);

        return r;
}

int unit_file_unmask(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char *files[],
                UnitFileChange **changes,
                unsigned *n_changes) {

        char **i, *config_path = NULL;
        int r, q;
        Set *remove_symlinks_to = NULL;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                goto finish;

        STRV_FOREACH(i, files) {
                char *path;

                if (!unit_name_is_valid_no_type(*i, true)) {
                        if (r == 0)
                                r = -EINVAL;
                        continue;
                }

                path = path_make_absolute(*i, config_path);
                if (!path) {
                        r = -ENOMEM;
                        break;
                }

                q = null_or_empty_path(path);
                if (q > 0) {
                        if (unlink(path) >= 0) {
                                mark_symlink_for_removal(&remove_symlinks_to, path);
                                add_file_change(changes, n_changes, UNIT_FILE_UNLINK, path, NULL);

                                free(path);
                                continue;
                        }

                        q = -errno;
                }

                if (q != -ENOENT && r == 0)
                        r = q;

                free(path);
        }


finish:
        q = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes);
        if (r == 0)
                r = q;

        set_free_free(remove_symlinks_to);
        free(config_path);

        return r;
}

int unit_file_link(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char *files[],
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        LookupPaths paths;
        char **i, *config_path = NULL;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        zero(paths);

        r = lookup_paths_init_from_scope(&paths, scope);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                goto finish;

        STRV_FOREACH(i, files) {
                char *path, *fn;
                struct stat st;

                fn = file_name_from_path(*i);

                if (!path_is_absolute(*i) ||
                    !unit_name_is_valid_no_type(fn, true)) {
                        if (r == 0)
                                r = -EINVAL;
                        continue;
                }

                if (lstat(*i, &st) < 0) {
                        if (r == 0)
                                r = -errno;
                        continue;
                }

                if (!S_ISREG(st.st_mode)) {
                        r = -ENOENT;
                        continue;
                }

                q = in_search_path(*i, paths.unit_path);
                if (q < 0) {
                        r = q;
                        break;
                }

                if (q > 0)
                        continue;

                path = path_make_absolute(fn, config_path);
                if (!path) {
                        r = -ENOMEM;
                        break;
                }

                if (symlink(*i, path) >= 0) {
                        add_file_change(changes, n_changes, UNIT_FILE_SYMLINK, path, *i);

                        free(path);
                        continue;
                }

                if (errno == EEXIST) {
                        char *dest = NULL;

                        q = readlink_and_make_absolute(path, &dest);

                        if (q < 0 && errno != ENOENT) {
                                free(path);

                                if (r == 0)
                                        r = q;

                                continue;
                        }

                        if (q >= 0 && path_equal(dest, *i)) {
                                free(dest);
                                free(path);
                                continue;
                        }

                        free(dest);

                        if (force) {
                                unlink(path);

                                if (symlink(*i, path) >= 0) {

                                        add_file_change(changes, n_changes, UNIT_FILE_UNLINK, path, NULL);
                                        add_file_change(changes, n_changes, UNIT_FILE_SYMLINK, path, *i);

                                        free(path);
                                        continue;
                                }
                        }

                        if (r == 0)
                                r = -EEXIST;
                } else {
                        if (r == 0)
                                r = -errno;
                }

                free(path);
        }

                finish:
        lookup_paths_free(&paths);
        free(config_path);

        return r;
}

void unit_file_list_free(Hashmap *h) {
        UnitFileList *i;

        while ((i = hashmap_steal_first(h))) {
                free(i->path);
                free(i);
        }

        hashmap_free(h);
}

void unit_file_changes_free(UnitFileChange *changes, unsigned n_changes) {
        unsigned i;

        assert(changes || n_changes == 0);

        if (!changes)
                return;

        for (i = 0; i < n_changes; i++) {
                free(changes[i].path);
                free(changes[i].source);
        }

        free(changes);
}

static void install_info_free(InstallInfo *i) {
        assert(i);

        free(i->name);
        free(i->path);
        strv_free(i->aliases);
        strv_free(i->wanted_by);
        free(i);
}

static void install_info_hashmap_free(Hashmap *m) {
        InstallInfo *i;

        if (!m)
                return;

        while ((i = hashmap_steal_first(m)))
                install_info_free(i);

        hashmap_free(m);
}

static void install_context_done(InstallContext *c) {
        assert(c);

        install_info_hashmap_free(c->will_install);
        install_info_hashmap_free(c->have_installed);

        c->will_install = c->have_installed = NULL;
}

static int install_info_add(
                InstallContext *c,
                const char *name,
                const char *path) {
        InstallInfo *i = NULL;
        int r;

        assert(c);
        assert(name || path);

        if (!name)
                name = file_name_from_path(path);

        if (!unit_name_is_valid_no_type(name, true))
                return -EINVAL;

        if (hashmap_get(c->have_installed, name) ||
            hashmap_get(c->will_install, name))
                return 0;

        r = hashmap_ensure_allocated(&c->will_install, string_hash_func, string_compare_func);
        if (r < 0)
                return r;

        i = new0(InstallInfo, 1);
        if (!i)
                return -ENOMEM;

        i->name = strdup(name);
        if (!i->name) {
                r = -ENOMEM;
                goto fail;
        }

        if (path) {
                i->path = strdup(path);
                if (!i->path) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        r = hashmap_put(c->will_install, i->name, i);
        if (r < 0)
                goto fail;

        return 0;

fail:
        if (i)
                install_info_free(i);

        return r;
}

static int install_info_add_auto(
                InstallContext *c,
                const char *name_or_path) {

        assert(c);
        assert(name_or_path);

        if (path_is_absolute(name_or_path))
                return install_info_add(c, NULL, name_or_path);
        else
                return install_info_add(c, name_or_path, NULL);
}

static int config_parse_also(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char *w;
        size_t l;
        char *state;
        InstallContext *c = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                char *n;
                int r;

                n = strndup(w, l);
                if (!n)
                        return -ENOMEM;

                r = install_info_add(c, n, NULL);
                if (r < 0) {
                        free(n);
                        return r;
                }

                free(n);
        }

        return 0;
}

static int unit_file_load(
                InstallContext *c,
                InstallInfo *info,
                const char *path,
                bool allow_symlink) {

        const ConfigTableItem items[] = {
                { "Install", "Alias",    config_parse_strv, 0, &info->aliases   },
                { "Install", "WantedBy", config_parse_strv, 0, &info->wanted_by },
                { "Install", "Also",     config_parse_also, 0, c                },
                { NULL, NULL, NULL, 0, NULL }
        };

        int fd;
        FILE *f;
        int r;

        assert(c);
        assert(info);
        assert(path);

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|(allow_symlink ? 0 : O_NOFOLLOW));
        if (fd < 0)
                return -errno;

        f = fdopen(fd, "re");
        if (!f) {
                close_nointr_nofail(fd);
                return -ENOMEM;
        }

        r = config_parse(path, f, NULL, config_item_table_lookup, (void*) items, true, info);
        fclose(f);
        if (r < 0)
                return r;

        return strv_length(info->aliases) + strv_length(info->wanted_by);
}

static int unit_file_search(
                InstallContext *c,
                InstallInfo *info,
                LookupPaths *paths,
                const char *root_dir,
                bool allow_symlink) {

        char **p;
        int r;

        assert(c);
        assert(info);
        assert(paths);

        if (info->path)
                return unit_file_load(c, info, info->path, allow_symlink);

        assert(info->name);

        STRV_FOREACH(p, paths->unit_path) {
                char *path = NULL;

                if (isempty(root_dir))
                        asprintf(&path, "%s/%s", *p, info->name);
                else
                        asprintf(&path, "%s/%s/%s", root_dir, *p, info->name);

                if (!path)
                        return -ENOMEM;

                r = unit_file_load(c, info, path, allow_symlink);

                if (r >= 0)
                        info->path = path;
                else
                        free(path);

                if (r != -ENOENT && r != -ELOOP)
                        return r;
        }

        return -ENOENT;
}

static int unit_file_can_install(
                LookupPaths *paths,
                const char *root_dir,
                const char *name,
                bool allow_symlink) {

        InstallContext c;
        InstallInfo *i;
        int r;

        assert(paths);
        assert(name);

        zero(c);

        r = install_info_add_auto(&c, name);
        if (r < 0)
                return r;

        assert_se(i = hashmap_first(c.will_install));

        r = unit_file_search(&c, i, paths, root_dir, allow_symlink);

        if (r >= 0)
                r = strv_length(i->aliases) + strv_length(i->wanted_by);

        install_context_done(&c);

        return r;
}

static int create_symlink(
                const char *old_path,
                const char *new_path,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        char *dest;
        int r;

        assert(old_path);
        assert(new_path);

        mkdir_parents(new_path, 0755);

        if (symlink(old_path, new_path) >= 0) {
                add_file_change(changes, n_changes, UNIT_FILE_SYMLINK, new_path, old_path);
                return 0;
        }

        if (errno != EEXIST)
                return -errno;

        r = readlink_and_make_absolute(new_path, &dest);
        if (r < 0)
                return r;

        if (path_equal(dest, old_path)) {
                free(dest);
                return 0;
        }

        free(dest);

        if (force)
                return -EEXIST;

        unlink(new_path);

        if (symlink(old_path, new_path) >= 0) {
                add_file_change(changes, n_changes, UNIT_FILE_UNLINK, new_path, NULL);
                add_file_change(changes, n_changes, UNIT_FILE_SYMLINK, new_path, old_path);
                return 0;
        }

        return -errno;
}

static int install_info_symlink_alias(
                InstallInfo *i,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        char **s;
        int r = 0, q;

        assert(i);
        assert(config_path);

        STRV_FOREACH(s, i->aliases) {
                char *alias_path;

                alias_path = path_make_absolute(*s, config_path);

                if (!alias_path)
                        return -ENOMEM;

                q = create_symlink(i->path, alias_path, force, changes, n_changes);
                free(alias_path);

                if (r == 0)
                        r = q;
        }

        return r;
}

static int install_info_symlink_wants(
                InstallInfo *i,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        char **s;
        int r = 0, q;

        assert(i);
        assert(config_path);

        STRV_FOREACH(s, i->wanted_by) {
                char *path;

                if (!unit_name_is_valid_no_type(*s, true)) {
                        r = -EINVAL;
                        continue;
                }

                if (asprintf(&path, "%s/%s.wants/%s", config_path, *s, i->name) < 0)
                        return -ENOMEM;

                q = create_symlink(i->path, path, force, changes, n_changes);
                free(path);

                if (r == 0)
                        r = q;
        }

        return r;
}

static int install_info_symlink_link(
                InstallInfo *i,
                LookupPaths *paths,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        int r;
        char *path;

        assert(i);
        assert(paths);
        assert(config_path);
        assert(i->path);

        r = in_search_path(i->path, paths->unit_path);
        if (r != 0)
                return r;

        if (asprintf(&path, "%s/%s", config_path, i->name) < 0)
                return -ENOMEM;

        r = create_symlink(i->path, path, force, changes, n_changes);
        free(path);

        return r;
}

static int install_info_apply(
                InstallInfo *i,
                LookupPaths *paths,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        int r, q;

        assert(i);
        assert(paths);
        assert(config_path);

        r = install_info_symlink_alias(i, config_path, force, changes, n_changes);

        q = install_info_symlink_wants(i, config_path, force, changes, n_changes);
        if (r == 0)
                r = q;

        q = install_info_symlink_link(i, paths, config_path, force, changes, n_changes);
        if (r == 0)
                r = q;

        return r;
}

static int install_context_apply(
                InstallContext *c,
                LookupPaths *paths,
                const char *config_path,
                const char *root_dir,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        InstallInfo *i;
        int r = 0, q;

        assert(c);
        assert(paths);
        assert(config_path);

        while ((i = hashmap_first(c->will_install))) {

                q = hashmap_ensure_allocated(&c->have_installed, string_hash_func, string_compare_func);
                if (q < 0)
                        return q;

                assert_se(hashmap_move_one(c->have_installed, c->will_install, i->name) == 0);

                q = unit_file_search(c, i, paths, root_dir, false);
                if (q < 0) {
                        if (r >= 0)
                                r = q;

                        return r;
                } else if (r >= 0)
                        r += q;

                q = install_info_apply(i, paths, config_path, force, changes, n_changes);
                if (r >= 0 && q < 0)
                        r = q;
        }

        return r;
}

static int install_context_mark_for_removal(
                InstallContext *c,
                LookupPaths *paths,
                Set **remove_symlinks_to,
                const char *config_path,
                const char *root_dir) {

        InstallInfo *i;
        int r = 0, q;

        assert(c);
        assert(paths);
        assert(config_path);

        /* Marks all items for removal */

        while ((i = hashmap_first(c->will_install))) {

                q = hashmap_ensure_allocated(&c->have_installed, string_hash_func, string_compare_func);
                if (q < 0)
                        return q;

                assert_se(hashmap_move_one(c->have_installed, c->will_install, i->name) == 0);

                q = unit_file_search(c, i, paths, root_dir, false);
                if (q < 0) {
                        if (r >= 0)
                                r = q;

                        return r;
                } else if (r >= 0)
                        r += q;

                q = mark_symlink_for_removal(remove_symlinks_to, i->name);
                if (r >= 0 && q < 0)
                        r = q;
        }

        return r;
}

int unit_file_enable(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char *files[],
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        LookupPaths paths;
        InstallContext c;
        char **i, *config_path = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        zero(paths);
        zero(c);

        r = lookup_paths_init_from_scope(&paths, scope);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                goto finish;

        STRV_FOREACH(i, files) {
                r = install_info_add_auto(&c, *i);
                if (r < 0)
                        goto finish;
        }

        /* This will return the number of symlink rules that were
        supposed to be created, not the ones actually created. This is
        useful to determine whether the passed files hat any
        installation data at all. */
        r = install_context_apply(&c, &paths, config_path, root_dir, force, changes, n_changes);

finish:
        install_context_done(&c);
        lookup_paths_free(&paths);
        free(config_path);

        return r;
}

int unit_file_disable(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char *files[],
                UnitFileChange **changes,
                unsigned *n_changes) {

        LookupPaths paths;
        InstallContext c;
        char **i, *config_path = NULL;
        Set *remove_symlinks_to = NULL;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        zero(paths);
        zero(c);

        r = lookup_paths_init_from_scope(&paths, scope);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                goto finish;

        STRV_FOREACH(i, files) {
                r = install_info_add_auto(&c, *i);
                if (r < 0)
                        goto finish;
        }

        r = install_context_mark_for_removal(&c, &paths, &remove_symlinks_to, config_path, root_dir);

        q = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes);
        if (r == 0)
                r = q;

finish:
        install_context_done(&c);
        lookup_paths_free(&paths);
        set_free_free(remove_symlinks_to);
        free(config_path);

        return r;
}

int unit_file_reenable(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char *files[],
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        LookupPaths paths;
        InstallContext c;
        char **i, *config_path = NULL;
        Set *remove_symlinks_to = NULL;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        zero(paths);
        zero(c);

        r = lookup_paths_init_from_scope(&paths, scope);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                goto finish;

        STRV_FOREACH(i, files) {
                r = mark_symlink_for_removal(&remove_symlinks_to, *i);
                if (r < 0)
                        goto finish;

                r = install_info_add_auto(&c, *i);
                if (r < 0)
                        goto finish;
        }

        r = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes);

        /* Returns number of symlinks that where supposed to be installed. */
        q = install_context_apply(&c, &paths, config_path, root_dir, force, changes, n_changes);
        if (r == 0)
                r = q;

finish:
        lookup_paths_free(&paths);
        install_context_done(&c);
        set_free_free(remove_symlinks_to);
        free(config_path);

        return r;
}

UnitFileState unit_file_get_state(
                UnitFileScope scope,
                const char *root_dir,
                const char *name) {

        LookupPaths paths;
        UnitFileState state = _UNIT_FILE_STATE_INVALID;
        char **i, *path = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        zero(paths);

        if (root_dir && scope != UNIT_FILE_SYSTEM)
                return -EINVAL;

        if (!unit_name_is_valid_no_type(name, true))
                return -EINVAL;

        r = lookup_paths_init_from_scope(&paths, scope);
        if (r < 0)
                return r;

        STRV_FOREACH(i, paths.unit_path) {
                struct stat st;

                free(path);
                path = NULL;

                if (root_dir)
                        asprintf(&path, "%s/%s/%s", root_dir, *i, name);
                else
                        asprintf(&path, "%s/%s", *i, name);

                if (!path) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (lstat(path, &st) < 0) {
                        r = -errno;
                        if (errno == ENOENT)
                                continue;

                        goto finish;
                }

                if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
                        r = -ENOENT;
                        goto finish;
                }

                r = null_or_empty_path(path);
                if (r < 0 && r != -ENOENT)
                        goto finish;
                else if (r > 0) {
                        state = path_startswith(*i, "/run") ?
                                UNIT_FILE_MASKED_RUNTIME : UNIT_FILE_MASKED;
                        r = 0;
                        goto finish;
                }

                r = find_symlinks_in_scope(scope, root_dir, name, &state);
                if (r < 0) {
                        goto finish;
                } else if (r > 0) {
                        r = 0;
                        goto finish;
                }

                r = unit_file_can_install(&paths, root_dir, path, true);
                if (r < 0 && errno != -ENOENT)
                        goto finish;
                else if (r > 0) {
                        state = UNIT_FILE_DISABLED;
                        r = 0;
                        goto finish;
                } else if (r == 0) {
                        state = UNIT_FILE_STATIC;
                        r = 0;
                        goto finish;
                }
        }

finish:
        lookup_paths_free(&paths);
        free(path);

        return r < 0 ? r : state;
}

int unit_file_query_preset(UnitFileScope scope, const char *name) {
        char **files, **i;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        if (scope == UNIT_FILE_SYSTEM)
                r = conf_files_list(&files, ".preset",
                                    "/etc/systemd/system.preset",
                                    "/usr/local/lib/systemd/system.preset",
                                    "/usr/lib/systemd/system.preset",
                                    "/lib/systemd/system.preset",
                                    NULL);
        else if (scope == UNIT_FILE_GLOBAL)
                r = conf_files_list(&files, ".preset",
                                    "/etc/systemd/user.preset",
                                    "/usr/local/lib/systemd/user.preset",
                                    "/usr/lib/systemd/user.preset",
                                    NULL);
        else
                return 1;

        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                FILE *f;

                f = fopen(*i, "re");
                if (!f) {
                        if (errno == ENOENT)
                                continue;

                        r = -errno;
                        goto finish;
                }

                for (;;) {
                        char line[LINE_MAX], *l;

                        if (!fgets(line, sizeof(line), f))
                                break;

                        l = strstrip(line);
                        if (!*l)
                                continue;

                        if (strchr(COMMENTS, *l))
                                continue;

                        if (first_word(l, "enable")) {
                                l += 6;
                                l += strspn(l, WHITESPACE);

                                if (fnmatch(l, name, FNM_NOESCAPE) == 0) {
                                        r = 1;
                                        fclose(f);
                                        goto finish;
                                }
                        } else if (first_word(l, "disable")) {
                                l += 7;
                                l += strspn(l, WHITESPACE);

                                if (fnmatch(l, name, FNM_NOESCAPE) == 0) {
                                        r = 0;
                                        fclose(f);
                                        goto finish;
                                }
                        } else
                                log_debug("Couldn't parse line '%s'", l);
                }

                fclose(f);
        }

        /* Default is "enable" */
        r = 1;

finish:
        strv_free(files);

        return r;
}

int unit_file_preset(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char *files[],
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        LookupPaths paths;
        InstallContext plus, minus;
        char **i, *config_path = NULL;
        Set *remove_symlinks_to = NULL;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        zero(paths);
        zero(plus);
        zero(minus);

        r = lookup_paths_init_from_scope(&paths, scope);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                goto finish;

        STRV_FOREACH(i, files) {

                if (!unit_name_is_valid_no_type(*i, true)) {
                        r = -EINVAL;
                        goto finish;
                }

                r = unit_file_query_preset(scope, *i);
                if (r < 0)
                        goto finish;

                if (r)
                        r = install_info_add_auto(&plus, *i);
                else
                        r = install_info_add_auto(&minus, *i);

                if (r < 0)
                        goto finish;
        }

        r = install_context_mark_for_removal(&minus, &paths, &remove_symlinks_to, config_path, root_dir);

        q = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes);
        if (r == 0)
                r = q;

        /* Returns number of symlinks that where supposed to be installed. */
        q = install_context_apply(&plus, &paths, config_path, root_dir, force, changes, n_changes);
        if (r == 0)
                r = q;

finish:
        lookup_paths_free(&paths);
        install_context_done(&plus);
        install_context_done(&minus);
        set_free_free(remove_symlinks_to);
        free(config_path);

        return r;
}

int unit_file_get_list(
                UnitFileScope scope,
                const char *root_dir,
                Hashmap *h) {

        LookupPaths paths;
        char **i, *buf = NULL;
        DIR *d = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(h);

        zero(paths);

        if (root_dir && scope != UNIT_FILE_SYSTEM)
                return -EINVAL;

        r = lookup_paths_init_from_scope(&paths, scope);
        if (r < 0)
                return r;

        STRV_FOREACH(i, paths.unit_path) {
                struct dirent buffer, *de;
                const char *units_dir;

                free(buf);
                buf = NULL;

                if (root_dir) {
                        if (asprintf(&buf, "%s/%s", root_dir, *i) < 0) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        units_dir = buf;
                } else
                        units_dir = *i;

                if (d)
                        closedir(d);

                d = opendir(units_dir);
                if (!d) {
                        if (errno == ENOENT)
                                continue;

                        r = -errno;
                        goto finish;
                }

                for (;;) {
                        UnitFileList *f;

                        r = readdir_r(d, &buffer, &de);
                        if (r != 0) {
                                r = -r;
                                goto finish;
                        }

                        if (!de)
                                break;

                        if (ignore_file(de->d_name))
                                continue;

                        if (!unit_name_is_valid_no_type(de->d_name, true))
                                continue;

                        if (hashmap_get(h, de->d_name))
                                continue;

                        r = dirent_ensure_type(d, de);
                        if (r < 0) {
                                if (r == -ENOENT)
                                        continue;

                                goto finish;
                        }

                        if (de->d_type != DT_LNK && de->d_type != DT_REG)
                                continue;

                        f = new0(UnitFileList, 1);
                        if (!f) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        f->path = path_make_absolute(de->d_name, units_dir);
                        if (!f->path) {
                                free(f);
                                r = -ENOMEM;
                                goto finish;
                        }

                        r = null_or_empty_path(f->path);
                        if (r < 0 && r != -ENOENT) {
                                free(f->path);
                                free(f);
                                goto finish;
                        } else if (r > 0) {
                                f->state =
                                        path_startswith(*i, "/run") ?
                                        UNIT_FILE_MASKED_RUNTIME : UNIT_FILE_MASKED;
                                goto found;
                        }

                        r = find_symlinks_in_scope(scope, root_dir, de->d_name, &f->state);
                        if (r < 0) {
                                free(f->path);
                                free(f);
                                goto finish;
                        } else if (r > 0)
                                goto found;

                        r = unit_file_can_install(&paths, root_dir, f->path, true);
                        if (r < 0) {
                                free(f->path);
                                free(f);
                                goto finish;
                        } else if (r > 0) {
                                f->state = UNIT_FILE_DISABLED;
                                goto found;
                        } else {
                                f->state = UNIT_FILE_STATIC;
                                goto found;
                        }

                        free(f->path);
                        free(f);
                        continue;

                found:
                        r = hashmap_put(h, file_name_from_path(f->path), f);
                        if (r < 0) {
                                free(f->path);
                                free(f);
                                goto finish;
                        }
                }
        }

finish:
        lookup_paths_free(&paths);
        free(buf);

        if (d)
                closedir(d);

        return r;
}

static const char* const unit_file_state_table[_UNIT_FILE_STATE_MAX] = {
        [UNIT_FILE_ENABLED] = "enabled",
        [UNIT_FILE_ENABLED_RUNTIME] = "enabled-runtie",
        [UNIT_FILE_LINKED] = "linked",
        [UNIT_FILE_LINKED_RUNTIME] = "linked-runtime",
        [UNIT_FILE_MASKED] = "masked",
        [UNIT_FILE_MASKED_RUNTIME] = "masked-runtime",
        [UNIT_FILE_STATIC] = "static",
        [UNIT_FILE_DISABLED] = "disabled"
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_state, UnitFileState);

static const char* const unit_file_change_type_table[_UNIT_FILE_CHANGE_TYPE_MAX] = {
        [UNIT_FILE_SYMLINK] = "symlink",
        [UNIT_FILE_UNLINK] = "unlink",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_change_type, UnitFileChangeType);
