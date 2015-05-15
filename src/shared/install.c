/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty <of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
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
#include "path-util.h"
#include "path-lookup.h"
#include "strv.h"
#include "unit-name.h"
#include "install.h"
#include "conf-parser.h"
#include "conf-files.h"
#include "install-printf.h"
#include "special.h"

typedef struct {
        OrderedHashmap *will_install;
        OrderedHashmap *have_installed;
} InstallContext;

static int in_search_path(const char *path, char **search) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(path);

        r = path_get_parent(path, &parent);
        if (r < 0)
                return r;

        return strv_contains(search, parent);
}

static int get_config_path(UnitFileScope scope, bool runtime, const char *root_dir, char **ret) {
        char *p = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(ret);

        switch (scope) {

        case UNIT_FILE_SYSTEM:

                if (runtime)
                        p = path_join(root_dir, "/run/systemd/system", NULL);
                else
                        p = path_join(root_dir, SYSTEM_CONFIG_UNIT_PATH, NULL);
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

                if (root_dir)
                        return -EINVAL;

                if (runtime)
                        r = user_runtime_dir(&p);
                else
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

static int mark_symlink_for_removal(
                Set **remove_symlinks_to,
                const char *p) {

        char *n;
        int r;

        assert(p);

        r = set_ensure_allocated(remove_symlinks_to, &string_hash_ops);
        if (r < 0)
                return r;

        n = strdup(p);
        if (!n)
                return -ENOMEM;

        path_kill_slashes(n);

        r = set_consume(*remove_symlinks_to, n);
        if (r < 0)
                return r == -EEXIST ? 0 : r;

        return 0;
}

static int remove_marked_symlinks_fd(
                Set *remove_symlinks_to,
                int fd,
                const char *path,
                const char *config_path,
                bool *deleted,
                UnitFileChange **changes,
                unsigned *n_changes,
                char** instance_whitelist) {

        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        assert(remove_symlinks_to);
        assert(fd >= 0);
        assert(path);
        assert(config_path);
        assert(deleted);

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return -errno;
        }

        rewinddir(d);

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0) {
                        r = -errno;
                        break;
                }

                if (!de)
                        break;

                if (hidden_file(de->d_name))
                        continue;

                dirent_ensure_type(d, de);

                if (de->d_type == DT_DIR) {
                        int nfd, q;
                        _cleanup_free_ char *p = NULL;

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
                                safe_close(nfd);
                                return -ENOMEM;
                        }

                        /* This will close nfd, regardless whether it succeeds or not */
                        q = remove_marked_symlinks_fd(remove_symlinks_to, nfd, p, config_path, deleted, changes, n_changes, instance_whitelist);
                        if (q < 0 && r == 0)
                                r = q;

                } else if (de->d_type == DT_LNK) {
                        _cleanup_free_ char *p = NULL, *dest = NULL;
                        int q;
                        bool found;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        if (unit_name_is_valid(de->d_name, UNIT_NAME_INSTANCE) &&
                            instance_whitelist &&
                            !strv_contains(instance_whitelist, de->d_name)) {

                                _cleanup_free_ char *w;

                                /* OK, the file is not listed directly
                                 * in the whitelist, so let's check if
                                 * the template of it might be
                                 * listed. */

                                r = unit_name_template(de->d_name, &w);
                                if (r < 0)
                                        return r;

                                if (!strv_contains(instance_whitelist, w))
                                        continue;
                        }

                        p = path_make_absolute(de->d_name, path);
                        if (!p)
                                return -ENOMEM;

                        q = readlink_and_canonicalize(p, &dest);
                        if (q < 0) {
                                if (q == -ENOENT)
                                        continue;

                                if (r == 0)
                                        r = q;
                                continue;
                        }

                        found =
                                set_get(remove_symlinks_to, dest) ||
                                set_get(remove_symlinks_to, basename(dest));

                        if (!found)
                                continue;

                        if (unlink(p) < 0 && errno != ENOENT) {
                                if (r == 0)
                                        r = -errno;
                                continue;
                        }

                        path_kill_slashes(p);
                        rmdir_parents(p, config_path);
                        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, p, NULL);

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

        return r;
}

static int remove_marked_symlinks(
                Set *remove_symlinks_to,
                const char *config_path,
                UnitFileChange **changes,
                unsigned *n_changes,
                char** instance_whitelist) {

        _cleanup_close_ int fd = -1;
        int r = 0;
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

                cfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (cfd < 0) {
                        r = -errno;
                        break;
                }

                /* This takes possession of cfd and closes it */
                q = remove_marked_symlinks_fd(remove_symlinks_to, cfd, config_path, config_path, &deleted, changes, n_changes, instance_whitelist);
                if (r == 0)
                        r = q;
        } while (deleted);

        return r;
}

static int find_symlinks_fd(
                const char *name,
                int fd,
                const char *path,
                const char *config_path,
                bool *same_name_link) {

        int r = 0;
        _cleanup_closedir_ DIR *d = NULL;

        assert(name);
        assert(fd >= 0);
        assert(path);
        assert(config_path);
        assert(same_name_link);

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return -errno;
        }

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0)
                        return -errno;

                if (!de)
                        return r;

                if (hidden_file(de->d_name))
                        continue;

                dirent_ensure_type(d, de);

                if (de->d_type == DT_DIR) {
                        int nfd, q;
                        _cleanup_free_ char *p = NULL;

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
                                safe_close(nfd);
                                return -ENOMEM;
                        }

                        /* This will close nfd, regardless whether it succeeds or not */
                        q = find_symlinks_fd(name, nfd, p, config_path, same_name_link);
                        if (q > 0)
                                return 1;
                        if (r == 0)
                                r = q;

                } else if (de->d_type == DT_LNK) {
                        _cleanup_free_ char *p = NULL, *dest = NULL;
                        bool found_path, found_dest, b = false;
                        int q;

                        /* Acquire symlink name */
                        p = path_make_absolute(de->d_name, path);
                        if (!p)
                                return -ENOMEM;

                        /* Acquire symlink destination */
                        q = readlink_and_canonicalize(p, &dest);
                        if (q < 0) {
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
                                found_dest = streq(basename(dest), name);

                        if (found_path && found_dest) {
                                _cleanup_free_ char *t = NULL;

                                /* Filter out same name links in the main
                                 * config path */
                                t = path_make_absolute(name, config_path);
                                if (!t)
                                        return -ENOMEM;

                                b = path_equal(t, p);
                        }

                        if (b)
                                *same_name_link = true;
                        else if (found_path || found_dest)
                                return 1;
                }
        }
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
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        /* This takes possession of fd and closes it */
        return find_symlinks_fd(name, fd, config_path, config_path, same_name_link);
}

static int find_symlinks_in_scope(
                UnitFileScope scope,
                const char *root_dir,
                const char *name,
                UnitFileState *state) {

        int r;
        _cleanup_free_ char *normal_path = NULL, *runtime_path = NULL;
        bool same_name_link_runtime = false, same_name_link = false;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        /* First look in runtime config path */
        r = get_config_path(scope, true, root_dir, &normal_path);
        if (r < 0)
                return r;

        r = find_symlinks(name, normal_path, &same_name_link_runtime);
        if (r < 0)
                return r;
        else if (r > 0) {
                *state = UNIT_FILE_ENABLED_RUNTIME;
                return r;
        }

        /* Then look in the normal config path */
        r = get_config_path(scope, false, root_dir, &runtime_path);
        if (r < 0)
                return r;

        r = find_symlinks(name, runtime_path, &same_name_link);
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
                char **files,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        char **i;
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = get_config_path(scope, runtime, root_dir, &prefix);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                _cleanup_free_ char *path = NULL;

                if (!unit_name_is_valid(*i, UNIT_NAME_ANY)) {
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
                        unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, path, "/dev/null");
                        continue;
                }

                if (errno == EEXIST) {

                        if (null_or_empty_path(path) > 0)
                                continue;

                        if (force) {
                                if (symlink_atomic("/dev/null", path) >= 0) {
                                        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, path, NULL);
                                        unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, path, "/dev/null");
                                        continue;
                                }
                        }

                        if (r == 0)
                                r = -EEXIST;
                } else {
                        if (r == 0)
                                r = -errno;
                }
        }

        return r;
}

int unit_file_unmask(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char **files,
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
                _cleanup_free_ char *path = NULL;

                if (!unit_name_is_valid(*i, UNIT_NAME_ANY)) {
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
                        if (unlink(path) < 0)
                                q = -errno;
                        else {
                                q = mark_symlink_for_removal(&remove_symlinks_to, path);
                                unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, path, NULL);
                        }
                }

                if (q != -ENOENT && r == 0)
                        r = q;
        }


finish:
        q = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes, files);
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
                char **files,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        char **i;
        _cleanup_free_ char *config_path = NULL;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                _cleanup_free_ char *path = NULL;
                char *fn;
                struct stat st;

                fn = basename(*i);

                if (!path_is_absolute(*i) ||
                    !unit_name_is_valid(fn, UNIT_NAME_ANY)) {
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
                if (q < 0)
                        return q;

                if (q > 0)
                        continue;

                path = path_make_absolute(fn, config_path);
                if (!path)
                        return -ENOMEM;

                if (symlink(*i, path) >= 0) {
                        unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, path, *i);
                        continue;
                }

                if (errno == EEXIST) {
                        _cleanup_free_ char *dest = NULL;

                        q = readlink_and_make_absolute(path, &dest);
                        if (q < 0 && errno != ENOENT) {
                                if (r == 0)
                                        r = q;
                                continue;
                        }

                        if (q >= 0 && path_equal(dest, *i))
                                continue;

                        if (force) {
                                if (symlink_atomic(*i, path) >= 0) {
                                        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, path, NULL);
                                        unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, path, *i);
                                        continue;
                                }
                        }

                        if (r == 0)
                                r = -EEXIST;
                } else {
                        if (r == 0)
                                r = -errno;
                }
        }

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

int unit_file_changes_add(
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

        path_kill_slashes(c[i].path);

        if (source) {
                c[i].source = strdup(source);
                if (!c[i].source) {
                        free(c[i].path);
                        return -ENOMEM;
                }

                path_kill_slashes(c[i].path);
        } else
                c[i].source = NULL;

        *n_changes = i+1;
        return 0;
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

static void install_info_free(UnitFileInstallInfo *i) {
        assert(i);

        free(i->name);
        free(i->path);
        strv_free(i->aliases);
        strv_free(i->wanted_by);
        strv_free(i->required_by);
        strv_free(i->also);
        free(i->default_instance);
        free(i);
}

static void install_info_hashmap_free(OrderedHashmap *m) {
        UnitFileInstallInfo *i;

        if (!m)
                return;

        while ((i = ordered_hashmap_steal_first(m)))
                install_info_free(i);

        ordered_hashmap_free(m);
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
        UnitFileInstallInfo *i = NULL;
        int r;

        assert(c);
        assert(name || path);

        if (!name)
                name = basename(path);

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        if (ordered_hashmap_get(c->have_installed, name) ||
            ordered_hashmap_get(c->will_install, name))
                return 0;

        r = ordered_hashmap_ensure_allocated(&c->will_install, &string_hash_ops);
        if (r < 0)
                return r;

        i = new0(UnitFileInstallInfo, 1);
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

        r = ordered_hashmap_put(c->will_install, i->name, i);
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
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t l;
        const char *word, *state;
        InstallContext *c = data;
        UnitFileInstallInfo *i = userdata;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ char *n;
                int r;

                n = strndup(word, l);
                if (!n)
                        return -ENOMEM;

                r = install_info_add(c, n, NULL);
                if (r < 0)
                        return r;

                r = strv_extend(&i->also, n);
                if (r < 0)
                        return r;
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

static int config_parse_user(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        UnitFileInstallInfo *i = data;
        char *printed;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = install_full_printf(i, rvalue, &printed);
        if (r < 0)
                return r;

        free(i->user);
        i->user = printed;

        return 0;
}

static int config_parse_default_instance(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        UnitFileInstallInfo *i = data;
        char *printed;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = install_full_printf(i, rvalue, &printed);
        if (r < 0)
                return r;

        if (!unit_instance_is_valid(printed)) {
                free(printed);
                return -EINVAL;
        }

        free(i->default_instance);
        i->default_instance = printed;

        return 0;
}

static int unit_file_load(
                InstallContext *c,
                UnitFileInstallInfo *info,
                const char *path,
                const char *root_dir,
                bool allow_symlink,
                bool load,
                bool *also) {

        const ConfigTableItem items[] = {
                { "Install", "Alias",           config_parse_strv,             0, &info->aliases           },
                { "Install", "WantedBy",        config_parse_strv,             0, &info->wanted_by         },
                { "Install", "RequiredBy",      config_parse_strv,             0, &info->required_by       },
                { "Install", "DefaultInstance", config_parse_default_instance, 0, info                     },
                { "Install", "Also",            config_parse_also,             0, c                        },
                { "Exec",    "User",            config_parse_user,             0, info                     },
                {}
        };

        _cleanup_fclose_ FILE *f = NULL;
        int fd, r;

        assert(c);
        assert(info);
        assert(path);

        if (!isempty(root_dir))
                path = strjoina(root_dir, "/", path);

        if (!load) {
                r = access(path, F_OK) ? -errno : 0;
                return r;
        }

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|(allow_symlink ? 0 : O_NOFOLLOW));
        if (fd < 0)
                return -errno;

        f = fdopen(fd, "re");
        if (!f) {
                safe_close(fd);
                return -ENOMEM;
        }

        r = config_parse(NULL, path, f,
                         NULL,
                         config_item_table_lookup, items,
                         true, true, false, info);
        if (r < 0)
                return r;

        if (also)
                *also = !strv_isempty(info->also);

        return
                (int) strv_length(info->aliases) +
                (int) strv_length(info->wanted_by) +
                (int) strv_length(info->required_by);
}

static int unit_file_search(
                InstallContext *c,
                UnitFileInstallInfo *info,
                const LookupPaths *paths,
                const char *root_dir,
                bool allow_symlink,
                bool load,
                bool *also) {

        char **p;
        int r;

        assert(c);
        assert(info);
        assert(paths);

        if (info->path)
                return unit_file_load(c, info, info->path, root_dir, allow_symlink, load, also);

        assert(info->name);

        STRV_FOREACH(p, paths->unit_path) {
                _cleanup_free_ char *path = NULL;

                path = strjoin(*p, "/", info->name, NULL);
                if (!path)
                        return -ENOMEM;

                r = unit_file_load(c, info, path, root_dir, allow_symlink, load, also);
                if (r >= 0) {
                        info->path = path;
                        path = NULL;
                        return r;
                }
                if (r != -ENOENT && r != -ELOOP)
                        return r;
        }

        if (unit_name_is_valid(info->name, UNIT_NAME_INSTANCE)) {

                /* Unit file doesn't exist, however instance
                 * enablement was requested.  We will check if it is
                 * possible to load template unit file. */

                _cleanup_free_ char *template = NULL;

                r = unit_name_template(info->name, &template);
                if (r < 0)
                        return r;

                STRV_FOREACH(p, paths->unit_path) {
                        _cleanup_free_ char *path = NULL;

                        path = strjoin(*p, "/", template, NULL);
                        if (!path)
                                return -ENOMEM;

                        r = unit_file_load(c, info, path, root_dir, allow_symlink, load, also);
                        if (r >= 0) {
                                info->path = path;
                                path = NULL;
                                return r;
                        }
                        if (r != -ENOENT && r != -ELOOP)
                                return r;
                }
        }

        return -ENOENT;
}

static int unit_file_can_install(
                const LookupPaths *paths,
                const char *root_dir,
                const char *name,
                bool allow_symlink,
                bool *also) {

        _cleanup_(install_context_done) InstallContext c = {};
        UnitFileInstallInfo *i;
        int r;

        assert(paths);
        assert(name);

        r = install_info_add_auto(&c, name);
        if (r < 0)
                return r;

        assert_se(i = ordered_hashmap_first(c.will_install));

        r = unit_file_search(&c, i, paths, root_dir, allow_symlink, true, also);

        if (r >= 0)
                r =
                        (int) strv_length(i->aliases) +
                        (int) strv_length(i->wanted_by) +
                        (int) strv_length(i->required_by);

        return r;
}

static int create_symlink(
                const char *old_path,
                const char *new_path,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_free_ char *dest = NULL;
        int r;

        assert(old_path);
        assert(new_path);

        mkdir_parents_label(new_path, 0755);

        if (symlink(old_path, new_path) >= 0) {
                unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, new_path, old_path);
                return 0;
        }

        if (errno != EEXIST)
                return -errno;

        r = readlink_and_make_absolute(new_path, &dest);
        if (r < 0)
                return r;

        if (path_equal(dest, old_path))
                return 0;

        if (!force)
                return -EEXIST;

        r = symlink_atomic(old_path, new_path);
        if (r < 0)
                return r;

        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, new_path, NULL);
        unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, new_path, old_path);

        return 0;
}

static int install_info_symlink_alias(
                UnitFileInstallInfo *i,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        char **s;
        int r = 0, q;

        assert(i);
        assert(config_path);

        STRV_FOREACH(s, i->aliases) {
                _cleanup_free_ char *alias_path = NULL, *dst = NULL;

                q = install_full_printf(i, *s, &dst);
                if (q < 0)
                        return q;

                alias_path = path_make_absolute(dst, config_path);
                if (!alias_path)
                        return -ENOMEM;

                q = create_symlink(i->path, alias_path, force, changes, n_changes);
                if (r == 0)
                        r = q;
        }

        return r;
}

static int install_info_symlink_wants(
                UnitFileInstallInfo *i,
                const char *config_path,
                char **list,
                const char *suffix,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_free_ char *buf = NULL;
        const char *n;
        char **s;
        int r = 0, q;

        assert(i);
        assert(config_path);

        if (unit_name_is_valid(i->name, UNIT_NAME_TEMPLATE)) {

                /* Don't install any symlink if there's no default
                 * instance configured */

                if (!i->default_instance)
                        return 0;

                r = unit_name_replace_instance(i->name, i->default_instance, &buf);
                if (r < 0)
                        return r;

                n = buf;
        } else
                n = i->name;

        STRV_FOREACH(s, list) {
                _cleanup_free_ char *path = NULL, *dst = NULL;

                q = install_full_printf(i, *s, &dst);
                if (q < 0)
                        return q;

                if (!unit_name_is_valid(dst, UNIT_NAME_ANY)) {
                        r = -EINVAL;
                        continue;
                }

                path = strjoin(config_path, "/", dst, suffix, n, NULL);
                if (!path)
                        return -ENOMEM;

                q = create_symlink(i->path, path, force, changes, n_changes);
                if (r == 0)
                        r = q;
        }

        return r;
}

static int install_info_symlink_link(
                UnitFileInstallInfo *i,
                const LookupPaths *paths,
                const char *config_path,
                const char *root_dir,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_free_ char *path = NULL;
        int r;

        assert(i);
        assert(paths);
        assert(config_path);
        assert(i->path);

        r = in_search_path(i->path, paths->unit_path);
        if (r != 0)
                return r;

        path = strjoin(config_path, "/", i->name, NULL);
        if (!path)
                return -ENOMEM;

        return create_symlink(i->path, path, force, changes, n_changes);
}

static int install_info_apply(
                UnitFileInstallInfo *i,
                const LookupPaths *paths,
                const char *config_path,
                const char *root_dir,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        int r, q;

        assert(i);
        assert(paths);
        assert(config_path);

        r = install_info_symlink_alias(i, config_path, force, changes, n_changes);

        q = install_info_symlink_wants(i, config_path, i->wanted_by, ".wants/", force, changes, n_changes);
        if (r == 0)
                r = q;

        q = install_info_symlink_wants(i, config_path, i->required_by, ".requires/", force, changes, n_changes);
        if (r == 0)
                r = q;

        q = install_info_symlink_link(i, paths, config_path, root_dir, force, changes, n_changes);
        if (r == 0)
                r = q;

        return r;
}

static int install_context_apply(
                InstallContext *c,
                const LookupPaths *paths,
                const char *config_path,
                const char *root_dir,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        UnitFileInstallInfo *i;
        int r, q;

        assert(c);
        assert(paths);
        assert(config_path);

        if (!ordered_hashmap_isempty(c->will_install)) {
                r = ordered_hashmap_ensure_allocated(&c->have_installed, &string_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_hashmap_reserve(c->have_installed, ordered_hashmap_size(c->will_install));
                if (r < 0)
                        return r;
        }

        r = 0;
        while ((i = ordered_hashmap_first(c->will_install))) {
                assert_se(ordered_hashmap_move_one(c->have_installed, c->will_install, i->name) == 0);

                q = unit_file_search(c, i, paths, root_dir, false, true, NULL);
                if (q < 0) {
                        if (r >= 0)
                                r = q;

                        return r;
                } else if (r >= 0)
                        r += q;

                q = install_info_apply(i, paths, config_path, root_dir, force, changes, n_changes);
                if (r >= 0 && q < 0)
                        r = q;
        }

        return r;
}

static int install_context_mark_for_removal(
                InstallContext *c,
                const LookupPaths *paths,
                Set **remove_symlinks_to,
                const char *config_path,
                const char *root_dir) {

        UnitFileInstallInfo *i;
        int r, q;

        assert(c);
        assert(paths);
        assert(config_path);

        /* Marks all items for removal */

        if (!ordered_hashmap_isempty(c->will_install)) {
                r = ordered_hashmap_ensure_allocated(&c->have_installed, &string_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_hashmap_reserve(c->have_installed, ordered_hashmap_size(c->will_install));
                if (r < 0)
                        return r;
        }

        r = 0;
        while ((i = ordered_hashmap_first(c->will_install))) {
                assert_se(ordered_hashmap_move_one(c->have_installed, c->will_install, i->name) == 0);

                q = unit_file_search(c, i, paths, root_dir, false, true, NULL);
                if (q == -ENOENT) {
                        /* do nothing */
                } else if (q < 0) {
                        if (r >= 0)
                                r = q;

                        return r;
                } else if (r >= 0)
                        r += q;

                if (unit_name_is_valid(i->name, UNIT_NAME_INSTANCE)) {
                        char *unit_file;

                        if (i->path) {
                                unit_file = basename(i->path);

                                if (unit_name_is_valid(unit_file, UNIT_NAME_INSTANCE))
                                        /* unit file named as instance exists, thus all symlinks
                                         * pointing to it will be removed */
                                        q = mark_symlink_for_removal(remove_symlinks_to, i->name);
                                else
                                        /* does not exist, thus we will mark for removal symlinks
                                         * to template unit file */
                                        q = mark_symlink_for_removal(remove_symlinks_to, unit_file);
                        } else {
                                /* If i->path is not set, it means that we didn't actually find
                                 * the unit file. But we can still remove symlinks to the
                                 * nonexistent template. */
                                r = unit_name_template(i->name, &unit_file);
                                if (r < 0)
                                        return r;

                                q = mark_symlink_for_removal(remove_symlinks_to, unit_file);
                                free(unit_file);
                        }
                } else
                        q = mark_symlink_for_removal(remove_symlinks_to, i->name);

                if (r >= 0 && q < 0)
                        r = q;
        }

        return r;
}

int unit_file_add_dependency(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char **files,
                char *target,
                UnitDependency dep,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        _cleanup_free_ char *config_path = NULL;
        char **i;
        int r;
        UnitFileInstallInfo *info;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                UnitFileState state;

                state = unit_file_get_state(scope, root_dir, *i);
                if (state < 0)
                        return log_error_errno(state, "Failed to get unit file state for %s: %m", *i);

                if (state == UNIT_FILE_MASKED || state == UNIT_FILE_MASKED_RUNTIME) {
                        log_error("Failed to enable unit: Unit %s is masked", *i);
                        return -EOPNOTSUPP;
                }

                r = install_info_add_auto(&c, *i);
                if (r < 0)
                        return r;
        }

        if (!ordered_hashmap_isempty(c.will_install)) {
                r = ordered_hashmap_ensure_allocated(&c.have_installed, &string_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_hashmap_reserve(c.have_installed, ordered_hashmap_size(c.will_install));
                if (r < 0)
                        return r;
        }

        while ((info = ordered_hashmap_first(c.will_install))) {
                assert_se(ordered_hashmap_move_one(c.have_installed, c.will_install, info->name) == 0);

                r = unit_file_search(&c, info, &paths, root_dir, false, false, NULL);
                if (r < 0)
                        return r;

                if (dep == UNIT_WANTS)
                        r = strv_extend(&info->wanted_by, target);
                else if (dep == UNIT_REQUIRES)
                        r = strv_extend(&info->required_by, target);
                else
                        r = -EINVAL;

                if (r < 0)
                        return r;

                r = install_info_apply(info, &paths, config_path, root_dir, force, changes, n_changes);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_file_enable(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char **files,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        char **i;
        _cleanup_free_ char *config_path = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                UnitFileState state;

                /* We only want to know if this unit is masked, so we ignore
                 * errors from unit_file_get_state, deferring other checks.
                 * This allows templated units to be enabled on the fly. */
                state = unit_file_get_state(scope, root_dir, *i);
                if (state == UNIT_FILE_MASKED || state == UNIT_FILE_MASKED_RUNTIME) {
                        log_error("Failed to enable unit: Unit %s is masked", *i);
                        return -EOPNOTSUPP;
                }

                r = install_info_add_auto(&c, *i);
                if (r < 0)
                        return r;
        }

        /* This will return the number of symlink rules that were
        supposed to be created, not the ones actually created. This is
        useful to determine whether the passed files had any
        installation data at all. */

        return install_context_apply(&c, &paths, config_path, root_dir, force, changes, n_changes);
}

int unit_file_disable(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        char **i;
        _cleanup_free_ char *config_path = NULL;
        _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                r = install_info_add_auto(&c, *i);
                if (r < 0)
                        return r;
        }

        r = install_context_mark_for_removal(&c, &paths, &remove_symlinks_to, config_path, root_dir);

        q = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes, files);
        if (r >= 0)
                r = q;

        return r;
}

int unit_file_reenable(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char **files,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {
        int r;

        r = unit_file_disable(scope, runtime, root_dir, files,
                              changes, n_changes);
        if (r < 0)
                return r;

        return unit_file_enable(scope, runtime, root_dir, files, force,
                                changes, n_changes);
}

int unit_file_set_default(
                UnitFileScope scope,
                const char *root_dir,
                const char *file,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        _cleanup_free_ char *config_path = NULL;
        char *path;
        int r;
        UnitFileInstallInfo *i = NULL;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(file);

        if (unit_name_to_type(file) != UNIT_TARGET)
                return -EINVAL;

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        r = get_config_path(scope, false, root_dir, &config_path);
        if (r < 0)
                return r;

        r = install_info_add_auto(&c, file);
        if (r < 0)
                return r;

        assert_se(i = ordered_hashmap_first(c.will_install));

        r = unit_file_search(&c, i, &paths, root_dir, false, true, NULL);
        if (r < 0)
                return r;

        path = strjoina(config_path, "/" SPECIAL_DEFAULT_TARGET);

        r = create_symlink(i->path, path, force, changes, n_changes);
        if (r < 0)
                return r;

        return 0;
}

int unit_file_get_default(
                UnitFileScope scope,
                const char *root_dir,
                char **name) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        char **p;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(p, paths.unit_path) {
                _cleanup_free_ char *path = NULL, *tmp = NULL;
                char *n;

                path = path_join(root_dir, *p, SPECIAL_DEFAULT_TARGET);
                if (!path)
                        return -ENOMEM;

                r = readlink_malloc(path, &tmp);
                if (r == -ENOENT)
                        continue;
                else if (r == -EINVAL)
                        /* not a symlink */
                        n = strdup(SPECIAL_DEFAULT_TARGET);
                else if (r < 0)
                        return r;
                else
                        n = strdup(basename(tmp));

                if (!n)
                        return -ENOMEM;

                *name = n;
                return 0;
        }

        return -ENOENT;
}

UnitFileState unit_file_lookup_state(
                UnitFileScope scope,
                const char *root_dir,
                const LookupPaths *paths,
                const char *name) {

        UnitFileState state = _UNIT_FILE_STATE_INVALID;
        char **i;
        _cleanup_free_ char *path = NULL;
        int r = 0;

        assert(paths);

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        STRV_FOREACH(i, paths->unit_path) {
                struct stat st;
                char *partial;
                bool also = false;

                free(path);
                path = path_join(root_dir, *i, name);
                if (!path)
                        return -ENOMEM;

                if (root_dir)
                        partial = path + strlen(root_dir);
                else
                        partial = path;

                /*
                 * Search for a unit file in our default paths, to
                 * be sure, that there are no broken symlinks.
                 */
                if (lstat(path, &st) < 0) {
                        r = -errno;
                        if (errno != ENOENT)
                                return r;

                        if (!unit_name_is_valid(name, UNIT_NAME_INSTANCE))
                                continue;
                } else {
                        if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
                                return -ENOENT;

                        r = null_or_empty_path(path);
                        if (r < 0 && r != -ENOENT)
                                return r;
                        else if (r > 0) {
                                state = path_startswith(*i, "/run") ? UNIT_FILE_MASKED_RUNTIME : UNIT_FILE_MASKED;
                                return state;
                        }
                }

                r = find_symlinks_in_scope(scope, root_dir, name, &state);
                if (r < 0)
                        return r;
                else if (r > 0)
                        return state;

                r = unit_file_can_install(paths, root_dir, partial, true, &also);
                if (r < 0 && errno != ENOENT)
                        return r;
                else if (r > 0)
                        return UNIT_FILE_DISABLED;
                else if (r == 0) {
                        if (also)
                                return UNIT_FILE_INDIRECT;
                        return UNIT_FILE_STATIC;
                }
        }

        return r < 0 ? r : state;
}

UnitFileState unit_file_get_state(
                UnitFileScope scope,
                const char *root_dir,
                const char *name) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        if (root_dir && scope != UNIT_FILE_SYSTEM)
                return -EINVAL;

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        return unit_file_lookup_state(scope, root_dir, &paths, name);
}

int unit_file_query_preset(UnitFileScope scope, const char *root_dir, const char *name) {
        _cleanup_strv_free_ char **files = NULL;
        char **p;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        if (scope == UNIT_FILE_SYSTEM)
                r = conf_files_list(&files, ".preset", root_dir,
                                    "/etc/systemd/system-preset",
                                    "/usr/local/lib/systemd/system-preset",
                                    "/usr/lib/systemd/system-preset",
#ifdef HAVE_SPLIT_USR
                                    "/lib/systemd/system-preset",
#endif
                                    NULL);
        else if (scope == UNIT_FILE_GLOBAL)
                r = conf_files_list(&files, ".preset", root_dir,
                                    "/etc/systemd/user-preset",
                                    "/usr/local/lib/systemd/user-preset",
                                    "/usr/lib/systemd/user-preset",
                                    NULL);
        else
                return 1;

        if (r < 0)
                return r;

        STRV_FOREACH(p, files) {
                _cleanup_fclose_ FILE *f;

                f = fopen(*p, "re");
                if (!f) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                for (;;) {
                        char line[LINE_MAX], *l;

                        if (!fgets(line, sizeof(line), f))
                                break;

                        l = strstrip(line);
                        if (!*l)
                                continue;

                        if (strchr(COMMENTS "\n", *l))
                                continue;

                        if (first_word(l, "enable")) {
                                l += 6;
                                l += strspn(l, WHITESPACE);

                                if (fnmatch(l, name, FNM_NOESCAPE) == 0) {
                                        log_debug("Preset file says enable %s.", name);
                                        return 1;
                                }

                        } else if (first_word(l, "disable")) {
                                l += 7;
                                l += strspn(l, WHITESPACE);

                                if (fnmatch(l, name, FNM_NOESCAPE) == 0) {
                                        log_debug("Preset file says disable %s.", name);
                                        return 0;
                                }

                        } else
                                log_debug("Couldn't parse line '%s'", l);
                }
        }

        /* Default is "enable" */
        log_debug("Preset file doesn't say anything about %s, enabling.", name);
        return 1;
}

int unit_file_preset(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                char **files,
                UnitFilePresetMode mode,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_(install_context_done) InstallContext plus = {}, minus = {};
        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        _cleanup_free_ char *config_path = NULL;
        char **i;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(mode < _UNIT_FILE_PRESET_MAX);

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {

                if (!unit_name_is_valid(*i, UNIT_NAME_ANY))
                        return -EINVAL;

                r = unit_file_query_preset(scope, root_dir, *i);
                if (r < 0)
                        return r;

                if (r && mode != UNIT_FILE_PRESET_DISABLE_ONLY)
                        r = install_info_add_auto(&plus, *i);
                else if (!r && mode != UNIT_FILE_PRESET_ENABLE_ONLY)
                        r = install_info_add_auto(&minus, *i);
                else
                        r = 0;
                if (r < 0)
                        return r;
        }

        r = 0;

        if (mode != UNIT_FILE_PRESET_ENABLE_ONLY) {
                _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;

                r = install_context_mark_for_removal(&minus, &paths, &remove_symlinks_to, config_path, root_dir);

                q = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes, files);
                if (r == 0)
                        r = q;
        }

        if (mode != UNIT_FILE_PRESET_DISABLE_ONLY) {
                /* Returns number of symlinks that where supposed to be installed. */
                q = install_context_apply(&plus, &paths, config_path, root_dir, force, changes, n_changes);
                if (r == 0)
                        r = q;
        }

        return r;
}

int unit_file_preset_all(
                UnitFileScope scope,
                bool runtime,
                const char *root_dir,
                UnitFilePresetMode mode,
                bool force,
                UnitFileChange **changes,
                unsigned *n_changes) {

        _cleanup_(install_context_done) InstallContext plus = {}, minus = {};
        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        _cleanup_free_ char *config_path = NULL;
        char **i;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(mode < _UNIT_FILE_PRESET_MAX);

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        r = get_config_path(scope, runtime, root_dir, &config_path);
        if (r < 0)
                return r;

        STRV_FOREACH(i, paths.unit_path) {
                _cleanup_closedir_ DIR *d = NULL;
                _cleanup_free_ char *units_dir;

                units_dir = path_join(root_dir, *i, NULL);
                if (!units_dir)
                        return -ENOMEM;

                d = opendir(units_dir);
                if (!d) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                for (;;) {
                        struct dirent *de;

                        errno = 0;
                        de = readdir(d);
                        if (!de && errno != 0)
                                return -errno;

                        if (!de)
                                break;

                        if (hidden_file(de->d_name))
                                continue;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        dirent_ensure_type(d, de);

                        if (de->d_type != DT_REG)
                                continue;

                        r = unit_file_query_preset(scope, root_dir, de->d_name);
                        if (r < 0)
                                return r;

                        if (r && mode != UNIT_FILE_PRESET_DISABLE_ONLY)
                                r = install_info_add_auto(&plus, de->d_name);
                        else if (!r && mode != UNIT_FILE_PRESET_ENABLE_ONLY)
                                r = install_info_add_auto(&minus, de->d_name);
                        else
                                r = 0;
                        if (r < 0)
                                return r;
                }
        }

        r = 0;

        if (mode != UNIT_FILE_PRESET_ENABLE_ONLY) {
                _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;

                r = install_context_mark_for_removal(&minus, &paths, &remove_symlinks_to, config_path, root_dir);

                q = remove_marked_symlinks(remove_symlinks_to, config_path, changes, n_changes, NULL);
                if (r == 0)
                        r = q;
        }

        if (mode != UNIT_FILE_PRESET_DISABLE_ONLY) {
                q = install_context_apply(&plus, &paths, config_path, root_dir, force, changes, n_changes);
                if (r == 0)
                        r = q;
        }

        return r;
}

static void unit_file_list_free_one(UnitFileList *f) {
        if (!f)
                return;

        free(f->path);
        free(f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UnitFileList*, unit_file_list_free_one);

int unit_file_get_list(
                UnitFileScope scope,
                const char *root_dir,
                Hashmap *h) {

        _cleanup_lookup_paths_free_ LookupPaths paths = {};
        char **i;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(h);

        if (root_dir && scope != UNIT_FILE_SYSTEM)
                return -EINVAL;

        if (root_dir) {
                r = access(root_dir, F_OK);
                if (r < 0)
                        return -errno;
        }

        r = lookup_paths_init_from_scope(&paths, scope, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(i, paths.unit_path) {
                _cleanup_closedir_ DIR *d = NULL;
                _cleanup_free_ char *units_dir;

                units_dir = path_join(root_dir, *i, NULL);
                if (!units_dir)
                        return -ENOMEM;

                d = opendir(units_dir);
                if (!d) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                for (;;) {
                        _cleanup_(unit_file_list_free_onep) UnitFileList *f = NULL;
                        struct dirent *de;
                        _cleanup_free_ char *path = NULL;

                        errno = 0;
                        de = readdir(d);
                        if (!de && errno != 0)
                                return -errno;

                        if (!de)
                                break;

                        if (hidden_file(de->d_name))
                                continue;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        if (hashmap_get(h, de->d_name))
                                continue;

                        dirent_ensure_type(d, de);

                        if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                                continue;

                        f = new0(UnitFileList, 1);
                        if (!f)
                                return -ENOMEM;

                        f->path = path_make_absolute(de->d_name, units_dir);
                        if (!f->path)
                                return -ENOMEM;

                        r = null_or_empty_path(f->path);
                        if (r < 0 && r != -ENOENT)
                                return r;
                        else if (r > 0) {
                                f->state =
                                        path_startswith(*i, "/run") ?
                                        UNIT_FILE_MASKED_RUNTIME : UNIT_FILE_MASKED;
                                goto found;
                        }

                        r = find_symlinks_in_scope(scope, root_dir, de->d_name, &f->state);
                        if (r < 0)
                                return r;
                        else if (r > 0) {
                                f->state = UNIT_FILE_ENABLED;
                                goto found;
                        }

                        path = path_make_absolute(de->d_name, *i);
                        if (!path)
                                return -ENOMEM;

                        r = unit_file_can_install(&paths, root_dir, path, true, NULL);
                        if (r == -EINVAL ||  /* Invalid setting? */
                            r == -EBADMSG || /* Invalid format? */
                            r == -ENOENT     /* Included file not found? */)
                                f->state = UNIT_FILE_INVALID;
                        else if (r < 0)
                                return r;
                        else if (r > 0)
                                f->state = UNIT_FILE_DISABLED;
                        else
                                f->state = UNIT_FILE_STATIC;

                found:
                        r = hashmap_put(h, basename(f->path), f);
                        if (r < 0)
                                return r;
                        f = NULL; /* prevent cleanup */
                }
        }

        return r;
}

static const char* const unit_file_state_table[_UNIT_FILE_STATE_MAX] = {
        [UNIT_FILE_ENABLED] = "enabled",
        [UNIT_FILE_ENABLED_RUNTIME] = "enabled-runtime",
        [UNIT_FILE_LINKED] = "linked",
        [UNIT_FILE_LINKED_RUNTIME] = "linked-runtime",
        [UNIT_FILE_MASKED] = "masked",
        [UNIT_FILE_MASKED_RUNTIME] = "masked-runtime",
        [UNIT_FILE_STATIC] = "static",
        [UNIT_FILE_DISABLED] = "disabled",
        [UNIT_FILE_INDIRECT] = "indirect",
        [UNIT_FILE_INVALID] = "invalid",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_state, UnitFileState);

static const char* const unit_file_change_type_table[_UNIT_FILE_CHANGE_TYPE_MAX] = {
        [UNIT_FILE_SYMLINK] = "symlink",
        [UNIT_FILE_UNLINK] = "unlink",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_change_type, UnitFileChangeType);

static const char* const unit_file_preset_mode_table[_UNIT_FILE_PRESET_MAX] = {
        [UNIT_FILE_PRESET_FULL] = "full",
        [UNIT_FILE_PRESET_ENABLE_ONLY] = "enable-only",
        [UNIT_FILE_PRESET_DISABLE_ONLY] = "disable-only",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_preset_mode, UnitFilePresetMode);
