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

#include <sys/stat.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include "log.h"
#include "path-lookup.h"
#include "util.h"
#include "macro.h"
#include "strv.h"
#include "conf-parser.h"
#include "dbus-common.h"
#include "sd-daemon.h"

static bool arg_force = false;
static bool arg_all = false;
static bool arg_verbose = false;

static enum {
        WHERE_SYSTEM,
        WHERE_SESSION,
        WHERE_GLOBAL,
} arg_where = WHERE_SYSTEM;

static enum {
        ACTION_INVALID,
        ACTION_ENABLE,
        ACTION_DISABLE,
        ACTION_REALIZE,
        ACTION_TEST
} arg_action = ACTION_INVALID;

static enum {
        REALIZE_NO,        /* Don't reload/start/stop or anything */
        REALIZE_RELOAD,    /* Only reload daemon config, don't stop/start */
        REALIZE_MINIMAL,   /* Only shutdown/restart if running. */
        REALIZE_MAYBE,     /* Start if WantedBy= suggests */
        REALIZE_YES        /* Start unconditionally */
} arg_realize = REALIZE_NO;

typedef struct {
        char *name;
        char *path;

        char **aliases;
        char **wanted_by;
} InstallInfo;

static Hashmap *will_install = NULL, *have_installed = NULL;
static Set *remove_symlinks_to = NULL;

static int help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Install init system units.\n\n"
               "  -h --help           Show this help\n"
               "     --force          Override existing links\n"
               "     --verbose        Show what is being done as it is done\n"
               "     --system         Install into system\n"
               "     --session        Install into session\n"
               "     --global         Install into all sessions\n"
               "     --all            When disabling, remove all symlinks, not\n"
               "                      just those listed in the [Install] section\n"
               "     --realize[=MODE] Start/stop/restart unit after installation\n"
               "                      Takes 'no', 'minimal', 'maybe' or 'yes'\n\n"
               "Commands:\n"
               "  enable [NAME...]    Enable one or more units\n"
               "  disable [NAME...]   Disable one or more units\n"
               "  realize [NAME...]   Test whether any of the specified units are enabled\n"
               "                      and the start/stop/restart units accordingly\n"
               "  test [NAME...]      Test whether any of the specified units are enabled\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_SESSION = 0x100,
                ARG_SYSTEM,
                ARG_GLOBAL,
                ARG_FORCE,
                ARG_REALIZE,
                ARG_ALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'         },
                { "session",   no_argument,       NULL, ARG_SESSION },
                { "system",    no_argument,       NULL, ARG_SYSTEM  },
                { "global",    no_argument,       NULL, ARG_GLOBAL  },
                { "force",     no_argument,       NULL, ARG_FORCE   },
                { "realize",   optional_argument, NULL, ARG_REALIZE },
                { "all",       no_argument,       NULL, ARG_ALL     },
                { "verbose",   no_argument,       NULL, 'v'         },
                { NULL,        0,                 NULL, 0           }
        };

        int c;
        bool realize_switch = false;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hv", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_SESSION:
                        arg_where = WHERE_SESSION;
                        break;

                case ARG_SYSTEM:
                        arg_where = WHERE_SYSTEM;
                        break;

                case ARG_GLOBAL:
                        arg_where = WHERE_GLOBAL;
                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_REALIZE:

                        realize_switch = true;

                        if (!optarg)
                                arg_realize = REALIZE_MAYBE;
                        else if (streq(optarg, "no"))
                                arg_realize = REALIZE_NO;
                        else if (streq(optarg, "minimal"))
                                arg_realize = REALIZE_MINIMAL;
                        else if (streq(optarg, "maybe"))
                                arg_realize = REALIZE_MAYBE;
                        else if (streq(optarg, "yes"))
                                arg_realize = REALIZE_YES;
                        else if (streq(optarg, "reload"))
                                arg_realize = REALIZE_RELOAD;
                        else {
                                log_error("Invalid --realize argument %s", optarg);
                                return -EINVAL;
                        }

                        break;

                case ARG_ALL:
                        arg_all = true;
                        break;

                case 'v':
                        arg_verbose = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc) {
                help();
                return -EINVAL;
        }

        if (streq(argv[optind], "enable"))
                arg_action = ACTION_ENABLE;
        else if (streq(argv[optind], "disable"))
                arg_action = ACTION_DISABLE;
        else if (streq(argv[optind], "test"))
                arg_action = ACTION_TEST;
        else if (streq(argv[optind], "realize")) {
                arg_action = ACTION_REALIZE;

                if (!realize_switch)
                        arg_realize = REALIZE_MAYBE;
        } else {
                log_error("Unknown verb %s.", argv[optind]);
                return -EINVAL;
        }

        optind++;

        if (optind >= argc) {
                log_error("Missing unit name.");
                return -EINVAL;
        }


        return 1;
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

        while ((i = hashmap_steal_first(m)))
                install_info_free(i);

        hashmap_free(m);
}

static bool unit_name_valid(const char *name) {

        /* This is a minimal version of unit_name_valid() from
         * unit-name.c */

        if (!*name)
                return false;

        if (ignore_file(name))
                return false;

        return true;
}

static int install_info_add(const char *name) {
        InstallInfo *i;
        int r;

        if (!unit_name_valid(name))
                return -EINVAL;

        if (hashmap_get(have_installed, name) ||
            hashmap_get(will_install, name))
                return 0;

        if (!(i = new0(InstallInfo, 1))) {
                r = -ENOMEM;
                goto fail;
        }

        if (!(i->name = strdup(name))) {
                r = -ENOMEM;
                goto fail;
        }

        if ((r = hashmap_put(will_install, i->name, i)) < 0)
                goto fail;

        return 0;

fail:
        if (i)
                install_info_free(i);

        return r;
}

static int daemon_reload(DBusConnection *bus) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;

        assert(bus);

        dbus_error_init(&error);

        if (arg_verbose)
                log_info("Reloading daemon configuration.");

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "Reload"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to reload configuration: %s", error.message);
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int install_info_run(DBusConnection *bus, InstallInfo *i, bool enabled) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *mode = "replace";

        assert(bus);
        assert(i);

        dbus_error_init(&error);

        if (arg_action == ACTION_ENABLE ||
            (arg_action == ACTION_REALIZE && enabled)) {

                if (arg_realize == REALIZE_MAYBE) {
                        char **k;
                        bool yes_please = false;

                        STRV_FOREACH(k, i->wanted_by) {
                                DBusMessageIter sub, iter;

                                const char *path, *state;
                                const char *interface = "org.freedesktop.systemd1.Unit";
                                const char *property = "ActiveState";

                                if (!(m = dbus_message_new_method_call(
                                                      "org.freedesktop.systemd1",
                                                      "/org/freedesktop/systemd1",
                                                      "org.freedesktop.systemd1.Manager",
                                                      "GetUnit"))) {
                                        log_error("Could not allocate message.");
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                if (!dbus_message_append_args(m,
                                                              DBUS_TYPE_STRING, k,
                                                              DBUS_TYPE_INVALID)) {
                                        log_error("Could not append arguments to message.");
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                                        /* Hmm, this unit doesn't exist, let's try the next one */
                                        dbus_message_unref(m);
                                        m = NULL;
                                        continue;
                                }

                                if (!dbus_message_get_args(reply, &error,
                                                           DBUS_TYPE_OBJECT_PATH, &path,
                                                           DBUS_TYPE_INVALID)) {
                                        log_error("Failed to parse reply: %s", error.message);
                                        r = -EIO;
                                        goto finish;
                                }

                                dbus_message_unref(m);
                                if (!(m = dbus_message_new_method_call(
                                                      "org.freedesktop.systemd1",
                                                      path,
                                                      "org.freedesktop.DBus.Properties",
                                                      "Get"))) {
                                        log_error("Could not allocate message.");
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                if (!dbus_message_append_args(m,
                                                              DBUS_TYPE_STRING, &interface,
                                                              DBUS_TYPE_STRING, &property,
                                                              DBUS_TYPE_INVALID)) {
                                        log_error("Could not append arguments to message.");
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                dbus_message_unref(reply);
                                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                                        log_error("Failed to issue method call: %s", error.message);
                                        r = -EIO;
                                        goto finish;
                                }

                                if (!dbus_message_iter_init(reply, &iter) ||
                                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                                        log_error("Failed to parse reply.");
                                        r = -EIO;
                                        goto finish;
                                }

                                dbus_message_iter_recurse(&iter, &sub);

                                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)  {
                                        log_error("Failed to parse reply.");
                                        r = -EIO;
                                        goto finish;
                                }

                                dbus_message_iter_get_basic(&sub, &state);

                                dbus_message_unref(m);
                                dbus_message_unref(reply);
                                m = reply = NULL;

                                if (streq(state, "active") ||
                                    startswith(state, "reloading") ||
                                    startswith(state, "activating")) {
                                        yes_please = true;
                                        break;
                                }
                        }

                        if (!yes_please) {
                                r = 0;
                                goto finish;
                        }
                }

                if (arg_verbose)
                        log_info("Restarting %s.", i->name);

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      arg_realize == REALIZE_MINIMAL ? "TryRestartUnit" : "RestartUnit"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &i->name,
                                              DBUS_TYPE_STRING, &mode,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }


        } else if (arg_action == ACTION_DISABLE ||
                   (arg_action == ACTION_REALIZE && !enabled)) {

                if (arg_verbose)
                        log_info("Stopping %s.", i->name);

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "StopUnit"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &i->name,
                                              DBUS_TYPE_STRING, &mode,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }
        } else
                assert_not_reached("install_info_run() called but nothing to do?");

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to realize unit: %s", error.message);
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int config_parse_also(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                char *n;
                int r;

                if (!(n = strndup(w, l)))
                        return -ENOMEM;

                r = install_info_add(n);
                free(n);

                if (r < 0)
                        return r;
        }

        return 0;
}

static int mark_symlink_for_removal(const char *p) {
        char *n;
        int r;

        assert(p);
        assert(path_is_absolute(p));

        if (!remove_symlinks_to)
                return 0;

        if (!(n = canonicalize_file_name(p)))
                if (!(n = strdup(p)))
                        return -ENOMEM;

        path_kill_slashes(n);

        if ((r = set_put(remove_symlinks_to, n)) < 0) {
                free(n);
                return r;
        }

        return 0;
}

static int remove_marked_symlinks_fd(int fd, const char *config_path, const char *root, bool *deleted) {
        int r = 0;
        DIR *d;
        struct dirent *de;

        assert(fd >= 0);
        assert(root);
        assert(deleted);

        if (!(d = fdopendir(fd)))
                return -errno;

        rewinddir(d);

        while ((de = readdir(d))) {
                bool is_dir = false, is_link = false;

                if (ignore_file(de->d_name))
                        continue;

                if (de->d_type == DT_LNK)
                        is_link = true;
                else if (de->d_type == DT_DIR)
                        is_dir = true;
                else if (de->d_type == DT_UNKNOWN) {
                        struct stat st;

                        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                                log_error("Failed to stat %s/%s: %m", root, de->d_name);

                                if (r == 0)
                                        r = -errno;
                                continue;
                        }

                        is_link = S_ISLNK(st.st_mode);
                        is_dir = S_ISDIR(st.st_mode);
                } else
                        continue;

                if (is_dir) {
                        int nfd, q;
                        char *p;

                        if ((nfd = openat(fd, de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)) < 0) {
                                log_error("Failed to open %s/%s: %m", root, de->d_name);

                                if (r == 0)
                                        r = -errno;
                                continue;
                        }

                        if (asprintf(&p, "%s/%s", root, de->d_name) < 0) {
                                log_error("Failed to allocate directory string.");
                                close_nointr_nofail(nfd);
                                r = -ENOMEM;
                                break;
                        }

                        q = remove_marked_symlinks_fd(nfd, config_path, p, deleted);
                        free(p);
                        close_nointr_nofail(nfd);

                        if (r == 0)
                                q = r;

                } else if (is_link) {
                        char *p, *dest, *c;
                        int q;

                        if (asprintf(&p, "%s/%s", root, de->d_name) < 0) {
                                log_error("Failed to allocate symlink string.");
                                r = -ENOMEM;
                                break;
                        }

                        if ((q = readlink_and_make_absolute(p, &dest)) < 0) {
                                log_error("Cannot read symlink %s: %s", p, strerror(-q));
                                free(p);

                                if (r == 0)
                                        r = q;
                                continue;
                        }

                        if ((c = canonicalize_file_name(dest))) {
                                /* This might fail if the destination
                                 * is already removed */

                                free(dest);
                                dest = c;
                        }

                        path_kill_slashes(dest);
                        if (set_get(remove_symlinks_to, dest)) {

                                if (arg_verbose)
                                        log_info("rm '%s'", p);

                                if (unlink(p) < 0) {
                                        log_error("Cannot unlink symlink %s: %m", p);

                                        if (r == 0)
                                                r = -errno;
                                } else {
                                        rmdir_parents(p, config_path);
                                        path_kill_slashes(p);

                                        if (!set_get(remove_symlinks_to, p)) {

                                                if ((r = mark_symlink_for_removal(p)) < 0) {
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

        return r;
}

static int remove_marked_symlinks(const char *config_path) {
        int fd, r = 0;
        bool deleted;

        assert(config_path);

        if (set_size(remove_symlinks_to) <= 0)
                return 0;

        if ((fd = open(config_path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)) < 0)
                return -errno;

        do {
                int q;
                deleted = false;

                if ((q = remove_marked_symlinks_fd(fd, config_path, config_path, &deleted)) < 0) {
                        if (r == 0)
                                r = q;
                }
        } while (deleted);

        close_nointr_nofail(fd);

        return r;
}

static int create_symlink(const char *old_path, const char *new_path) {
        int r;

        assert(old_path);
        assert(new_path);

        if (arg_action == ACTION_ENABLE) {
                char *dest;

                mkdir_parents(new_path, 0755);

                if (symlink(old_path, new_path) >= 0)
                        return 0;

                if (errno != EEXIST) {
                        log_error("Cannot link %s to %s: %m", old_path, new_path);
                        return -errno;
                }

                if ((r = readlink_and_make_absolute(new_path, &dest)) < 0) {

                        if (errno == EINVAL) {
                                log_error("Cannot link %s to %s, file exists already and is not a symlink.", old_path, new_path);
                                return -EEXIST;
                        }

                        log_error("readlink() failed: %s", strerror(-r));
                        return r;
                }

                if (streq(dest, old_path)) {
                        free(dest);
                        return 0;
                }

                if (!arg_force) {
                        log_error("Cannot link %s to %s, symlink exists already and points to %s.", old_path, new_path, dest);
                        free(dest);
                        return -EEXIST;
                }

                free(dest);
                unlink(new_path);

                if (arg_verbose)
                        log_info("ln -s '%s' '%s'", old_path, new_path);

                if (symlink(old_path, new_path) >= 0)
                        return 0;

                log_error("Cannot link %s to %s: %m", old_path, new_path);
                return -errno;

        } else if (arg_action == ACTION_DISABLE) {
                char *dest;

                if ((r = mark_symlink_for_removal(old_path)) < 0)
                        return r;

                if ((r = readlink_and_make_absolute(new_path, &dest)) < 0) {
                        if (errno == ENOENT)
                                return 0;

                        if (errno == EINVAL) {
                                log_warning("File %s not a symlink, ignoring.", old_path);
                                return 0;
                        }

                        log_error("readlink() failed: %s", strerror(-r));
                        return r;
                }

                if (!streq(dest, old_path)) {
                        log_warning("File %s not a symlink to %s but points to %s, ignoring.", new_path, old_path, dest);
                        free(dest);
                        return 0;
                }


                free(dest);

                if ((r = mark_symlink_for_removal(new_path)) < 0)
                        return r;

                if (arg_verbose)
                        log_info("rm '%s'", new_path);

                if (unlink(new_path) >= 0)
                        return 0;

                log_error("Cannot unlink %s: %m", new_path);
                return -errno;

        } else if (arg_action == ACTION_TEST || arg_action == ACTION_REALIZE) {
                char *dest;

                if ((r = readlink_and_make_absolute(new_path, &dest)) < 0) {

                        if (errno == ENOENT || errno == EINVAL)
                                return 0;

                        log_error("readlink() failed: %s", strerror(-r));
                        return r;
                }

                if (streq(dest, old_path)) {
                        free(dest);
                        return 1;
                }

                return 0;
        }

        assert_not_reached("Unknown action.");
}

static int install_info_symlink_alias(InstallInfo *i, const char *config_path) {
        char **s;
        char *alias_path = NULL;
        int r;

        assert(i);

        STRV_FOREACH(s, i->aliases) {

                if (!unit_name_valid(*s)) {
                        log_error("Invalid name %s.", *s);
                        r = -EINVAL;
                        goto finish;
                }

                free(alias_path);
                if (!(alias_path = path_make_absolute(*s, config_path))) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = create_symlink(i->path, alias_path)) != 0)
                        goto finish;

                if (arg_action == ACTION_DISABLE)
                        rmdir_parents(alias_path, config_path);
        }

        r = 0;

finish:
        free(alias_path);

        return r;
}

static int install_info_symlink_wants(InstallInfo *i, const char *config_path) {
        char **s;
        char *alias_path = NULL;
        int r;

        assert(i);

        STRV_FOREACH(s, i->wanted_by) {
                if (!unit_name_valid(*s)) {
                        log_error("Invalid name %s.", *s);
                        r = -EINVAL;
                        goto finish;
                }

                free(alias_path);
                alias_path = NULL;

                if (asprintf(&alias_path, "%s/%s.wants/%s", config_path, *s, i->name) < 0) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = create_symlink(i->path, alias_path)) != 0)
                        goto finish;

                if (arg_action == ACTION_DISABLE)
                        rmdir_parents(alias_path, config_path);
        }

        r = 0;

finish:
        free(alias_path);

        return r;
}

static int install_info_apply(LookupPaths *paths, InstallInfo *i, const char *config_path) {

        const ConfigItem items[] = {
                { "Alias",    config_parse_strv, &i->aliases,   "Install" },
                { "WantedBy", config_parse_strv, &i->wanted_by, "Install" },
                { "Also",     config_parse_also, NULL,          "Install" },

                { NULL, NULL, NULL, NULL }
        };

        char **p;
        char *filename = NULL;
        FILE *f = NULL;
        int r;

        assert(paths);
        assert(i);

        STRV_FOREACH(p, paths->unit_path) {
                int fd;

                if (!(filename = path_make_absolute(i->name, *p))) {
                        log_error("Out of memory");
                        return -ENOMEM;
                }

                /* Ensure that we don't follow symlinks */
                if ((fd = open(filename, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NOCTTY)) >= 0)
                        if ((f = fdopen(fd, "re")))
                                break;

                if (errno == ELOOP) {
                        log_error("Refusing to operate on symlinks, please pass unit names or absolute paths to unit files.");
                        free(filename);
                        return -errno;
                }

                if (errno != ENOENT) {
                        log_error("Failed to open %s: %m", filename);
                        free(filename);
                        return -errno;
                }

                free(filename);
                filename = NULL;
        }

        if (!f) {
                log_error("Couldn't find %s.", i->name);
                return -ENOENT;
        }

        i->path = filename;

        if ((r = config_parse(filename, f, NULL, items, true, i)) < 0) {
                fclose(f);
                return r;
        }

        fclose(f);

        if ((r = install_info_symlink_alias(i, config_path)) != 0)
                return r;

        if ((r = install_info_symlink_wants(i, config_path)) != 0)
                return r;

        if ((r = mark_symlink_for_removal(filename)) < 0)
                return r;

        if ((r = remove_marked_symlinks(config_path)) < 0)
                return r;

        return 0;
}

static char *get_config_path(void) {

        switch (arg_where) {

        case WHERE_SYSTEM:
                return strdup(SYSTEM_CONFIG_UNIT_PATH);

        case WHERE_GLOBAL:
                return strdup(SESSION_CONFIG_UNIT_PATH);

        case WHERE_SESSION: {
                char *p;

                if (session_config_home(&p) < 0)
                        return NULL;

                return p;
        }

        default:
                assert_not_reached("Unknown config path.");
        }
}

static int do_realize(bool enabled) {
        DBusConnection *bus = NULL;
        DBusError error;
        int r, q;
        Iterator i;
        InstallInfo *j;

        dbus_error_init(&error);

        if (arg_realize == REALIZE_NO)
                return 0;

        if (arg_where == WHERE_GLOBAL) {
                log_warning("Warning: --realize has no effect with --global.");
                return 0;
        }

        if (arg_action == ACTION_TEST) {
                log_warning("Warning: --realize has no effect with test.");
                return 0;
        }

        if (arg_where == WHERE_SYSTEM && sd_booted() <= 0) {
                log_info("systemd is not running, --realize has no effect.");
                return 0;
        }

        if (arg_where == WHERE_SYSTEM && running_in_chroot() > 0) {
                log_info("Running in a chroot() environment, --realize has no effect.");
                return 0;
        }

        if ((r = bus_connect(arg_where == WHERE_SESSION ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM, &bus, NULL, &error)) < 0) {
                log_error("Failed to get D-Bus connection: %s", error.message);
                goto finish;
        }

        r = 0;

        if (arg_action == ACTION_ENABLE || arg_action == ACTION_REALIZE)
                if ((r = daemon_reload(bus)) < 0)
                        goto finish;

        if (arg_realize != REALIZE_RELOAD) {
                HASHMAP_FOREACH(j, have_installed, i)
                        if ((q = install_info_run(bus, j, enabled)) < 0)
                                r = q;
        }

        if (arg_action == ACTION_DISABLE)
                if ((q = daemon_reload(bus)) < 0)
                        r = q;

finish:
        if (bus) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);

        dbus_shutdown();
        return r;
}

int main(int argc, char *argv[]) {
        int r, retval = 1, j;
        LookupPaths paths;
        InstallInfo *i;
        char *config_path = NULL;

        zero(paths);

        log_parse_environment();

        if ((r = parse_argv(argc, argv)) < 0)
                goto finish;
        else if (r == 0) {
                retval = 0;
                goto finish;
        }

        if ((r = lookup_paths_init(&paths, arg_where == WHERE_SYSTEM ? MANAGER_SYSTEM : MANAGER_SESSION)) < 0) {
                log_error("Failed to determine lookup paths: %s", strerror(-r));
                goto finish;
        }

        if (!(config_path = get_config_path())) {
                log_error("Failed to determine config path");
                goto finish;
        }

        will_install = hashmap_new(string_hash_func, string_compare_func);
        have_installed = hashmap_new(string_hash_func, string_compare_func);

        if (!will_install || !have_installed) {
                log_error("Failed to allocate unit sets.");
                goto finish;
        }

        if (arg_all)
                if (!(remove_symlinks_to = set_new(string_hash_func, string_compare_func))) {
                        log_error("Failed to allocate symlink sets.");
                        goto finish;
                }

        for (j = optind; j < argc; j++)
                if ((r = install_info_add(argv[j])) < 0)
                        goto finish;


        while ((i = hashmap_first(will_install))) {
                assert_se(hashmap_move_one(have_installed, will_install, i->name) == 0);

                if ((r = install_info_apply(&paths, i, config_path)) != 0) {

                        if (r < 0)
                                goto finish;

                        /* In test mode and found something */
                        retval = 0;
                        break;
                }
        }

        if (do_realize(!retval) < 0)
                goto finish;

finish:
        install_info_hashmap_free(will_install);
        install_info_hashmap_free(have_installed);

        set_free_free(remove_symlinks_to);

        lookup_paths_free(&paths);

        free(config_path);

        return retval;
}
