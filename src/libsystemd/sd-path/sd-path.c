/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-path.h"

#include "alloc-util.h"
#include "architecture.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "network-util.h"
#include "nulstr-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static int from_environment(const char *envname, const char *fallback, const char **ret) {
        assert(ret);

        if (envname) {
                const char *e;

                e = secure_getenv(envname);
                if (e && path_is_absolute(e)) {
                        *ret = e;
                        return 0;
                }
        }

        if (fallback) {
                *ret = fallback;
                return 0;
        }

        return -ENXIO;
}

static int from_home_dir(
                const char *envname,
                const char *suffix,
                char **buffer,
                const char **ret) {

        _cleanup_free_ char *h = NULL;
        int r;

        assert(suffix);
        assert(buffer);
        assert(ret);

        if (envname) {
                const char *e = NULL;

                e = secure_getenv(envname);
                if (e && path_is_absolute(e)) {
                        *ret = e;
                        return 0;
                }
        }

        r = get_home_dir(&h);
        if (r < 0)
                return r;

        if (!path_extend(&h, suffix))
                return -ENOMEM;

        *buffer = h;
        *ret = TAKE_PTR(h);
        return 0;
}

static int from_xdg_user_dir(const char *field, char **buffer, const char **ret) {
        _cleanup_free_ char *user_dirs = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(field);
        assert(buffer);
        assert(ret);

        r = sd_path_lookup(SD_PATH_USER_CONFIGURATION, "user-dirs.dirs", &user_dirs);
        if (r < 0)
                return r;

        f = fopen(user_dirs, "re");
        if (!f) {
                if (errno == ENOENT)
                        goto fallback;

                return -errno;
        }

        /* This is an awful parse, but it follows closely what xdg-user-dirs does upstream */
        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *p, *e;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = startswith(line, field);
                if (!p)
                        continue;

                p = skip_leading_chars(p, WHITESPACE);
                if (*p != '=')
                        continue;
                p++;

                p = skip_leading_chars(p, WHITESPACE);
                if (*p != '"')
                        continue;
                p++;

                e = strrchr(p, '"');
                if (!e)
                        continue;
                *e = 0;

                /* Three syntaxes permitted: relative to $HOME, $HOME itself, and absolute path */
                if (streq(p, "$HOME"))
                        goto home;

                const char *s = startswith(p, "$HOME/");
                if (s)
                        return from_home_dir(/* envname = */ NULL, s, buffer, ret);

                if (path_is_absolute(p)) {
                        char *c = strdup(p);
                        if (!c)
                                return -ENOMEM;

                        *ret = *buffer = c;
                        return 0;
                }
        }

fallback:
        /* The desktop directory defaults to $HOME/Desktop, the others to $HOME */
        if (streq(field, "XDG_DESKTOP_DIR"))
                return from_home_dir(/* envname = */ NULL, "Desktop", buffer, ret);

home:
        r = get_home_dir(buffer);
        if (r < 0)
                return r;

        *ret = *buffer;
        return 0;
}

static int get_path(uint64_t type, char **buffer, const char **ret) {
        int r;

        assert(buffer);
        assert(ret);

        switch (type) {

        case SD_PATH_TEMPORARY:
                return tmp_dir(ret);

        case SD_PATH_TEMPORARY_LARGE:
                return var_tmp_dir(ret);

        case SD_PATH_SYSTEM_BINARIES:
                *ret = "/usr/bin";
                return 0;

        case SD_PATH_SYSTEM_INCLUDE:
                *ret = "/usr/include";
                return 0;

        case SD_PATH_SYSTEM_LIBRARY_PRIVATE:
                *ret = "/usr/lib";
                return 0;

        case SD_PATH_SYSTEM_LIBRARY_ARCH:
                *ret = LIBDIR;
                return 0;

        case SD_PATH_SYSTEM_SHARED:
                *ret = "/usr/share";
                return 0;

        case SD_PATH_SYSTEM_CONFIGURATION_FACTORY:
                *ret = "/usr/share/factory/etc";
                return 0;

        case SD_PATH_SYSTEM_STATE_FACTORY:
                *ret = "/usr/share/factory/var";
                return 0;

        case SD_PATH_SYSTEM_CONFIGURATION:
                *ret = "/etc";
                return 0;

        case SD_PATH_SYSTEM_RUNTIME:
                *ret = "/run";
                return 0;

        case SD_PATH_SYSTEM_RUNTIME_LOGS:
                *ret = "/run/log";
                return 0;

        case SD_PATH_SYSTEM_STATE_PRIVATE:
                *ret = "/var/lib";
                return 0;

        case SD_PATH_SYSTEM_STATE_LOGS:
                *ret = "/var/log";
                return 0;

        case SD_PATH_SYSTEM_STATE_CACHE:
                *ret = "/var/cache";
                return 0;

        case SD_PATH_SYSTEM_STATE_SPOOL:
                *ret = "/var/spool";
                return 0;

        case SD_PATH_USER_BINARIES:
                return from_home_dir(NULL, ".local/bin", buffer, ret);

        case SD_PATH_USER_LIBRARY_PRIVATE:
                return from_home_dir(NULL, ".local/lib", buffer, ret);

        case SD_PATH_USER_LIBRARY_ARCH:
                return from_home_dir(NULL, ".local/lib/" LIB_ARCH_TUPLE, buffer, ret);

        case SD_PATH_USER_SHARED:
                return from_home_dir("XDG_DATA_HOME", ".local/share", buffer, ret);

        case SD_PATH_USER_CONFIGURATION:
                return from_home_dir("XDG_CONFIG_HOME", ".config", buffer, ret);

        case SD_PATH_USER_RUNTIME:
                return from_environment("XDG_RUNTIME_DIR", NULL, ret);

        case SD_PATH_USER_STATE_CACHE:
                return from_home_dir("XDG_CACHE_HOME", ".cache", buffer, ret);

        case SD_PATH_USER_STATE_PRIVATE:
                return from_home_dir("XDG_STATE_HOME", ".local/state", buffer, ret);

        case SD_PATH_USER:
                r = get_home_dir(buffer);
                if (r < 0)
                        return r;

                *ret = *buffer;
                return 0;

        case SD_PATH_USER_DOCUMENTS:
                return from_xdg_user_dir("XDG_DOCUMENTS_DIR", buffer, ret);

        case SD_PATH_USER_MUSIC:
                return from_xdg_user_dir("XDG_MUSIC_DIR", buffer, ret);

        case SD_PATH_USER_PICTURES:
                return from_xdg_user_dir("XDG_PICTURES_DIR", buffer, ret);

        case SD_PATH_USER_VIDEOS:
                return from_xdg_user_dir("XDG_VIDEOS_DIR", buffer, ret);

        case SD_PATH_USER_DOWNLOAD:
                return from_xdg_user_dir("XDG_DOWNLOAD_DIR", buffer, ret);

        case SD_PATH_USER_PUBLIC:
                return from_xdg_user_dir("XDG_PUBLICSHARE_DIR", buffer, ret);

        case SD_PATH_USER_TEMPLATES:
                return from_xdg_user_dir("XDG_TEMPLATES_DIR", buffer, ret);

        case SD_PATH_USER_DESKTOP:
                return from_xdg_user_dir("XDG_DESKTOP_DIR", buffer, ret);

        case SD_PATH_SYSTEMD_UTIL:
                *ret = PREFIX_NOSLASH "/lib/systemd";
                return 0;

        case SD_PATH_SYSTEMD_SYSTEM_UNIT:
                *ret = SYSTEM_DATA_UNIT_DIR;
                return 0;

        case SD_PATH_SYSTEMD_SYSTEM_PRESET:
                *ret = PREFIX_NOSLASH "/lib/systemd/system-preset";
                return 0;

        case SD_PATH_SYSTEMD_USER_UNIT:
                *ret = USER_DATA_UNIT_DIR;
                return 0;

        case SD_PATH_SYSTEMD_USER_PRESET:
                *ret = PREFIX_NOSLASH "/lib/systemd/user-preset";
                return 0;

        case SD_PATH_SYSTEMD_SYSTEM_CONF:
                *ret = SYSTEM_CONFIG_UNIT_DIR;
                return 0;

        case SD_PATH_SYSTEMD_USER_CONF:
                *ret = USER_CONFIG_UNIT_DIR;
                return 0;

        case SD_PATH_SYSTEMD_SYSTEM_GENERATOR:
                *ret = SYSTEM_GENERATOR_DIR;
                return 0;

        case SD_PATH_SYSTEMD_USER_GENERATOR:
                *ret = USER_GENERATOR_DIR;
                return 0;

        case SD_PATH_SYSTEMD_SLEEP:
                *ret = PREFIX_NOSLASH "/lib/systemd/system-sleep";
                return 0;

        case SD_PATH_SYSTEMD_SHUTDOWN:
                *ret = PREFIX_NOSLASH "/lib/systemd/system-shutdown";
                return 0;

        case SD_PATH_TMPFILES:
                *ret = "/usr/lib/tmpfiles.d";
                return 0;

        case SD_PATH_SYSUSERS:
                *ret = PREFIX_NOSLASH "/lib/sysusers.d";
                return 0;

        case SD_PATH_SYSCTL:
                *ret = PREFIX_NOSLASH "/lib/sysctl.d";
                return 0;

        case SD_PATH_BINFMT:
                *ret = PREFIX_NOSLASH "/lib/binfmt.d";
                return 0;

        case SD_PATH_MODULES_LOAD:
                *ret = PREFIX_NOSLASH "/lib/modules-load.d";
                return 0;

        case SD_PATH_CATALOG:
                *ret = "/usr/lib/systemd/catalog";
                return 0;

        case SD_PATH_SYSTEMD_SYSTEM_ENVIRONMENT_GENERATOR:
                *ret = SYSTEM_ENV_GENERATOR_DIR;
                return 0;

        case SD_PATH_SYSTEMD_USER_ENVIRONMENT_GENERATOR:
                *ret = USER_ENV_GENERATOR_DIR;
                return 0;

        case SD_PATH_SYSTEM_CREDENTIAL_STORE:
                *ret = "/etc/credstore";
                return 0;

        case SD_PATH_SYSTEM_CREDENTIAL_STORE_ENCRYPTED:
                *ret = "/etc/credstore.encrypted";
                return 0;

        case SD_PATH_USER_CREDENTIAL_STORE:
                r = xdg_user_config_dir("credstore", buffer);
                if (r < 0)
                        return r;

                *ret = *buffer;
                return 0;

        case SD_PATH_USER_CREDENTIAL_STORE_ENCRYPTED:
                r = xdg_user_config_dir("credstore.encrypted", buffer);
                if (r < 0)
                        return r;

                *ret = *buffer;
                return 0;
        }

        return -EOPNOTSUPP;
}

static int get_path_alloc(uint64_t type, const char *suffix, char **ret) {
        _cleanup_free_ char *buffer = NULL;
        const char *p;
        int r;

        assert(ret);

        r = get_path(type, &buffer, &p);
        if (r < 0)
                return r;

        if (!isempty(suffix)) {
                char *suffixed = path_join(p, suffix);
                if (!suffixed)
                        return -ENOMEM;

                path_simplify_full(suffixed, PATH_SIMPLIFY_KEEP_TRAILING_SLASH);

                free_and_replace(buffer, suffixed);
        } else if (!buffer) {
                buffer = strdup(p);
                if (!buffer)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(buffer);
        return 0;
}

_public_ int sd_path_lookup(uint64_t type, const char *suffix, char **ret) {
        int r;

        assert_return(ret, -EINVAL);

        r = get_path_alloc(type, suffix, ret);
        if (r != -EOPNOTSUPP)
                return r;

        /* Fall back to sd_path_lookup_strv */
        _cleanup_strv_free_ char **l = NULL;

        r = sd_path_lookup_strv(type, suffix, &l);
        if (r < 0)
                return r;

        char *joined = strv_join(l, ":");
        if (!joined)
                return -ENOMEM;

        *ret = joined;
        return 0;
}

static int search_from_environment(
                char ***ret,
                const char *env_home,
                const char *home_suffix,
                const char *env_search,
                bool env_search_sufficient,
                const char *first, ...) {

        _cleanup_strv_free_ char **l = NULL;
        const char *e;
        char *h = NULL;
        int r;

        assert(ret);

        if (env_search) {
                e = secure_getenv(env_search);
                if (e) {
                        l = strv_split(e, ":");
                        if (!l)
                                return -ENOMEM;

                        if (env_search_sufficient) {
                                *ret = TAKE_PTR(l);
                                return 0;
                        }
                }
        }

        if (!l && first) {
                va_list ap;

                va_start(ap, first);
                l = strv_new_ap(first, ap);
                va_end(ap);

                if (!l)
                        return -ENOMEM;
        }

        if (env_home) {
                e = secure_getenv(env_home);
                if (e && path_is_absolute(e)) {
                        h = strdup(e);
                        if (!h)
                                return -ENOMEM;
                }
        }

        if (!h && home_suffix) {
                e = secure_getenv("HOME");
                if (e && path_is_absolute(e)) {
                        h = path_join(e, home_suffix);
                        if (!h)
                                return -ENOMEM;
                }
        }

        if (h) {
                r = strv_consume_prepend(&l, h);
                if (r < 0)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(l);
        return 0;
}

#if HAVE_SPLIT_BIN
#  define ARRAY_SBIN_BIN(x) x "sbin", x "bin"
#else
#  define ARRAY_SBIN_BIN(x) x "bin"
#endif

static int get_search(uint64_t type, char ***ret) {
        int r;

        assert(ret);

        switch (type) {

        case SD_PATH_SEARCH_BINARIES:
                return search_from_environment(ret,
                                               NULL,
                                               ".local/bin",
                                               "PATH",
                                               true,
                                               ARRAY_SBIN_BIN("/usr/local/"),
                                               ARRAY_SBIN_BIN("/usr/"),
                                               NULL);

        case SD_PATH_SEARCH_LIBRARY_PRIVATE:
                return search_from_environment(ret,
                                               NULL,
                                               ".local/lib",
                                               NULL,
                                               false,
                                               "/usr/local/lib",
                                               "/usr/lib",
                                               NULL);

        case SD_PATH_SEARCH_LIBRARY_ARCH:
                return search_from_environment(ret,
                                               NULL,
                                               ".local/lib/" LIB_ARCH_TUPLE,
                                               "LD_LIBRARY_PATH",
                                               true,
                                               LIBDIR,
                                               NULL);

        case SD_PATH_SEARCH_SHARED:
                return search_from_environment(ret,
                                               "XDG_DATA_HOME",
                                               ".local/share",
                                               "XDG_DATA_DIRS",
                                               false,
                                               "/usr/local/share",
                                               "/usr/share",
                                               NULL);

        case SD_PATH_SEARCH_CONFIGURATION_FACTORY:
                return search_from_environment(ret,
                                               NULL,
                                               NULL,
                                               NULL,
                                               false,
                                               "/usr/local/share/factory/etc",
                                               "/usr/share/factory/etc",
                                               NULL);

        case SD_PATH_SEARCH_STATE_FACTORY:
                return search_from_environment(ret,
                                               NULL,
                                               NULL,
                                               NULL,
                                               false,
                                               "/usr/local/share/factory/var",
                                               "/usr/share/factory/var",
                                               NULL);

        case SD_PATH_SEARCH_CONFIGURATION:
                return search_from_environment(ret,
                                               "XDG_CONFIG_HOME",
                                               ".config",
                                               "XDG_CONFIG_DIRS",
                                               false,
                                               "/etc",
                                               NULL);

        case SD_PATH_SEARCH_BINARIES_DEFAULT: {
                char **t = strv_split(default_PATH(), ":");
                if (!t)
                        return -ENOMEM;

                *ret = t;
                return 0;
        }

        case SD_PATH_SYSTEMD_SEARCH_SYSTEM_UNIT:
        case SD_PATH_SYSTEMD_SEARCH_USER_UNIT: {
                _cleanup_(lookup_paths_done) LookupPaths lp = {};
                RuntimeScope scope = type == SD_PATH_SYSTEMD_SEARCH_SYSTEM_UNIT ?
                        RUNTIME_SCOPE_SYSTEM : RUNTIME_SCOPE_USER;

                r = lookup_paths_init(&lp, scope, 0, NULL);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(lp.search_path);
                return 0;
        }

        case SD_PATH_SYSTEMD_SEARCH_SYSTEM_GENERATOR:
        case SD_PATH_SYSTEMD_SEARCH_USER_GENERATOR:
        case SD_PATH_SYSTEMD_SEARCH_SYSTEM_ENVIRONMENT_GENERATOR:
        case SD_PATH_SYSTEMD_SEARCH_USER_ENVIRONMENT_GENERATOR: {
                RuntimeScope scope = IN_SET(type, SD_PATH_SYSTEMD_SEARCH_SYSTEM_GENERATOR,
                                                  SD_PATH_SYSTEMD_SEARCH_SYSTEM_ENVIRONMENT_GENERATOR) ?
                                     RUNTIME_SCOPE_SYSTEM : RUNTIME_SCOPE_USER;
                bool env_generator = IN_SET(type, SD_PATH_SYSTEMD_SEARCH_SYSTEM_ENVIRONMENT_GENERATOR,
                                                  SD_PATH_SYSTEMD_SEARCH_USER_ENVIRONMENT_GENERATOR);

                char **t = generator_binary_paths_internal(scope, env_generator);
                if (!t)
                        return -ENOMEM;

                *ret = t;
                return 0;
        }

        case SD_PATH_SYSTEMD_SEARCH_NETWORK:
                return strv_from_nulstr(ret, NETWORK_DIRS_NULSTR);

        case SD_PATH_SYSTEM_SEARCH_CREDENTIAL_STORE:
        case SD_PATH_SYSTEM_SEARCH_CREDENTIAL_STORE_ENCRYPTED: {
                const char *suffix =
                        type == SD_PATH_SYSTEM_SEARCH_CREDENTIAL_STORE_ENCRYPTED ? "credstore.encrypted" : "credstore";

                _cleanup_strv_free_ char **l = NULL;
                FOREACH_STRING(d, CONF_PATHS("")) {
                        char *j = path_join(d, suffix);
                        if (!j)
                                return -ENOMEM;

                        r = strv_consume(&l, TAKE_PTR(j));
                        if (r < 0)
                                return r;
                }

                *ret = TAKE_PTR(l);
                return 0;
        }

        case SD_PATH_USER_SEARCH_CREDENTIAL_STORE:
        case SD_PATH_USER_SEARCH_CREDENTIAL_STORE_ENCRYPTED: {
                const char *suffix =
                        type == SD_PATH_USER_SEARCH_CREDENTIAL_STORE_ENCRYPTED ? "credstore.encrypted" : "credstore";

                static const uint64_t dirs[] = {
                        SD_PATH_USER_CONFIGURATION,
                        SD_PATH_USER_RUNTIME,
                        SD_PATH_USER_LIBRARY_PRIVATE,
                };

                _cleanup_strv_free_ char **l = NULL;
                FOREACH_ELEMENT(d, dirs) {
                        _cleanup_free_ char *p = NULL;
                        r = sd_path_lookup(*d, suffix, &p);
                        if (r == -ENXIO)
                                continue;
                        if (r < 0)
                                return r;

                        r = strv_consume(&l, TAKE_PTR(p));
                        if (r < 0)
                                return r;
                }

                *ret = TAKE_PTR(l);
                return 0;
        }}

        return -EOPNOTSUPP;
}

_public_ int sd_path_lookup_strv(uint64_t type, const char *suffix, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert_return(ret, -EINVAL);

        r = get_search(type, &l);
        if (r == -EOPNOTSUPP) {
                _cleanup_free_ char *t = NULL;

                r = get_path_alloc(type, suffix, &t);
                if (r < 0)
                        return r;

                l = new(char*, 2);
                if (!l)
                        return -ENOMEM;
                l[0] = TAKE_PTR(t);
                l[1] = NULL;

                *ret = TAKE_PTR(l);
                return 0;
        }
        if (r < 0)
                return r;

        if (suffix)
                STRV_FOREACH(i, l) {
                        if (!path_extend(i, suffix))
                                return -ENOMEM;

                        path_simplify_full(*i, PATH_SIMPLIFY_KEEP_TRAILING_SLASH);
                }

        *ret = TAKE_PTR(l);
        return 0;
}
