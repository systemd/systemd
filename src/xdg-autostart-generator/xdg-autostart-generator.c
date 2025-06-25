/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "generator.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-lookup.h"
#include "strv.h"
#include "xdg-autostart-service.h"

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(xdgautostartservice_hash_ops, char, string_hash_func, string_compare_func, XdgAutostartService, xdg_autostart_service_free);

static int xdg_base_dirs(char ***ret_config_dirs, char ***ret_data_dirs) {
        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;
        const char *e;

        /* Implement the mechanisms defined in
         * https://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html */

        assert(ret_config_dirs);
        assert(ret_data_dirs);

        e = getenv("XDG_CONFIG_DIRS");
        if (e)
                config_dirs = strv_split(e, ":");
        else
                config_dirs = strv_new("/etc/xdg");
        if (!config_dirs)
                return -ENOMEM;

        e = getenv("XDG_DATA_DIRS");
        if (e)
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share",
                                     "/usr/share");
        if (!data_dirs)
                return -ENOMEM;

        *ret_config_dirs = TAKE_PTR(config_dirs);
        *ret_data_dirs = TAKE_PTR(data_dirs);

        return 0;
}

static int enumerate_xdg_autostart(Hashmap *all_services) {
        _cleanup_strv_free_ char **autostart_dirs = NULL;
        _cleanup_strv_free_ char **config_dirs = NULL;
        _unused_ _cleanup_strv_free_ char **data_dirs = NULL;
        _cleanup_free_ char *user_config_autostart_dir = NULL;
        int r;

        r = xdg_user_config_dir("/autostart", &user_config_autostart_dir);
        if (r < 0)
                return r;
        r = strv_extend(&autostart_dirs, user_config_autostart_dir);
        if (r < 0)
                return r;

        r = xdg_base_dirs(&config_dirs, &data_dirs);
        if (r < 0)
                return r;
        r = strv_extend_strv_concat(&autostart_dirs, (const char* const*) config_dirs, "/autostart");
        if (r < 0)
                return r;

        STRV_FOREACH(path, autostart_dirs) {
                _cleanup_closedir_ DIR *d = NULL;

                log_debug("Scanning autostart directory \"%s\"%s", *path, glyph(GLYPH_ELLIPSIS));
                d = opendir(*path);
                if (!d) {
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Opening %s failed, ignoring: %m", *path);
                        continue;
                }

                FOREACH_DIRENT(de, d, log_warning_errno(errno, "Failed to enumerate directory %s, ignoring: %m", *path)) {
                        struct stat st;
                        if (fstatat(dirfd(d), de->d_name, &st, 0) < 0) {
                                log_warning_errno(errno, "%s/%s: stat() failed, ignoring: %m", *path, de->d_name);
                                continue;
                        }

                        if (!S_ISREG(st.st_mode)) {
                                log_debug("%s/%s: not a regular file, ignoring.", *path, de->d_name);
                                continue;
                        }

                        _cleanup_free_ char *name = xdg_autostart_service_translate_name(de->d_name);
                        if (!name)
                                return log_oom();

                        if (hashmap_contains(all_services, name)) {
                                log_debug("%s/%s: we have already seen \"%s\", ignoring.",
                                          *path, de->d_name, name);
                                continue;
                        }

                        _cleanup_free_ char *fpath = path_join(*path, de->d_name);
                        if (!fpath)
                                return log_oom();

                        _cleanup_(xdg_autostart_service_freep) XdgAutostartService *service =
                                xdg_autostart_service_parse_desktop(fpath);
                        if (!service)
                                return log_oom();
                        service->name = TAKE_PTR(name);

                        r = hashmap_put(all_services, service->name, service);
                        if (r < 0)
                                return log_oom();
                        TAKE_PTR(service);
                }
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        _cleanup_hashmap_free_ Hashmap *all_services = NULL;
        XdgAutostartService *service;
        int r;

        assert_se(dest_late);

        all_services = hashmap_new(&xdgautostartservice_hash_ops);
        if (!all_services)
                return log_oom();

        r = enumerate_xdg_autostart(all_services);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(service, all_services)
                (void) xdg_autostart_service_generate_unit(service, dest_late);

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
