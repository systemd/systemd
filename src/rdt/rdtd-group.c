/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/stat.h>
#include "dirent-util.h"
#include "fd-util.h"
#include "rdtd-group.h"
#include "rdtd-resctrl.h"
#include "strv.h"
#include "fileio-label.h"
#include "stat-util.h"

RdtGroup* group_new(Manager *m, const char *name) {
        RdtGroup *g;

        assert(m);

        g = new0(RdtGroup, 1);
        if (!g)
                return NULL;

        g->name = strdup(name);
        if (!g->name)
                return mfree(g);

        g->manager = m;
        return g;
}

void group_free(RdtGroup *g) {
        if (!g)
                return;
        free(g->name);
        free(g->l3_id);
        free(g->source);
        free(g);
}

static int rdt_parse_config_file(RdtGroup *g, const char *dir, const char *name) {
        _cleanup_free_ char *filename = NULL;

        assert(g);

        filename = path_make_absolute(name, dir);
        if (!filename)
                return -ENOMEM;
        return config_parse_many_nulstr(filename,
                                        NULL,
                                        "Rdt\0",
                                        config_item_perf_lookup, rdtd_gperf_lookup,
                                        CONFIG_PARSE_WARN, g);
}

static bool rdt_static_config_exist(const char *name) {
        _cleanup_free_ char *filename = NULL;

        filename = path_make_absolute(name, RDT_STATIC_DIR);
        if (!filename)
                return false;
        if (null_or_empty_path(filename))
                return false;
        return true;
}

static int rdt_remove_deleted_group(const char *name) {
        _cleanup_free_ char *filename = NULL;
        int r;

        log_info("config %s deleted, remove its group now", name);
        r = resctrl_alloc_group_remove(name);
        if (r < 0)
                return r;;
        filename = path_make_absolute(name, RDT_RUNTIME_DIR);
        if (!filename)
                return -ENOMEM;

        return unlink(filename);
}

int rdt_scan_runtime_configs(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;
        RdtGroup *g;

        d = opendir(RDT_RUNTIME_DIR);
        if (d) {
                FOREACH_DIRENT(de, d, return -errno) {
                        g = group_new(m, de->d_name);
                        if (!g)
                                return -ENOMEM;
                        r = rdt_parse_config_file(g, RDT_RUNTIME_DIR, de->d_name);
                        if (r < 0) {
                                log_error("config %s parsed failed, ignoring it.", de->d_name);
                                group_free(g);
                                continue;
                        }

                        /* delete a group if its static config has been deleted */
                        if (g->source && streq(g->source, "static") &&
                            !rdt_static_config_exist(de->d_name)) {
                                rdt_remove_deleted_group(de->d_name);
                                group_free(g);
                                continue;
                        }
                        r = hashmap_put(m->groups, g->name, g);
                        if (r < 0) {
                                group_free(g);
                                continue;
                        }
                }
        } else {
                log_warning_errno(errno, "Cannot open path %s: %m.", RDT_RUNTIME_DIR);
        }
        return 0;
}

static int rdt_get_config_mtime(const char *dir, const char *name, time_t *mtime) {
        _cleanup_free_ char *filename = NULL;
        struct stat st;
        int r;

        filename = path_make_absolute(name, dir);
        if (!filename)
                return -ENOMEM;
        r = stat(filename, &st);
        if (r < 0)
                return -errno;
        *mtime = st.st_mtime;
        return 0;
}

static int rdt_write_runtime_config(Manager *m, RdtGroup *g) {
        _cleanup_free_ char *filename = NULL;
        _cleanup_free_ char *data = NULL;
        _cleanup_strv_free_ char **config_items = NULL;
        const char *wrapped;
        int r;

        filename = path_make_absolute(g->name, RDT_RUNTIME_DIR);
        if (!filename)
                return -ENOMEM;

        config_items = strv_new("[Rdt]", NULL);
        if (!config_items)
                return -ENOMEM;
        if (g->l3_size != 0) {
                r = strv_extendf(&config_items, "L3CacheAllocationSize=%"PRIu64, g->l3_size);
                if (r < 0)
                        return r;
        }
        if (g->l3_id) {
                r = strv_extendf(&config_items, "L3CacheAllocationId=%s", g->l3_id);
                if (r < 0)
                        return r;
        }
        r = strv_extendf(&config_items, "ConfigMtime=%lu", g->mtime);
        if (r < 0)
                return r;
        r = strv_extendf(&config_items, "ConfigSource=%s", g->source);
        if (r < 0)
                return r;

        data = strv_join(config_items, "\n");
        if (!data)
                return -ENOMEM;

        wrapped = strjoina("# This is a runtime rdt config created by systemd-rdtd.\n"
                           "# Do not edit.\n",
                           data,
                           "\n");
        r = write_string_file_atomic_label(filename, wrapped);
        if (r < 0)
                return r;
        return 0;
}

static int rdt_update_group_from_static_config(Manager *m, const char *name,
                                               time_t mtime) {
        int r;
        RdtGroup *rung, *g;

        rung = hashmap_get(m->groups, name);
        if (rung && rung->mtime == mtime)
                return 0;

        log_info("config %s newly added or changed, update its group now", name);
        g = group_new(m, name);
        if (!g)
                return -ENOMEM;

        r = rdt_parse_config_file(g, RDT_STATIC_DIR, name);
        if (r < 0) {
                log_error("config %s parsed failed, ignoring it.", name);
                goto out;
        }

        if (g->l3_size == 0)
                goto out;

        r = resctrl_update_schemata(g);
        if (r < 0)
                goto out;

        g->mtime = mtime;
        g->source = strdup("static");
        if (!g->source) {
                r = -ENOMEM;
                goto out;
        }

        r = rdt_write_runtime_config(m, g);
        if (r < 0) {
                log_error("runtime config (%s) written failed", name);
                goto out;
        }

        r = hashmap_replace(m->groups, g->name, g);
        g = rung ? rung : NULL;
out:
        group_free(g);
        return r;
}

int rdt_scan_static_configs(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;
        time_t mtime;

        d = opendir(RDT_STATIC_DIR);
        if (d) {
                FOREACH_DIRENT(de, d, return -errno) {
                        /* filter non-conf files */
                        if (!dirent_is_file(de))
                                continue;

                        r = rdt_get_config_mtime(RDT_STATIC_DIR, de->d_name, &mtime);
                        if (r < 0) {
                                log_error("Failed to get modification time of config(%s)", de->d_name);
                                continue;
                        }

                        r = rdt_update_group_from_static_config(m, de->d_name, mtime);
                        if (r < 0)
                                continue;
                }
        } else {
                log_warning_errno(errno, "Cannot open path %s: %m.", RDT_STATIC_DIR);
        }
        return 0;
}
