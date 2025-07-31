/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "alloc-util.h"
#include "device-enumerator-private.h"
#include "device-util.h"
#include "glyph-util.h"
#include "path-util.h"
#include "string-util.h"
#include "sysfs-show.h"
#include "terminal-util.h"

static int show_sysfs_one(
                const char *seat,
                sd_device **dev_list,
                size_t *i_dev,
                size_t n_dev,
                const char *sub,
                const char *prefix,
                unsigned n_columns,
                OutputFlags flags) {

        size_t max_width;
        int r;

        assert(seat);
        assert(dev_list);
        assert(i_dev);
        assert(prefix);

        if (flags & OUTPUT_FULL_WIDTH)
                max_width = SIZE_MAX;
        else if (n_columns < 10)
                max_width = 10;
        else
                max_width = n_columns;

        while (*i_dev < n_dev) {
                const char *sysfs, *sn, *name = NULL, *subsystem, *sysname;
                _cleanup_free_ char *k = NULL, *l = NULL;
                size_t lookahead;
                bool is_master;

                if (sd_device_get_syspath(dev_list[*i_dev], &sysfs) < 0 ||
                    !path_startswith(sysfs, sub))
                        return 0;

                r = device_get_seat(dev_list[*i_dev], &sn);
                if (r < 0)
                        return r;

                /* Explicitly also check for tag 'seat' here */
                if (!streq(seat, sn) ||
                    sd_device_has_current_tag(dev_list[*i_dev], "seat") <= 0 ||
                    sd_device_get_subsystem(dev_list[*i_dev], &subsystem) < 0 ||
                    sd_device_get_sysname(dev_list[*i_dev], &sysname) < 0) {
                        (*i_dev)++;
                        continue;
                }

                is_master = sd_device_has_current_tag(dev_list[*i_dev], "master-of-seat") > 0;

                if (sd_device_get_sysattr_value(dev_list[*i_dev], "name", &name) < 0)
                        (void) sd_device_get_sysattr_value(dev_list[*i_dev], "id", &name);

                /* Look if there's more coming after this */
                for (lookahead = *i_dev + 1; lookahead < n_dev; lookahead++) {
                        const char *lookahead_sysfs;

                        if (sd_device_get_syspath(dev_list[lookahead], &lookahead_sysfs) < 0)
                                continue;

                        if (path_startswith(lookahead_sysfs, sub) &&
                            !path_startswith(lookahead_sysfs, sysfs)) {
                                const char *lookahead_sn;

                                r = device_get_seat(dev_list[lookahead], &lookahead_sn);
                                if (r < 0)
                                        return r;

                                if (streq(seat, lookahead_sn) && sd_device_has_current_tag(dev_list[lookahead], "seat") > 0)
                                        break;
                        }
                }

                k = ellipsize(sysfs, max_width, 20);
                if (!k)
                        return -ENOMEM;

                printf("%s%s%s\n", prefix, glyph(lookahead < n_dev ? GLYPH_TREE_BRANCH : GLYPH_TREE_RIGHT), k);

                if (asprintf(&l,
                             "%s%s:%s%s%s%s",
                             is_master ? "[MASTER] " : "",
                             subsystem, sysname,
                             name ? " \"" : "", strempty(name), name ? "\"" : "") < 0)
                        return -ENOMEM;

                free(k);
                k = ellipsize(l, max_width, 70);
                if (!k)
                        return -ENOMEM;

                printf("%s%s%s\n", prefix, lookahead < n_dev ? glyph(GLYPH_TREE_VERTICAL) : "  ", k);

                if (++(*i_dev) < n_dev) {
                        _cleanup_free_ char *p = NULL;

                        p = strjoin(prefix, lookahead < n_dev ? glyph(GLYPH_TREE_VERTICAL) : "  ");
                        if (!p)
                                return -ENOMEM;

                        r = show_sysfs_one(seat, dev_list, i_dev, n_dev, sysfs, p,
                                           n_columns == UINT_MAX || n_columns < 2 ? n_columns : n_columns - 2,
                                           flags);
                        if (r < 0)
                                return r;
                }

        }

        return 0;
}

int show_sysfs(const char *seat, const char *prefix, unsigned n_columns, OutputFlags flags) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        size_t n_dev = 0, i = 0;
        sd_device **dev_list;
        int r;

        if (n_columns <= 0)
                n_columns = columns();

        prefix = strempty(prefix);

        if (isempty(seat))
                seat = "seat0";

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_tag(e, streq(seat, "seat0") ? "seat" : seat);
        if (r < 0)
                return r;

        r = device_enumerator_scan_devices(e);
        if (r < 0)
                return r;

        dev_list = device_enumerator_get_devices(e, &n_dev);

        if (dev_list && n_dev > 0)
                show_sysfs_one(seat, dev_list, &i, n_dev, "/", prefix, n_columns, flags);
        else
                printf("%s%s%s\n", prefix, glyph(GLYPH_TREE_RIGHT), "(none)");

        return 0;
}
