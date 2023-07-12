/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "static-destruct.h"
#include "string-table.h"
#include "strv.h"
#include "udev-util.h"
#include "udevadm.h"
#include "device-enumerator-private.h"
#include "format-table.h"
#include "terminal-util.h"

static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;

static int help(void) {
        printf("%s wait [OPTIONS] DEVICE [DEVICE…]\n\n"
               "Wait for devices or device symlinks being created.\n\n"
               "  -h --help             Print this message\n"
               "  -V --version          Print version of the program\n"
               "  -t --timeout=SEC      Maximum time to wait for the device\n"
               "     --initialized=BOOL Wait for devices being initialized by systemd-udevd\n"
               "     --removed          Wait for devices being removed\n"
               "     --settle           Also wait for all queued events being processed\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_NO_PAGER = 0x100,
                ARG_NO_LEGEND,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, 'V'             },
                { "no-pager",    no_argument,       NULL, ARG_NO_PAGER             },
                { "no-legend",   no_argument,       NULL, ARG_NO_LEGEND            },
                { "json",        required_argument, NULL, ARG_JSON        },
                {}
        };

        int c, r;

        while ((c = getopt_long(argc, argv, "t:hV", options, NULL)) >= 0)

                switch (c) {

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case 'V':
                        return print_version();

                case 'h':
                        return help();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1; /* work to do */
}

static int query(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        sd_device **array;
        size_t n = 0;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device enumerator: %m");

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return log_error_errno(r, "Failed to enable enumeration of uninitialized devices: %m");

        r = device_enumerator_scan_devices(e);
        if (r < 0)
                return log_error_errno(r, "Failed to scan for devices and subsystems: %m");

        assert_se(array = device_enumerator_get_devices(e, &n));

        t = table_new_vertical();
        if (!t)
                return log_oom();

        table_set_header(t, false);

        FOREACH_ARRAY(d, array, n) {
                FOREACH_DEVICE_PROPERTY(*d, key, value) {
                        r = table_add_many(t, TABLE_FIELD, key, TABLE_SET_ALIGN_PERCENT, 100, TABLE_STRING, value);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_delimiter(t);
                if (r < 0)
                        return r;
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

int query_main(int argc, char *argv[], void *userdata) {
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = query();
        if (r < 0)
                return r;

        return 0;
}
