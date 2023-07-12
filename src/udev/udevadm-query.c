/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>

#include "device-enumerator-private.h"
#include "device-util.h"
#include "format-table.h"
#include "parse-argument.h"
#include "path-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "udevadm.h"

static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static char **arg_properties = NULL;
static char **arg_tags = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_properties, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tags, strv_freep);

static int parse_property_argument(const char *s) {
        _cleanup_free_ char *k, *v;
        int r;

        r = extract_many_words(&s, "=", EXTRACT_DONT_COALESCE_SEPARATORS, &k, &v, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse property match %s: %m", s);
        if (r < 2)
                return log_error_errno(SYNTHETIC_ERRNO(r), "Missing '=' in property match %s.", s);

        if (!filename_is_valid(k))
                return log_error_errno(r, "%s is not a valid property name", k);

        return strv_consume_pair(&arg_properties, TAKE_PTR(k), TAKE_PTR(v));
}

static int help(void) {
        printf("%s query [OPTIONS] DEVICE [DEVICE…]\n\n"
               "Query sysfs or the udev database.\n\n"
               "  -h --help               Print this message\n"
               "  -V --version            Print version of the program\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "  -p --property=KEY=VALUE Match against entries with the given property\n"
               "  -t --tag=TAG            Match against entries with the given tag\n",
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
                { "help",        no_argument,       NULL, 'h'           },
                { "version",     no_argument,       NULL, 'V'           },
                { "no-pager",    no_argument,       NULL, ARG_NO_PAGER  },
                { "no-legend",   no_argument,       NULL, ARG_NO_LEGEND },
                { "json",        required_argument, NULL, ARG_JSON      },
                { "property",    required_argument, NULL, 'p'           },
                { "tag",         required_argument, NULL, 't'           },
                {}
        };

        int c, r;

        while ((c = getopt_long(argc, argv, "p:t:hV", options, NULL)) >= 0)

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

                case 'p':
                        r = parse_property_argument(optarg);
                        if (r < 0)
                                return r;
                        break;

                case 't':
                        r = strv_extend(&arg_tags, optarg);
                        if (r < 0)
                                return log_oom();
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

int query_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device enumerator: %m");

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return log_error_errno(r, "Failed to enable enumeration of uninitialized devices: %m");

        STRV_FOREACH_PAIR(k, v, arg_properties) {
                r = sd_device_enumerator_add_match_property(e, *k, *v);
                if (r < 0)
                        return log_error_errno(r, "Failed to add property match: %m");
        }

        STRV_FOREACH(s, arg_tags) {
                r = sd_device_enumerator_add_match_tag(e, *s);
                if (r < 0)
                        return log_error_errno(r, "Failed to add tag match: %m");
        }

        FOREACH_DEVICE(e, d) {
                if (t) {
                        r = table_add_delimiter(t);
                        if (r < 0)
                                return r;
                } else {
                        t = table_new_vertical();
                        if (!t)
                                return log_oom();

                        table_set_header(t, false);
                }

                FOREACH_DEVICE_PROPERTY(d, key, value) {
                        r = table_add_many(t, TABLE_FIELD, key, TABLE_SET_ALIGN_PERCENT, 100, TABLE_STRING, value);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}
