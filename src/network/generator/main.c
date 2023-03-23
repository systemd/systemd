/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "build.h"
#include "fd-util.h"
#include "fs-util.h"
#include "generator.h"
#include "macro.h"
#include "main-func.h"
#include "mkdir.h"
#include "network-generator.h"
#include "path-util.h"
#include "proc-cmdline.h"

#define NETWORKD_UNIT_DIRECTORY "/run/systemd/network"

static const char *arg_root = NULL;

static int network_save(Network *network, const char *dest_dir) {
        _cleanup_free_ char *filename = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(network);

        r = asprintf(&filename, "%s-%s.network",
                     isempty(network->ifname) ? "91" : "90",
                     isempty(network->ifname) ? "default" : network->ifname);
        if (r < 0)
                return log_oom();

        r = generator_open_unit_file(dest_dir, "kernel command line", filename, &f);
        if (r < 0)
                return r;

        network_dump(network, f);

        return 0;
}

static int netdev_save(NetDev *netdev, const char *dest_dir) {
        _cleanup_free_ char *filename = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(netdev);

        r = asprintf(&filename, "90-%s.netdev",
                     netdev->ifname);
        if (r < 0)
                return log_oom();

        r = generator_open_unit_file(dest_dir, "kernel command line", filename, &f);
        if (r < 0)
                return r;

        netdev_dump(netdev, f);

        return 0;
}

static int link_save(Link *link, const char *dest_dir) {
        _cleanup_free_ char *filename = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(link);

        filename = strjoin(!isempty(link->ifname) ? "90" :
                           !hw_addr_is_null(&link->mac) ? "91" : "92",
                           "-", link->filename, ".link");
        if (!filename)
                return log_oom();

        r = generator_open_unit_file(dest_dir, "kernel command line", filename, &f);
        if (r < 0)
                return r;

        link_dump(link, f);

        return 0;
}

static int context_save(Context *context, const char *dest_dir) {
        Network *network;
        NetDev *netdev;
        Link *link;
        int k, r = 0;

        if (access(dest_dir, F_OK) < 0) {
                r = mkdir_p(dest_dir, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory %s: %m", dest_dir);
        }

        HASHMAP_FOREACH(network, context->networks_by_name) {
                k = network_save(network, dest_dir);
                if (k < 0 && r >= 0)
                        r = k;
        }

        HASHMAP_FOREACH(netdev, context->netdevs_by_name) {
                k = netdev_save(netdev, dest_dir);
                if (k < 0 && r >= 0)
                        r = k;
        }

        HASHMAP_FOREACH(link, context->links_by_filename) {
                k = link_save(link, dest_dir);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int help(void) {
        printf("%s [OPTIONS...] [-- KERNEL_CMDLINE]\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "     --root=PATH                  Operate on an alternate filesystem root\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
        };
        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "root",               required_argument, NULL, ARG_ROOT               },
                {},
        };
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_ROOT:
                        arg_root = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_clear) Context context = {};
        _cleanup_free_ char *unit_dir = NULL, *cmdline_parsed_file = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        unit_dir = path_join(arg_root, NETWORKD_UNIT_DIRECTORY);
        if (!unit_dir)
                return log_oom();

        if (optind >= argc) {
                cmdline_parsed_file = path_join(unit_dir, "cmdline-parsed");
                if (!cmdline_parsed_file)
                        return log_oom();

                r = access(cmdline_parsed_file, F_OK);
                if (r >= 0) {
                        log_info("Kernel command line already parsed");
                        return 0;
                }
                else if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to determine whether %s exists, ignoring: %m", cmdline_parsed_file);

                r = proc_cmdline_parse(parse_cmdline_item, &context, 0);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse kernel command line: %m");

                r = touch_file(cmdline_parsed_file, /* parents= */ true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID);
                if (r < 0)
                        log_debug_errno(r, "Failed to touch %s, ignoring: %m", cmdline_parsed_file);
        } else {
                for (int i = optind; i < argc; i++) {
                        _cleanup_free_ char *word = NULL;
                        char *value;

                        word = strdup(argv[i]);
                        if (!word)
                                return log_oom();

                        value = strchr(word, '=');
                        if (value)
                                *(value++) = 0;

                        r = parse_cmdline_item(word, value, &context);
                        if (r < 0)
                                return log_warning_errno(r, "Failed to parse command line \"%s%s%s\": %m",
                                                         word, value ? "=" : "", strempty(value));
                }
        }

        r = context_merge_networks(&context);
        if (r < 0)
                return log_warning_errno(r, "Failed to merge multiple command line options: %m");

        return context_save(&context, unit_dir);
}

DEFINE_MAIN_FUNCTION(run);
