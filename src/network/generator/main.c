/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "build.h"
#include "creds-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "generator.h"
#include "macro.h"
#include "main-func.h"
#include "mkdir.h"
#include "network-generator.h"
#include "path-util.h"
#include "proc-cmdline.h"

#define NETWORK_UNIT_DIRECTORY "/run/systemd/network/"

static const char *arg_root = NULL;

static int network_save(Network *network, const char *dest_dir) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(network);

        r = generator_open_unit_file_full(
                        dest_dir,
                        /* source= */ NULL,
                        /* name= */ NULL,
                        &f,
                        /* ret_final_path= */ NULL,
                        &temp_path);
        if (r < 0)
                return r;

        network_dump(network, f);

        if (asprintf(&p, "%s/%s-%s.network",
                     dest_dir,
                     isempty(network->ifname) ? "71" : "70",
                     isempty(network->ifname) ? "default" : network->ifname) < 0)
                return log_oom();

        r = conservative_rename(temp_path, p);
        if (r < 0)
                return log_error_errno(r, "Failed to rename '%s' to '%s': %m", temp_path, p);

        temp_path = mfree(temp_path);
        return 0;
}

static int netdev_save(NetDev *netdev, const char *dest_dir) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(netdev);

        r = generator_open_unit_file_full(
                        dest_dir,
                        /* source= */ NULL,
                        /* name= */ NULL,
                        &f,
                        /* ret_final_path= */ NULL,
                        &temp_path);
        if (r < 0)
                return r;

        netdev_dump(netdev, f);

        if (asprintf(&p, "%s/70-%s.netdev", dest_dir, netdev->ifname) < 0)
                return log_oom();

        r = conservative_rename(temp_path, p);
        if (r < 0)
                return log_error_errno(r, "Failed to rename '%s' to '%s': %m", temp_path, p);

        temp_path = mfree(temp_path);
        return 0;
}

static int link_save(Link *link, const char *dest_dir) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(link);

        r = generator_open_unit_file_full(
                        dest_dir,
                        /* source= */ NULL,
                        /* name= */ NULL,
                        &f,
                        /* ret_final_path= */ NULL,
                        &temp_path);
        if (r < 0)
                return r;

        link_dump(link, f);

        if (asprintf(&p, "%s/%s-%s.link",
                     dest_dir,
                     !isempty(link->ifname) ? "70" : !hw_addr_is_null(&link->mac) ? "71" : "72",
                     link->filename) < 0)
                return log_oom();

        r = conservative_rename(temp_path, p);
        if (r < 0)
                return log_error_errno(r, "Failed to rename '%s' to '%s': %m", temp_path, p);

        temp_path = mfree(temp_path);
        return 0;
}

static int context_save(Context *context) {
        Network *network;
        NetDev *netdev;
        Link *link;
        int r;

        const char *p = prefix_roota(arg_root, NETWORK_UNIT_DIRECTORY);

        r = mkdir_p(p, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create directory " NETWORK_UNIT_DIRECTORY ": %m");

        HASHMAP_FOREACH(network, context->networks_by_name)
                RET_GATHER(r, network_save(network, p));

        HASHMAP_FOREACH(netdev, context->netdevs_by_name)
                RET_GATHER(r, netdev_save(netdev, p));

        HASHMAP_FOREACH(link, context->links_by_filename)
                RET_GATHER(r, link_save(link, p));

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
        int r, ret = 0;

        log_setup();

        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (optind >= argc) {
                r = proc_cmdline_parse(parse_cmdline_item, &context, 0);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse kernel command line: %m");
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

        RET_GATHER(ret, context_save(&context));

        static const PickUpCredential table[] = {
                { "network.conf.",    "/run/systemd/networkd.conf.d/", ".conf"    },
                { "network.link.",    NETWORK_UNIT_DIRECTORY,          ".link"    },
                { "network.netdev.",  NETWORK_UNIT_DIRECTORY,          ".netdev"  },
                { "network.network.", NETWORK_UNIT_DIRECTORY,          ".network" },
        };
        RET_GATHER(ret, pick_up_credentials(table, ELEMENTSOF(table)));

        return ret;
}

DEFINE_MAIN_FUNCTION(run);
