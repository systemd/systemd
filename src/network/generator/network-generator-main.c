/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "creds-util.h"
#include "dlopen-note.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "generator.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "network-generator.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "verbs.h"

#define NETWORK_UNIT_DIRECTORY "/run/systemd/network/"
#define NETWORKD_CONF_DROPIN_DIRECTORY "/run/systemd/networkd.conf.d/"

static const char *arg_root = NULL;

COMMAND(
        "systemd-network-generator\0",
        "Generate network configuration from the kernel command line.",
        .argspec = "[-- KERNEL_CMDLINE]\0",
        .man_pages = "systemd-network-generator.service(8)\0",
);

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

        _cleanup_free_ char *p = path_join(arg_root, NETWORK_UNIT_DIRECTORY);
        if (!p)
                return log_oom();

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

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("root", "PATH",
                            "Operate on an alternate filesystem root"):
                        arg_root = opts.arg;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_clear) Context context = {};
        int r, ret = 0;

        LIBSELINUX_NOTE(recommended);

        log_setup();

        umask(0022);

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        if (strv_isempty(args)) {
                r = proc_cmdline_parse(parse_cmdline_item, &context, 0);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse kernel command line: %m");
        } else {
                STRV_FOREACH(a, args) {
                        _cleanup_free_ char *word = NULL;
                        char *value;

                        word = strdup(*a);
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

        context_finalize_bootif(&context);

        r = context_merge_networks(&context);
        if (r < 0)
                return log_warning_errno(r, "Failed to merge multiple command line options: %m");

        RET_GATHER(ret, context_save(&context));

        _cleanup_free_ char *network_dir = path_join(arg_root, NETWORK_UNIT_DIRECTORY);
        if (!network_dir)
                return log_oom();

        _cleanup_free_ char *networkd_conf_dropin_dir = path_join(arg_root, NETWORKD_CONF_DROPIN_DIRECTORY);
        if (!networkd_conf_dropin_dir)
                return log_oom();

        const PickUpCredential table[] = {
                { "network.conf.",    networkd_conf_dropin_dir, ".conf"    },
                { "network.link.",    network_dir,               ".link"    },
                { "network.netdev.",  network_dir,               ".netdev"  },
                { "network.network.", network_dir,               ".network" },
        };
        RET_GATHER(ret, pick_up_credentials(table, ELEMENTSOF(table)));

        return ret;
}

DEFINE_MAIN_FUNCTION(run);
