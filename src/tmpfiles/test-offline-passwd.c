/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "offline-passwd.h"
#include "user-util.h"
#include "format-util.h"
#include "tests.h"

static char *arg_root = NULL;

static void test_resolve_one(const char *name) {
        bool relaxed = name || arg_root;

        if (!name)
                name = "root";

        log_info("/* %s(\"%s\") */", __func__, name);

        _cleanup_(hashmap_freep) Hashmap *uid_cache = NULL, *gid_cache = NULL;
        uid_t uid = UID_INVALID;
        gid_t gid = GID_INVALID;
        int r;

        r = name_to_uid_offline(arg_root, name, &uid, &uid_cache);
        log_info_errno(r, "name_to_uid_offline: %s → "UID_FMT": %m", name, uid);
        assert_se(relaxed || r == 0);

        r = name_to_uid_offline(arg_root, name, &uid, &uid_cache);
        log_info_errno(r, "name_to_uid_offline: %s → "UID_FMT": %m", name, uid);
        assert_se(relaxed || r == 0);

        r = name_to_gid_offline(arg_root, name, &gid, &gid_cache);
        log_info_errno(r, "name_to_gid_offline: %s → "GID_FMT": %m", name, gid);
        assert_se(relaxed || r == 0);

        r = name_to_gid_offline(arg_root, name, &gid, &gid_cache);
        log_info_errno(r, "name_to_gid_offline: %s → "GID_FMT": %m", name, gid);
        assert_se(relaxed || r == 0);
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "root",           required_argument,   NULL, 'r' },
                {}
        };

        int c;

        assert_se(argc >= 0);
        assert_se(argv);

        while ((c = getopt_long(argc, argv, "r:", options, NULL)) >= 0)
                switch (c) {
                case 'r':
                        arg_root = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 0;
}

int main(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        r = parse_argv(argc, argv);
        if (r < 0)
                return r;

        if (optind >= argc)
                test_resolve_one(NULL);
        else
                while (optind < argc)
                        test_resolve_one(argv[optind++]);

        return 0;
}
