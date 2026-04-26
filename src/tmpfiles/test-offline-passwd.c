/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "hashmap.h"
#include "offline-passwd.h"
#include "options.h"
#include "strv.h"
#include "tests.h"

static const char *arg_root = NULL;

static void test_resolve_one(const char *name) {
        bool relaxed = name || arg_root;

        if (!name)
                name = "root";

        log_info("/* %s(\"%s\") */", __func__, name);

        _cleanup_hashmap_free_ Hashmap *uid_cache = NULL, *gid_cache = NULL;
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

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert_se(argc >= 0);
        assert_se(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION('r', "root", "PATH", "Operate on an alternate filesystem root"):
                        arg_root = opts.arg;
                        break;
                }

        *ret_args = option_parser_get_args(&opts);
        return 0;
}

int main(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r < 0)
                return r;

        if (strv_isempty(args))
                test_resolve_one(NULL);
        else
                STRV_FOREACH(a, args)
                        test_resolve_one(*a);

        return 0;
}
