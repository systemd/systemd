/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-login.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

static const char *arg_verb = NULL;  /* NULL means all */
static pid_t arg_pid = 0;            /* 0 == self */

static int print_info(void) {
        const char* const *verbs = arg_verb ?
                STRV_MAKE_CONST(arg_verb) :
                STRV_MAKE_CONST("session",
                                "unit",
                                "user_unit",
                                "machine_name",
                                "slice",
                                "user_slice",
                                "owner_uid",
                                "cgroup");
        int r = 0;

        STRV_FOREACH(verb, verbs) {
                _cleanup_free_ char *ans = NULL;
                int k;

                if (streq(*verb, "session"))
                        k = sd_pid_get_session(arg_pid, &ans);
                else if (streq(*verb, "unit"))
                        k = sd_pid_get_unit(arg_pid, &ans);
                else if (streq(*verb, "user_unit"))
                        k = sd_pid_get_user_unit(arg_pid, &ans);
                else if (streq(*verb, "machine_name"))
                        k = sd_pid_get_machine_name(arg_pid, &ans);
                else if (streq(*verb, "slice"))
                        k = sd_pid_get_slice(arg_pid, &ans);
                else if (streq(*verb, "user_slice"))
                        k = sd_pid_get_user_slice(arg_pid, &ans);
                else if (streq(*verb, "owner_uid")) {
                        uid_t owner;

                        k = sd_pid_get_owner_uid(arg_pid, &owner);
                        if (k < 0)
                                log_info_errno(k, "sd_pid_get_%s("PID_FMT") → %m", *verb, arg_pid);
                        else
                                log_info("sd_pid_get_%s("PID_FMT") → "UID_FMT, *verb, arg_pid, owner);
                        RET_GATHER(r, k);
                        continue;
                } else if (streq(*verb, "cgroup"))
                        k = sd_pid_get_cgroup(arg_pid, &ans);
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb '%s'.", *verb);

                log_info("sd_pid_get_%s("PID_FMT") → %s",
                         *verb, arg_pid, k < 0 ? STRERROR(k) : ans);
                RET_GATHER(r, k);
        }

        return r;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        if (argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Syntax: test-sd-login [VERB|all [PID]]");

        arg_verb = streq_ptr(argv[1], "all") ? NULL : argv[1];

        if (argc == 3) {
                r = parse_pid(argv[2], &arg_pid);
                if (r < 0)
                        return log_error_errno(r, "Cannot parse PID %s: %m", argv[2]);
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        r = parse_argv(argc, argv);
        if (r < 0)
                return r;

        r = print_info();
        if (argc > 1)
                /* We were called manually… */
                return r;

        /* This is how we get executed by the test suite.
         * Do not return the error. */
        assert_se(IN_SET(r, 0, -ENODATA, -ENOENT));
        return 0;
}

DEFINE_MAIN_FUNCTION(run);
