/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "argv-util.h"
#include "ask-password-agent.h"
#include "hashmap.h"
#include "main-func.h"
#include "pager.h"
#include "polkit-agent.h"
#include "selinux-util.h"

int _define_main_function_impl(
                int argc,
                char *argv[],
                MainIntroFunction intro,
                MainImplFunction impl,
                MainResultMapFunction result_to_exit_status,
                MainResultMapFunction result_to_return_value,
                typeof(static_destruct) _static_destruct,
                void *userdata) {

        int r;

        if (intro) {
                r = intro(argc, argv, userdata);
                if (r < 0)
                        return result_to_exit_status(r);
        }

        r = impl(argc, argv, userdata);
        if (r < 0)
                (void) sd_notifyf(0, "ERRNO=%i", -r);

        (void) sd_notifyf(0, "EXIT_STATUS=%i", result_to_exit_status(r));
        ask_password_agent_close();
        polkit_agent_close();
        pager_close();
        mac_selinux_finish();
        _static_destruct();
        return result_to_return_value(r);
}

int raise_or_exit_status(int ret) {
        if (ret < 0)
                return EXIT_FAILURE;
        if (ret == 0)
                return EXIT_SUCCESS;
        if (!SIGNAL_VALID(ret))
                return EXIT_FAILURE;

#if HAVE_VALGRIND_VALGRIND_H
        /* If raise() below succeeds, the destructor cleanup_pools() in hashmap.c will never called. */
        if (RUNNING_ON_VALGRIND)
                hashmap_trim_pools();
#endif

        (void) raise(ret);
        /* exit with failure if raise() does not immediately abort the program. */
        return EXIT_FAILURE;
}
