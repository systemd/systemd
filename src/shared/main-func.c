/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#include "argv-util.h"
#include "ask-password-agent.h"
#include "hashmap.h"
#include "main-func.h"
#include "pager.h"
#include "polkit-agent.h"
#include "selinux-util.h"
#include "signal-util.h"

void main_prepare(int argc, char *argv[]) {
        assert_se(argc > 0 && !isempty(argv[0]));
        save_argc_argv(argc, argv);
}

void main_finalize(void) {
        ask_password_agent_close();
        polkit_agent_close();
        pager_close();
        mac_selinux_finish();
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
