/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "argv-util.h"
#include "ask-password-agent.h"
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
                typeof(static_destruct) static_destruct,
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
        static_destruct();
        return result_to_return_value(r);
}
