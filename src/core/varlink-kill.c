/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "kill.h"
#include "signal-util.h"
#include "varlink-kill.h"
#include "varlink-util.h"

int unit_kill_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        KillContext *c = userdata;

        assert(ret);

        if (!c) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("KillMode", kill_mode_to_string(c->kill_mode)),
                        SD_JSON_BUILD_PAIR_STRING("KillSignal", signal_to_string(c->kill_signal)),
                        SD_JSON_BUILD_PAIR_STRING("RestartKillSignal", signal_to_string(restart_kill_signal(c))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGHUP", c->send_sighup),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGKILL", c->send_sigkill),
                        SD_JSON_BUILD_PAIR_STRING("FinalKillSignal", signal_to_string(c->final_kill_signal)),
                        SD_JSON_BUILD_PAIR_STRING("WatchdogSignal", signal_to_string(c->watchdog_signal)));
}
