/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "json-util.h"
#include "kill.h"
#include "signal-util.h"
#include "unit.h"
#include "varlink-kill.h"

/* Read side of the Kill context for List. */

int unit_kill_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        KillContext *c = userdata;

        assert(ret);

        if (!c) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        JSON_BUILD_PAIR_ENUM("KillMode", kill_mode_to_string(c->kill_mode)),
                        SD_JSON_BUILD_PAIR_STRING("KillSignal", signal_to_string(c->kill_signal)),
                        SD_JSON_BUILD_PAIR_STRING("RestartKillSignal", signal_to_string(restart_kill_signal(c))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGHUP", c->send_sighup),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGKILL", c->send_sigkill),
                        SD_JSON_BUILD_PAIR_STRING("FinalKillSignal", signal_to_string(c->final_kill_signal)),
                        SD_JSON_BUILD_PAIR_STRING("WatchdogSignal", signal_to_string(c->watchdog_signal)));
}

/* Write side of the Kill context for StartTransient. */

struct TransientKillContextParameters {
        KillMode kill_mode;  /* negative = absent */
        int send_sighup;     /* tristate: -1 = absent */
};

static JSON_DISPATCH_ENUM_DEFINE(dispatch_kill_mode, KillMode, kill_mode_from_string);

TransientKillContextParameters* transient_kill_context_parameters_free(TransientKillContextParameters *p) {
        return mfree(p);
}

int transient_kill_context_dispatch(
                sd_json_variant *variant,
                TransientKillContextParameters **ret,
                const char **reterr_field) {

        static const sd_json_dispatch_field kill_dispatch[] = {
                { "KillMode",   SD_JSON_VARIANT_STRING,  dispatch_kill_mode,        offsetof(TransientKillContextParameters, kill_mode),   0 },
                { "SendSIGHUP", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, offsetof(TransientKillContextParameters, send_sighup), 0 },
                {}
        };

        int r;

        assert(ret);

        _cleanup_free_ TransientKillContextParameters *p = NULL;
        p = new(TransientKillContextParameters, 1);
        if (!p)
                return -ENOMEM;

        *p = (TransientKillContextParameters) {
                .kill_mode = _KILL_MODE_INVALID,
                .send_sighup = -1,
        };

        r = sd_json_dispatch_full(variant, kill_dispatch, /* bad= */ NULL, /* flags= */ 0, p, reterr_field);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(p);
        return r;
}

int transient_kill_context_apply_properties(Unit *u, KillContext *k, TransientKillContextParameters *p) {
        assert(u);
        assert(k);
        assert(p);

        if (p->kill_mode >= 0) {
                k->kill_mode = p->kill_mode;
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "KillMode", "KillMode=%s", kill_mode_to_string(p->kill_mode));
        }

        if (p->send_sighup >= 0) {
                k->send_sighup = p->send_sighup;
                unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "SendSIGHUP", "SendSIGHUP=%s", yes_no(p->send_sighup));
        }

        return 0;
}
