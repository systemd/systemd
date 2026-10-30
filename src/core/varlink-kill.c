/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "json-util.h"
#include "kill.h"
#include "signal-util.h"
#include "unit.h"
#include "varlink-common.h"
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

        char *bad_field; /* Field path for error propagation. */
};

static JSON_DISPATCH_ENUM_DEFINE(dispatch_kill_mode, KillMode, kill_mode_from_string);
static DEFINE_VARLINK_APPLY_ENUM(kill_mode, KillMode, kill_mode_to_string);

TransientKillContextParameters* transient_kill_context_parameters_free(TransientKillContextParameters *p) {
        if (!p)
                return NULL;

        free(p->bad_field);
        return mfree(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(TransientKillContextParameters*, transient_kill_context_parameters_free);

int transient_kill_context_dispatch(
                sd_json_variant *variant,
                TransientKillContextParameters **ret,
                char **reterr_bad_field) {

        static const sd_json_dispatch_field kill_dispatch[] = {
                { "KillMode",   SD_JSON_VARIANT_STRING,  dispatch_kill_mode,        offsetof(TransientKillContextParameters, kill_mode),   0 },
                { "SendSIGHUP", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, offsetof(TransientKillContextParameters, send_sighup), 0 },
                {}
        };

        const char *bad_field = NULL;
        int r;

        assert(ret);

        _cleanup_(transient_kill_context_parameters_freep) TransientKillContextParameters *p = NULL;
        p = new(TransientKillContextParameters, 1);
        if (!p)
                return -ENOMEM;

        *p = (TransientKillContextParameters) {
                .kill_mode = _KILL_MODE_INVALID,
                .send_sighup = -1,
        };

        r = sd_json_dispatch_full(variant, kill_dispatch, /* bad= */ NULL, /* flags= */ 0, p, &bad_field);
        if (r < 0) {
                if (bad_field)
                        varlink_propagate_bad_field(bad_field, p->bad_field, reterr_bad_field);
                return r;
        }

        *ret = TAKE_PTR(p);
        return r;
}

int transient_kill_context_apply_properties(Unit *u, KillContext *k, TransientKillContextParameters *p) {
        assert(u);
        assert(k);
        assert(p);

        varlink_apply_enum_kill_mode(u, "KillMode", &k->kill_mode, p->kill_mode,
                                     /* refuse= */ NULL, UNIT_RUNTIME|UNIT_PRIVATE);
        varlink_apply_tristate_bool(u, "SendSIGHUP", &k->send_sighup, p->send_sighup, UNIT_RUNTIME|UNIT_PRIVATE);
        return 0;
}
