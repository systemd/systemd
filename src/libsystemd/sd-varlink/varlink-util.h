/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "pidref.h"
#include "set.h"

int varlink_get_peer_pidref(sd_varlink *v, PidRef *ret);

int varlink_call_and_log(sd_varlink *v, const char *method, sd_json_variant *parameters, sd_json_variant **ret_parameters);
int varlink_callb_and_log(sd_varlink *v, const char *method, sd_json_variant **ret_parameters, ...);
#define varlink_callbo_and_log(v, method, ret_parameters, ...)          \
        varlink_callb_and_log((v), (method), (ret_parameters), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

int varlink_many_notify(Set *s, sd_json_variant *parameters);
int varlink_many_notifyb(Set *s, ...);
#define varlink_many_notifybo(s, ...)                                   \
        varlink_many_notifyb((s), SD_JSON_BUILD_OBJECT(__VA_ARGS__))
int varlink_many_reply(Set *s, sd_json_variant *parameters);
int varlink_many_error(Set *s, const char *error_id, sd_json_variant *parameters);

int varlink_set_info_systemd(sd_varlink_server *server);

int varlink_server_new(
                sd_varlink_server **ret,
                sd_varlink_server_flags_t flags,
                void *userdata);
