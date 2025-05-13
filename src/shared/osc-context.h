/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"

int osc_context_open_boot(char **ret_seq);
int osc_context_open_container(const char *name, char **ret_seq, sd_id128_t *ret_context_id);
int osc_context_open_vm(const char *name, char **ret_seq, sd_id128_t *ret_context_id);
int osc_context_open_chpriv(const char *target_user, char **ret_seq, sd_id128_t *ret_context_id);
int osc_context_open_session(const char *user, const char *session_id, char **ret_seq, sd_id128_t *ret_context_id);
int osc_context_open_service(const char *unit, sd_id128_t invocation_id, char **ret_seq);
int osc_context_close(sd_id128_t id, char **ret_seq);

static inline void osc_context_closep(sd_id128_t *context_id) {
        (void) osc_context_close(*ASSERT_PTR(context_id), NULL);
}

int osc_context_id_from_invocation_id(sd_id128_t id, sd_id128_t *ret);
