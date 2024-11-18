/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

int osc_context_open_boot(char **ret_seq);
int osc_context_open_container(const char *name, char **ret_seq, sd_id128_t *ret_context_id);
int osc_context_open_vm(const char *name, char **ret_seq, sd_id128_t *ret_context_id);
int osc_context_open_chpriv(const char *target_user, char **ret_seq, sd_id128_t *ret_context_id);
int osc_context_close(sd_id128_t id, char **ret_seq);

static inline void osc_context_closep(sd_id128_t *context_id) {
        (void) osc_context_close(*context_id, NULL);
}
