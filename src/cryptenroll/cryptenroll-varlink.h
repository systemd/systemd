/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"

/* Sends a progress 'state' notification over c->link, if (and only if) the enrollment was triggered via a
 * Varlink call with the 'more' flag set. A no-op (returning 0) otherwise. */
int enroll_context_notify_state(const EnrollContext *c, const char *state);

int cryptenroll_varlink_server(void);
