/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

/* These functions serialize state for our own usage, i.e.: across a reload/reexec, rather than for being
 * passed to a child process. */

int unit_serialize_state(Unit *u, FILE *f, FDSet *fds, bool serialize_jobs);
int unit_deserialize_state(Unit *u, FILE *f, FDSet *fds);
int unit_deserialize_state_skip(FILE *f);

void unit_dump(Unit *u, FILE *f, const char *prefix);
