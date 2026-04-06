/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "output-mode.h"
#include "shared-forward.h"

int fork_notify(char * const *argv, PidRef *ret_pidref);

void fork_notify_terminate(PidRef *pidref);

void fork_notify_terminate_many(sd_event_source **array, size_t n);

int journal_fork(RuntimeScope scope, char * const *units, OutputMode output, PidRef *ret_pidref);
