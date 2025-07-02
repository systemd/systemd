/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int fork_notify(char * const *cmdline, PidRef *ret_pidref);

void fork_notify_terminate(PidRef *pidref);

int journal_fork(RuntimeScope scope, char * const *units, PidRef *ret_pidref);
