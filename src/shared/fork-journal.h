/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "runtime-scope.h"
#include "set.h"

int journal_fork(RuntimeScope scope, Set **pids, const char *unit);

Set *journal_terminate(Set *pids);

DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, journal_terminate);
