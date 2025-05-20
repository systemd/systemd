/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "pidref.h"
#include "runtime-scope.h"
#include "set.h"

int journal_fork(RuntimeScope scope, char * const *units, PidRef *ret_pidref);

void journal_terminate(PidRef *pidref);
