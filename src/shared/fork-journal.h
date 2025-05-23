/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int journal_fork(RuntimeScope scope, char * const *units, PidRef *ret_pidref);

void journal_terminate(PidRef *pidref);
