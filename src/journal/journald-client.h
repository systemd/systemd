/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"

int client_context_read_log_filter_patterns(ClientContext *c, const char *cgroup);
int client_context_check_keep_log(ClientContext *c, const char *message, size_t len);
