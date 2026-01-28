/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"

int syslog_fixup_facility(int priority) _const_;

size_t syslog_parse_identifier(const char **buf, char **ret_identifier, pid_t *ret_pid);

void manager_forward_syslog(Manager *m, int priority, const char *identifier, const char *message, const struct ucred *ucred, const struct timeval *tv);

void manager_process_syslog_message(Manager *m, const char *buf, size_t buf_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len);
int manager_open_syslog_socket(Manager *m, const char *syslog_socket);

void manager_maybe_warn_forward_syslog_missed(Manager *m);
