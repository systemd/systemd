/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "journald-forward.h"

typedef enum {
        HOSTNAME_NONE,
        HOSTNAME_IGNORE,
        HOSTNAME_USE
} HostnameField;

int syslog_fixup_facility(int priority) _const_;

size_t syslog_parse_identifier(const char **buf, char **identifier, char **pid);
size_t syslog_parse_hostname(const char **buf, char **hostname);

void manager_forward_syslog(Manager *m, int priority, const char *identifier, const char *message, const struct ucred *ucred, const struct timeval *tv);

void manager_process_syslog_message(Manager *m, const char *buf, size_t buf_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len);
void manager_process_syslog_message_remote(Manager *m, const char *buf, size_t buf_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len, HostnameField hostname_field, const union sockaddr_union *sa,  socklen_t salen);
int manager_open_syslog_socket(Manager *m, const char *syslog_socket);
int manager_open_udp_socket(Manager *m);

void manager_maybe_warn_forward_syslog_missed(Manager *m);
