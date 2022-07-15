/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-server.h"

int server_open_dev_kmsg(Server *s);
int server_flush_dev_kmsg(Server *s);

void server_forward_kmsg(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred);

int server_open_kernel_seqnum(Server *s);

void dev_kmsg_record(Server *s, char *p, size_t l);
