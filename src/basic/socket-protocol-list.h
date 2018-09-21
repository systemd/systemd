/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

const char *socket_protocol_to_name(int id);
int socket_protocol_from_name(const char *name);

int socket_protocol_max(void);
