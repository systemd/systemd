/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Server Server;

int server_open_varlink(Server *s, const char *socket, int fd);
