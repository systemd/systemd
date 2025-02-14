/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "pidref.h"

int notify_recv(int fd, char **ret_text, struct ucred *ret_ucred, PidRef *ret_pidref);
