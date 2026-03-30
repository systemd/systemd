/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

int luo_open_device(void);
int luo_create_session(int device_fd, const char *name);
int luo_retrieve_session(int device_fd, const char *name);
int luo_session_preserve_fd(int session_fd, int fd, uint64_t token);
int luo_session_retrieve_fd(int session_fd, uint64_t token);
int luo_session_finish(int session_fd);
