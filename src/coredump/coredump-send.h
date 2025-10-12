/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int pidref_can_forward_coredump(const PidRef *pid);

int coredump_send(CoredumpContext *context, int input_fd);
int coredump_send_to_container(CoredumpContext *context, int input_fd);
