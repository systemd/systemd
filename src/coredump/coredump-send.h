/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_send(CoredumpContext *context);
int coredump_send_to_container(CoredumpContext *context);
