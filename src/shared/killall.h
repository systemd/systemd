/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "time-util.h"

int broadcast_signal(int sig, bool wait_for_exit, bool send_sighup, usec_t timeout);
