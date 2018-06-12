/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2012 Lennart Poettering
***/

#include "time-util.h"

void broadcast_signal(int sig, bool wait_for_exit, bool send_sighup, usec_t timeout);
