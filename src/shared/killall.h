/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <signal.h>

#include "time-util.h"

int pid_set_survivor_cgroup(pid_t pid);
int broadcast_signal(int sig, bool wait_for_exit, bool send_sighup, usec_t timeout);
