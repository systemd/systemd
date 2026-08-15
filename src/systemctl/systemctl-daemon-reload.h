/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "systemctl.h"

int daemon_reload(enum action action, bool graceful);

int verb_daemon_reload(int argc, char *argv[], uintptr_t _data, void *userdata);
