/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "systemctl.h"

int daemon_reload(enum action, bool graceful);

int verb_daemon_reload(int argc, char *argv[], void *userdata);
