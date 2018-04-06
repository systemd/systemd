/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek
***/

#include "time-util.h"

int parse_sleep_config(const char *verb, char ***modes, char ***states, usec_t *delay);

int can_sleep(const char *verb);
int can_sleep_disk(char **types);
int can_sleep_state(char **types);
