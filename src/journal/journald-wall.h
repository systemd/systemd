/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Sebastian Thorarensen
***/

#include "journald-server.h"

void server_forward_wall(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred);
