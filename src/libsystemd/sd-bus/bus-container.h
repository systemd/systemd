/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering
***/

#include "sd-bus.h"

int bus_container_connect_socket(sd_bus *b);
