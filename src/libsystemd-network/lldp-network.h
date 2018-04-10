/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani
***/

#include "sd-event.h"

int lldp_network_bind_raw_socket(int ifindex);
