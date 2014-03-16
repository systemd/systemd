/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Kay Sievers

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"
#include "sd-event.h"

typedef struct SNTPContext SNTPContext;
struct SNTPContext;

int sntp_new(SNTPContext **sntp, sd_event *e);
SNTPContext *sntp_unref(SNTPContext *sntp);
int sntp_server_connect(SNTPContext *sntp, const char *server);
void sntp_server_disconnect(SNTPContext *sntp);
void sntp_report_register(SNTPContext *sntp, void (*report)(usec_t poll_usec, double offset, double delay, double jitter, bool spike));
