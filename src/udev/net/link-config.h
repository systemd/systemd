/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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

#pragma once

#include "libudev.h"
#include "util.h"
#include "list.h"


typedef struct link_config_ctx link_config_ctx;
typedef struct link_config link_config;

struct link_config {
        char *filename;

        char *match_mac;
        char *match_path;
        char *match_driver;
        char *match_type;

        char *description;
        unsigned int speed;
        char *duplex;
        char *wol;

        LIST_FIELDS(link_config, links);
};

int link_config_ctx_new(link_config_ctx **ret);
void link_config_ctx_free(link_config_ctx *ctx);

int link_config_load(link_config_ctx *ctx);
bool link_config_should_reload(link_config_ctx *ctx);

int link_config_get(link_config_ctx *ctx, struct udev_device *device, struct link_config **ret);
int link_config_apply(link_config_ctx *ctx, struct link_config *config, struct udev_device *device);

/* gperf lookup function */
const struct ConfigPerfItem* link_config_gperf_lookup(const char *key, unsigned length);
