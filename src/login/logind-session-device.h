/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 David Herrmann

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

typedef enum DeviceType DeviceType;
typedef struct SessionDevice SessionDevice;

#include "list.h"
#include "util.h"
#include "logind.h"
#include "logind-device.h"
#include "logind-seat.h"
#include "logind-session.h"

enum DeviceType {
        DEVICE_TYPE_UNKNOWN,
        DEVICE_TYPE_DRM,
        DEVICE_TYPE_EVDEV,
};

struct SessionDevice {
        Session *session;
        Device *device;

        dev_t dev;
        char *node;
        int fd;
        bool active;
        DeviceType type;

        LIST_FIELDS(struct SessionDevice, sd_by_device);
};

int session_device_new(Session *s, dev_t dev, SessionDevice **out);
void session_device_free(SessionDevice *sd);
void session_device_complete_pause(SessionDevice *sd);

void session_device_resume_all(Session *s);
void session_device_pause_all(Session *s);
unsigned int session_device_try_pause_all(Session *s);
