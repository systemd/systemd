/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum DeviceType DeviceType;
typedef struct SessionDevice SessionDevice;

#include "list.h"
#include "logind.h"

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
        DeviceType type:3;
        bool active:1;
        bool pushed_fd:1;

        LIST_FIELDS(struct SessionDevice, sd_by_device);
};

int session_device_new(Session *s, dev_t dev, bool open_device, SessionDevice **ret);
SessionDevice *session_device_free(SessionDevice *sd);
DEFINE_TRIVIAL_CLEANUP_FUNC(SessionDevice*, session_device_free);

void session_device_complete_pause(SessionDevice *sd);

void session_device_resume_all(Session *s);
void session_device_pause_all(Session *s);
unsigned session_device_try_pause_all(Session *s);

int session_device_save(SessionDevice *sd);
void session_device_attach_fd(SessionDevice *sd, int fd, bool active);
