/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-varlink.h"

#include "udev-ctrl.h"

typedef struct UdevConnection {
        sd_varlink *link;
        UdevCtrl *uctrl;
} UdevConnection;

int udev_connection_init(UdevConnection *conn);
void udev_connection_done(UdevConnection *conn);

int udev_connection_wait(UdevConnection *conn, usec_t timeout);

int udev_connection_send_ping(UdevConnection *conn);
