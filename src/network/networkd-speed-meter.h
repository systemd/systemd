/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Default interval is 10sec. The speed meter periodically make networkd
 * to be woke up. So, too small interval value is not desired.
 * We set the minimum value 100msec = 0.1sec. */
#define SPEED_METER_DEFAULT_TIME_INTERVAL (10 * USEC_PER_SEC)
#define SPEED_METER_MINIMUM_TIME_INTERVAL (100 * USEC_PER_MSEC)

typedef struct Manager Manager;

int manager_start_speed_meter(Manager *m);
