/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "time-util.h"
#include "timesyncd-forward.h"

/* udev tag marking PTP hardware clocks (PHCs) that track UTC and are hence suitable for synchronizing the
 * system clock to, such as the ones hypervisors offer to their guests. These are local clocks that can be
 * read cheaply via an ioctl(), hence we can poll them frequently and do not need any of the NTP machinery.
 * The tag is set by 50-udev-default.rules. */
#define PHC_UDEV_TAG "timesync"

#define PHC_POLL_INTERVAL_USEC (2 * USEC_PER_SEC)

/* How many consecutive read failures we tolerate before we give up on a PHC device */
#define PHC_MAX_FAILURES 5U

/* Number of sys/phc/sys sandwiches to request per PTP_SYS_OFFSET call, we use the tightest one */
#define PHC_SAMPLES 9U

struct ptp_sys_offset;

int phc_pick_sample(
                const struct ptp_sys_offset *s,
                int64_t *ret_offset_nsec,
                int64_t *ret_delay_nsec,
                int64_t *ret_device_nsec);

int manager_phc_setup(Manager *m);
void manager_phc_stop(Manager *m);
bool manager_phc_active(Manager *m);
