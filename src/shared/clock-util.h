/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int clock_is_localtime(const char *adjtime_path);
int clock_set_timezone(int *ret_minutesdelta);

#define EPOCH_CLOCK_FILE "/usr/lib/clock-epoch"
#define TIMESYNCD_CLOCK_FILE_DIR "/var/lib/systemd/timesync/"
#define TIMESYNCD_CLOCK_FILE TIMESYNCD_CLOCK_FILE_DIR "clock"
