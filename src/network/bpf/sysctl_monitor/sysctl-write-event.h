/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct sysctl_write_event {
        char comm[TASK_COMM_LEN];
        char name[64];
        char current[32];
        char newvalue[32];
};
