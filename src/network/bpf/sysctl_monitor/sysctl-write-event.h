/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct sysctl_write_event {
        /* Used to track changes in the struct layout */
        int version;
        /* The name of the binary that triggered the event */
        char comm[TASK_COMM_LEN];
        /* The path of the sysctl, relative to /proc/sys/ */
        char name[100];
        /* The value of the sysctl just before the write */
        char current[180];
        /* The new value being written into the sysctl */
        char newvalue[180];
};
