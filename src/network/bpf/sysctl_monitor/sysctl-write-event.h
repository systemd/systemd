#pragma once

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct sysctl_write_event {
        pid_t pid;
        char comm[TASK_COMM_LEN];
        char name[64];
        char current[32];
        char newvalue[32];
};
