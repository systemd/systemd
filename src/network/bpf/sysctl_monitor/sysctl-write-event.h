#pragma once

struct sysctl_write_event {
        pid_t pid;
        char comm[32];
        char name[64];
        char current[32];
        char newvalue[32];
};
