#pragma once

struct sysctl_write_event {
        char comm[32];
        char name[64];
        char current[32];
        char newvalue[32];
};
