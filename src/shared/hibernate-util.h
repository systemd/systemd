/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fiemap.h>
#include <sys/types.h>

/* represents values for /sys/power/resume & /sys/power/resume_offset and the corresponding path */
typedef struct HibernateDevice {
        dev_t devno;
        uint64_t offset; /* in memory pages */
        char *path;
} HibernateDevice;

void hibernate_device_done(HibernateDevice *hibernate_device);

int find_suitable_hibernate_device_full(HibernateDevice *ret_device, uint64_t *ret_size, uint64_t *ret_used) {
static inline int find_suitable_hibernate_device(HibernateDevice *ret) {
        return find_suitable_hibernate_device_full(ASSERT_PTR(ret), NULL, NULL);
}

bool enough_swap_for_hibernation(void);

int write_resume_config(dev_t devno, uint64_t offset, const char *device);

/* Only for test-fiemap */
int read_fiemap(int fd, struct fiemap **ret);
