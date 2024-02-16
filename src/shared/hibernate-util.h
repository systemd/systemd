/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fiemap.h>
#include <sys/types.h>

/* represents values for /sys/power/resume & /sys/power/resume_offset and the corresponding path */
typedef struct HibernationDevice {
        dev_t devno;
        uint64_t offset; /* in memory pages */
        char *path;
} HibernationDevice;

void hibernation_device_done(HibernationDevice *hibernation_device);

int find_suitable_hibernation_device_full(HibernationDevice *ret_device, uint64_t *ret_size, uint64_t *ret_used);
static inline int find_suitable_hibernation_device(HibernationDevice *ret) {
        return find_suitable_hibernation_device_full(ASSERT_PTR(ret), NULL, NULL);
}

int hibernation_is_safe(void);

int write_resume_config(dev_t devno, uint64_t offset, const char *device);

void clear_efi_hibernate_location_and_warn(void);

/* Only for test-fiemap */
int read_fiemap(int fd, struct fiemap **ret);
