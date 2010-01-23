/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foodevicehfoo
#define foodevicehfoo

typedef struct Device Device;

#include "name.h"

/* We simply watch devices, we cannot plug/unplug them. That
 * simplifies the state engine greatly */
typedef enum DeviceState {
        DEVICE_DEAD,
        DEVICE_AVAILABLE,
        _DEVICE_STATE_MAX
} DeviceState;

struct Device {
        Meta meta;

        DeviceState state;

        /* A single device can be created by multiple sysfs objects */
        char **sysfs;
};

extern const NameVTable device_vtable;

#endif
