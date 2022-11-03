/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>

#include "bus-common-errors.h"
#include "bus-polkit.h"
#include "data-fd-util.h"
#include "fd-util.h"
#include "oomd-manager-bus.h"
#include "oomd-manager.h"
#include "user-util.h"

static int bus_method_dump_by_fd(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *dump = NULL;
        _cleanup_close_ int fd = -1;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = manager_get_dump_string(m, &dump);
        if (r < 0)
                return r;

        fd = acquire_data_fd(dump, strlen(dump), 0);
        if (fd < 0)
                return fd;

        return sd_bus_reply_method_return(message, "h", fd);
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD_WITH_NAMES("DumpByFileDescriptor",
                                 NULL,,
                                 "h",
                                 SD_BUS_PARAM(fd),
                                 bus_method_dump_by_fd,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL_WITH_NAMES("Killed",
                                 "ss",
                                 SD_BUS_PARAM(cgroup)
                                 SD_BUS_PARAM(reason),
                                 0),
        SD_BUS_VTABLE_END
};

const BusObjectImplementation manager_object = {
        "/org/freedesktop/oom1",
        "org.freedesktop.oom1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
};
