/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "sd-bus.h"

#include "bus-internal.h"
#include "macro.h"

_public_ int sd_bus_interface_name_is_valid(const char *p) {
        assert_return(p, -EINVAL);

        return interface_name_is_valid(p);
}

_public_ int sd_bus_service_name_is_valid(const char *p) {
        assert_return(p, -EINVAL);

        return service_name_is_valid(p);
}

_public_ int sd_bus_member_name_is_valid(const char *p) {
        assert_return(p, -EINVAL);

        return member_name_is_valid(p);
}

_public_ int sd_bus_object_path_is_valid(const char *p) {
        assert_return(p, -EINVAL);

        return object_path_is_valid(p);
}
