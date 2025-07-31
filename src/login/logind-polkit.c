/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "logind.h"
#include "logind-polkit.h"

int check_polkit_chvt(sd_bus_message *message, Manager *manager, sd_bus_error *error) {
#if ENABLE_POLKIT
        return bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.chvt",
                        /* details= */ NULL,
                        &manager->polkit_registry,
                        error);
#else
        /* Allow chvt when polkit is not present. This allows a service to start a graphical session as a
         * non-root user when polkit is not compiled in, more closely matching the default polkit policy */
        return 1;
#endif
}
