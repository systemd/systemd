/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-id128.h"

int register_machine(
                sd_bus *bus,
                const char *machine_name,
                sd_id128_t uuid,
                const char *service,
                const char *directory,
                unsigned cid,
                const char *address,
                const char *key_path,
                bool keep_unit);

int unregister_machine(sd_bus *bus, const char *machine_name);
