/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "machine.h"

int lookup_machine_by_name(sd_varlink *link, Manager *manager, const char *machine_name, Machine **ret_machine);
int lookup_machine_by_pid(sd_varlink *link, Manager *manager, pid_t pid, Machine **ret_machine);

int vl_method_register(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
