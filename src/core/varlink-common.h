/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata);
int rlimit_table_build_json(sd_json_variant **ret, const char *name, void *userdata);
int cpuset_build_json(sd_json_variant **ret, const char *name, void *userdata);
const char* varlink_error_id_from_bus_error(const sd_bus_error *e);
int exec_command_build_json(sd_json_variant **ret, const char *name, void *userdata);
int exec_command_list_build_json(sd_json_variant **ret, const char *name, void *userdata);
int varlink_reply_bus_error(sd_varlink *link, int r, const sd_bus_error *e);
