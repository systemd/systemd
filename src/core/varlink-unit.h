/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

#define VARLINK_ERROR_UNIT_NO_SUCH_UNIT "io.systemd.Unit.NoSuchUnit"
#define VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY "io.systemd.Unit.OnlyByDependency"
#define VARLINK_ERROR_UNIT_DBUS_SHUTTING_DOWN "io.systemd.Unit.DBusShuttingDown"

int vl_method_list_units(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int varlink_unit_queue_job_one(
                Unit *u,
                JobType type,
                JobMode mode,
                bool reload_if_possible,
                uint32_t *ret_job_id,
                sd_bus_error *reterr_bus_error);

int vl_method_set_unit_properties(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int varlink_error_no_such_unit(sd_varlink *v, const char *name);
