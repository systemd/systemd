/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

#define VARLINK_ERROR_UNIT_NO_SUCH_UNIT "io.systemd.Unit.NoSuchUnit"
#define VARLINK_ERROR_UNIT_ONLY_BY_DEPENDENCY "io.systemd.Unit.OnlyByDependency"
#define VARLINK_ERROR_UNIT_DBUS_SHUTTING_DOWN "io.systemd.Unit.DBusShuttingDown"
#define VARLINK_ERROR_UNIT_UNIT_EXISTS "io.systemd.Unit.UnitExists"
#define VARLINK_ERROR_UNIT_TYPE_NOT_SUPPORTED "io.systemd.Unit.UnitTypeNotSupported"
#define VARLINK_ERROR_UNIT_BAD_SETTING "io.systemd.Unit.BadUnitSetting"

int vl_method_list_units(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int varlink_unit_queue_job_one(
                Unit *u,
                JobType type,
                JobMode mode,
                bool reload_if_possible,
                uint32_t *ret_job_id,
                Job **ret_job,
                sd_bus_error *reterr_bus_error);

int vl_method_set_unit_properties(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int vl_method_start_transient_unit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

void varlink_unit_send_change_signal(Unit *u);
void varlink_job_send_change_signal(Job *j);
void varlink_job_send_removed_signal(Job *j);

int varlink_error_no_such_unit(sd_varlink *v, const char *name);
