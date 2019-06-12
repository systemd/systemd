/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "logind.h"
#include "logind-session.h"
#include "logind-user.h"

int manager_get_session_from_creds(Manager *m, sd_bus_message *message, const char *name, sd_bus_error *error, Session **ret);
int manager_get_user_from_creds(Manager *m, sd_bus_message *message, uid_t uid, sd_bus_error *error, User **ret);
int manager_get_seat_from_creds(Manager *m, sd_bus_message *message, const char *name, sd_bus_error *error, Seat **ret);

int manager_dispatch_delayed(Manager *manager, bool timeout);

int bus_manager_shutdown_or_sleep_now_or_later(Manager *m, const char *unit_name, InhibitWhat w, sd_bus_error *error);

int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error);

int manager_send_changed(Manager *manager, const char *property, ...) _sentinel_;

int manager_start_scope(Manager *manager, const char *scope, pid_t pid, const char *slice, const char *description, char **wants, char **after, const char *requires_mounts_for, sd_bus_message *more_properties, sd_bus_error *error, char **job);
int manager_start_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job);
int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job);
int manager_abandon_scope(Manager *manager, const char *scope, sd_bus_error *error);
int manager_kill_unit(Manager *manager, const char *unit, KillWho who, int signo, sd_bus_error *error);
int manager_unit_is_active(Manager *manager, const char *unit, sd_bus_error *error);
int manager_job_is_active(Manager *manager, const char *path, sd_bus_error *error);
