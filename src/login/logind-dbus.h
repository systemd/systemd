/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

int manager_get_session_from_creds(Manager *m, sd_bus_message *message, const char *name, sd_bus_error *error, Session **ret);
int manager_get_user_from_creds(Manager *m, sd_bus_message *message, uid_t uid, sd_bus_error *error, User **ret);
int manager_get_seat_from_creds(Manager *m, sd_bus_message *message, const char *name, sd_bus_error *error, Seat **ret);

int manager_dispatch_delayed(Manager *manager, bool timeout);

int bus_manager_shutdown_or_sleep_now_or_later(Manager *m, const HandleActionData *a, sd_bus_error *error);

int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error);
int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error);

int manager_send_changed_strv(Manager *manager, char **properties);
#define manager_send_changed(manager, ...) manager_send_changed_strv(manager, STRV_MAKE(__VA_ARGS__))

int manager_start_scope(
                Manager *manager,
                const char *scope,
                const PidRef *pidref,
                bool allow_pidfd,
                const char *slice,
                const char *description,
                const char * const *requires,
                const char * const *wants,
                const char * const *extra_after,
                const char *requires_mounts_for,
                sd_bus_message *more_properties,
                sd_bus_error *error,
                char **ret_job);
int manager_start_unit(Manager *manager, const char *unit, sd_bus_error *error, char **ret_job);
int manager_stop_unit(Manager *manager, const char *unit, const char *job_mode, sd_bus_error *error, char **ret_job);
int manager_abandon_scope(Manager *manager, const char *scope, sd_bus_error *error);
int manager_kill_unit(Manager *manager, const char *unit, KillWhom whom, int signo, sd_bus_error *error);
int manager_unit_is_active(Manager *manager, const char *unit, sd_bus_error *error);
int manager_job_is_active(Manager *manager, const char *path, sd_bus_error *error);

void manager_load_scheduled_shutdown(Manager *m);

int manager_create_session(
                Manager *m,
                uid_t uid,
                PidRef *leader,
                const char *service,
                SessionType type,
                SessionClass class,
                const char *desktop,
                Seat *seat,
                unsigned vtnr,
                const char *tty,
                const char *display,
                bool remote,
                const char *remote_user,
                const char *remote_host,
                char * const *extra_device_access,
                Session **ret_session);

extern const BusObjectImplementation manager_object;
