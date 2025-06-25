/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

extern const BusObjectImplementation session_object;

char* session_bus_path(Session *s);

int session_send_signal(Session *s, bool new_session);
int session_send_changed_strv(Session *s, char **properties);
#define session_send_changed(s, ...) session_send_changed_strv(s, STRV_MAKE(__VA_ARGS__))
int session_send_lock(Session *s, bool lock);
int session_send_lock_all(Manager *m, bool lock);

int session_send_create_reply_bus(Session *s, const sd_bus_error *error);
int session_send_upgrade_reply(Session *s, const sd_bus_error *error);

int bus_session_method_activate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_session_method_lock(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_session_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_session_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error);
