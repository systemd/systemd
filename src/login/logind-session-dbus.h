/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "logind-session.h"

extern const sd_bus_vtable session_vtable[];
int session_node_enumerator(sd_bus *bus, const char *path,void *userdata, char ***nodes, sd_bus_error *error);
int session_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
char *session_bus_path(Session *s);

int session_send_signal(Session *s, bool new_session);
int session_send_changed(Session *s, const char *properties, ...) _sentinel_;
int session_send_lock(Session *s, bool lock);
int session_send_lock_all(Manager *m, bool lock);

int session_send_create_reply(Session *s, sd_bus_error *error);

int bus_session_method_activate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_session_method_lock(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_session_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_session_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error);
