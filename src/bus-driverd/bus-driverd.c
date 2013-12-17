/***
  This file is part of systemd.

  Copyright 2013 Daniel Mack

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/timex.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "kdbus.h"
#include "sd-bus.h"
#include "bus-internal.h"

#include "sd-daemon.h"
#include "sd-event.h"
#include "event-util.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-message.h"
#include "bus-kernel.h"
#include "socket-util.h"
#include "util.h"
#include "build.h"
#include "strv.h"
#include "sd-id128.h"
#include "async.h"
#include "hashmap.h"
#include "def.h"

/*
 * TODO:
 *
 * AddMatch / RemoveMatch
 * ListActivatableNames
 * StartServiceByName
 */

static int driver_name_info_error(sd_bus *bus, sd_bus_message *m, const char *name, int error_code) {

        if (error_code == -ENXIO || error_code == -ENOENT)
                return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_NAME_HAS_NO_OWNER,
                                                  "Could not get owner of name '%s': no such name",
                                                  name);

        return sd_bus_reply_method_errno(m, error_code, NULL);
}

static int driver_add_match(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        char *arg0, *match;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        match = strdup(arg0);
        if (!match)
                return -ENOMEM;

        /* FIXME */

        return sd_bus_reply_method_return(m, NULL);
}

static int driver_remove_match(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        /* FIXME */

        return sd_bus_reply_method_return(m, NULL);
}

static int driver_get_security_ctx(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        r = sd_bus_get_owner(bus, arg0, SD_BUS_CREDS_SELINUX_CONTEXT, &creds);
        if (r < 0) {
                if (r == -ENOENT)
                        return driver_name_info_error(bus, m, arg0, r);
                else
                        return r;
        }

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_array(reply, 'y', creds->label, strlen(creds->label));
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int driver_get_pid(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        r = sd_bus_get_owner(bus, arg0, SD_BUS_CREDS_PID, &creds);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "u", creds->pid);
}

static int driver_get_user(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        r = sd_bus_get_owner(bus, arg0, SD_BUS_CREDS_UID, &creds);
        if (r < 0) {
                if (r == -ENOENT)
                        return driver_name_info_error(bus, m, arg0, r);
                else
                        return r;
        }

        return sd_bus_reply_method_return(m, "u", creds->uid);
}

static int driver_get_id(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        sd_id128_t server_id;
        char buf[SD_ID128_STRING_MAX];
        int r;

        r = sd_bus_get_server_id(bus, &server_id);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "s", sd_id128_to_string(server_id, buf));
}

static int driver_get_name_owner(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        r = sd_bus_get_owner(bus, arg0, SD_BUS_CREDS_UNIQUE_NAME, &creds);
        if (r < 0) {
                if (r == -ENOENT)
                        return driver_name_info_error(bus, m, arg0, r);
                else
                        return r;
        }

        return sd_bus_reply_method_return(m, "s", creds->unique_name);
}

static int driver_hello(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        return sd_bus_reply_method_return(m, "s", m->sender);
}

static int driver_list_names(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **names = NULL;
        int r;

        r = sd_bus_list_names(bus, &names, NULL);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, names);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int driver_list_activatable_names(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **names = NULL;
        int r;

        r = sd_bus_list_names(bus, NULL, &names);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, names);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int driver_list_queued_owners(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        struct kdbus_cmd_name_list cmd = {};
        struct kdbus_name_list *name_list;
        struct kdbus_cmd_name *name;
        _cleanup_strv_free_ char **owners = NULL;
        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        cmd.flags = KDBUS_NAME_LIST_QUEUED;

        r = ioctl(bus->input_fd, KDBUS_CMD_NAME_LIST, &cmd);
        if (r < 0)
                return -errno;

        name_list = (struct kdbus_name_list *) ((uint8_t *) bus->kdbus_buffer + cmd.offset);

        KDBUS_ITEM_FOREACH(name, name_list, names) {
                if (name->size > sizeof(*name) && !streq(name->name, arg0)) {
                        char *n;

                        if (asprintf(&n, ":1.%llu", (unsigned long long) name->id) < 0)
                                return -ENOMEM;

                        r = strv_push(&owners, n);
                        if (r < 0) {
                                free(n);
                                return -ENOMEM;
                        }
                }
        }

        r = ioctl(sd_bus_get_fd(bus), KDBUS_CMD_FREE, &cmd.offset);
        if (r < 0)
                return -errno;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, owners);
        if (r < 0)
                return r;

        return sd_bus_send(bus, reply, NULL);
}

static int driver_name_has_owner(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        char *arg0;
        int r;

        r = sd_bus_message_read(m, "s", &arg0);
        if (r < 0)
                return r;

        r = sd_bus_get_owner(bus, arg0, 0, NULL);
        if (r < 0 && r != -ENOENT)
                return r;

        return sd_bus_reply_method_return(m, "b", r == 0);
}

static int driver_request_name(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        struct kdbus_cmd_name *cmd_name;
        uint32_t flags;
        size_t size;
        uint64_t id;
        char *name;
        int r;

        r = sd_bus_message_read(m, "su", &name, &flags);
        if (r < 0)
                return r;

        size = sizeof(*cmd_name) + strlen(name) + 1;

        cmd_name = alloca(size);
        memset(cmd_name, 0, size);
        strcpy(cmd_name->name, name);
        cmd_name->size = size;
        kdbus_translate_request_name_flags(flags, (uint64_t *) &cmd_name->conn_flags);

        /* This function is open-coded because we request the name 'on behalf'
         * of the requesting connection */
        r = bus_kernel_parse_unique_name(m->sender, &id);
        if (r < 0)
                return r;

        cmd_name->id = id;

        r = ioctl(sd_bus_get_fd(bus), KDBUS_CMD_NAME_ACQUIRE, cmd_name);
        if (r < 0) {
                if (errno == EEXIST)
                        return sd_bus_reply_method_return(m, "u", BUS_NAME_EXISTS);
                else if (errno == EALREADY)
                        return sd_bus_reply_method_return(m, "u", BUS_NAME_ALREADY_OWNER);
                else
                        return sd_bus_reply_method_return(m, "u", -errno);
        }

        if (cmd_name->flags & KDBUS_NAME_IN_QUEUE)
                return sd_bus_reply_method_return(m, "u", BUS_NAME_IN_QUEUE);

        return sd_bus_reply_method_return(m, "u", BUS_NAME_PRIMARY_OWNER);
}

static int driver_start_service_by_name(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        char *s;
        int r;

        return sd_bus_reply_method_return(m, "u", 2);

        r = sd_bus_message_read(m, "s", &s);
        if (r < 0)
                return r;

        /* FIXME */

        return sd_bus_send(bus, reply, NULL);
}

static int driver_unsupported(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "%s() is not supported", sd_bus_message_get_member(m));
}

static const sd_bus_vtable driver_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("AddMatch", "s", NULL, driver_add_match, 0),
        SD_BUS_METHOD("GetConnectionSELinuxSecurityContext", "s", "ay", driver_get_security_ctx, 0),
        SD_BUS_METHOD("GetConnectionUnixProcessID", "s", "u", driver_get_pid, 0),
        SD_BUS_METHOD("GetConnectionUnixUser", "s", "u", driver_get_user, 0),
        SD_BUS_METHOD("GetId", NULL, "s", driver_get_id, 0),
        SD_BUS_METHOD("GetNameOwner", "s", "s", driver_get_name_owner, 0),
        SD_BUS_METHOD("Hello", NULL, "s", driver_hello, 0),
        SD_BUS_METHOD("ListActivatableNames", NULL, "as", driver_list_activatable_names, 0),
        SD_BUS_METHOD("ListNames", NULL, "as", driver_list_names, 0),
        SD_BUS_METHOD("ListQueuedOwners", "s", "as", driver_list_queued_owners, 0),
        SD_BUS_METHOD("NameHasOwner", "s", "b", driver_name_has_owner, 0),
        SD_BUS_METHOD("ReloadConfig", NULL, NULL, driver_unsupported, 0),
        SD_BUS_METHOD("RemoveMatch", "s", NULL, driver_remove_match, 0),
        SD_BUS_METHOD("RequestName", "su", "u", driver_request_name, 0),
        SD_BUS_METHOD("StartServiceByName", "su", "u", driver_start_service_by_name, 0),
        SD_BUS_METHOD("UpdateActivationEnvironment", "a{ss}", NULL, driver_unsupported, 0),
        SD_BUS_SIGNAL("NameAcquired", "s", 0),
        SD_BUS_SIGNAL("NameLost", "s", 0),
        SD_BUS_SIGNAL("NameOwnerChanged", "sss", 0),
        SD_BUS_VTABLE_END
};

static int connect_bus(sd_event *event, sd_bus **_bus) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        assert(event);
        assert(_bus);

        r = sd_bus_default_system(&bus);
        if (r < 0) {
                log_error("Failed to create bus: %s", strerror(-r));
                return r;
        }

        r = sd_bus_add_object_vtable(bus, "/org/freedesktop/DBus", "org.freedesktop.DBus", driver_vtable, NULL);
        if (r < 0) {
                log_error("Failed to add manager object vtable: %s", strerror(-r));
                return r;
        }

        r = sd_bus_request_name(bus, "org.freedesktop.DBus", 0);
        if (r < 0) {
                log_error("Unable to request name: %s\n", strerror(-r));
                return r;
        }

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0) {
                log_error("Error %d while adding bus to even: %s", r, strerror(-r));
                return r;
        }

        *_bus = bus;
        bus = NULL;

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *event = NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        r = sd_event_default(&event);
        if (r < 0) {
                log_error("Failed to allocate event loop: %s", strerror(-r));
                goto finish;
        }

        sd_event_set_watchdog(event, true);

        r = connect_bus(event, &bus);
        if (r < 0)
                goto finish;

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.DBus", DEFAULT_EXIT_USEC);
        if (r < 0) {
                log_error("Failed to run event loop: %s", strerror(-r));
                goto finish;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

}
