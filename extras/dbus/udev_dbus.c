/*
 * udev_dbus.c
 *
 * Copyright (C) 2003 David Zeuthen <david@fubar.dk>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>

#include "../../udev_lib.h"
#include "../../logging.h"

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

/*  Variable for the connection the to system message bus or NULL
 *  if we cannot connect or acquire the org.kernel.udev service
 */
static DBusConnection* sysbus_connection;

/* Disconnect from the system message bus */
static void sysbus_disconnect(void)
{
	if (sysbus_connection == NULL)
		return;

	dbus_connection_disconnect(sysbus_connection);
	sysbus_connection = NULL;
}

/* Connect to the system message bus */
static void sysbus_connect(void)
{
	DBusError error;

	/* Connect to a well-known bus instance, the system bus */
	dbus_error_init(&error);
	sysbus_connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (sysbus_connection == NULL) {
		dbg("cannot connect to system message bus, error %s: %s", 
		    error.name, error.message);
		dbus_error_free(&error);
		return;
	}

	/*  Acquire the org.kernel.udev service such that listeners
	 *  know that the message is really from us and not from a
	 *  random attacker. See the file udev_sysbus_policy.conf for
	 *  details.
	 *
	 *  Note that a service can have multiple owners (though there
	 *  is a concept of a primary owner for reception of messages)
	 *  so no race is introduced if two copies of udev is running
	 *  at the same time.
	 */
	dbus_bus_acquire_service(sysbus_connection, "org.kernel.udev", 0, 
				 &error);
	if (dbus_error_is_set(&error)) {
		dbg("cannot acquire org.kernel.udev service, error %s: %s'",
		    error.name, error.message);
		sysbus_disconnect();
		return;
	}
}


/*  Send out a signal that a device node is created
 *
 *  @param  devname		Name of the device node, e.g. /dev/sda1
 *  @param  path		Sysfs path of device
 */
static void sysbus_send_create(const char *devname, const char *path)
{
	DBusMessage* message;
	DBusMessageIter iter;

	/* object, interface, member */
	message = dbus_message_new_signal("/org/kernel/udev/NodeMonitor", 
					  "org.kernel.udev.NodeMonitor",
					  "NodeCreated");

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_append_string(&iter, devname);
	dbus_message_iter_append_string(&iter, path);

	if ( !dbus_connection_send(sysbus_connection, message, NULL) )
		dbg("error sending d-bus signal");

	dbus_message_unref(message);

	dbus_connection_flush(sysbus_connection);
}

/*  Send out a signal that a device node is deleted
 *
 *  @param  devname		Name of the device node, e.g. /udev/sda1
 *  @param  path		Sysfs path of device
 */
static void sysbus_send_remove(const char *devname, const char *path)
{
	DBusMessage* message;
	DBusMessageIter iter;

	/* object, interface, member */
	message = dbus_message_new_signal("/org/kernel/udev/NodeMonitor", 
					  "org.kernel.udev.NodeMonitor",
					  "NodeDeleted");

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_append_string(&iter, devname);
	dbus_message_iter_append_string(&iter, path);

	if ( !dbus_connection_send(sysbus_connection, message, NULL) )
		dbg("error sending d-bus signal");

	dbus_message_unref(message);

	dbus_connection_flush(sysbus_connection);
}

int main(int argc, char *argv[], char *envp[])
{
	char *action;
	char *devpath;
	char *devname;
	int retval = 0;

	init_logging("udev_dbus");

	sysbus_connect();
	if (sysbus_connection == NULL)
		return 0;

	action = get_action();
	if (!action) {
		dbg("no action?");
		goto exit;
	}
	devpath = get_devpath();
	if (!devpath) {
		dbg("no devpath?");
		goto exit;
	}
	devname = get_devname();
	if (!devname) {
		dbg("no devname?");
		goto exit;
	}

	if (strcmp(action, "add") == 0) {
		sysbus_send_create(devname, devpath);
	} else {
		if (strcmp(action, "remove") == 0) {
			sysbus_send_remove(devname, devpath);
		} else {
			dbg("unknown action '%s'", action);
			retval = -EINVAL;
		}
	}

exit:
	sysbus_disconnect();
	return retval;
}
