#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>

#include "udev.h"
#include "udev_version.h"
#include "udev_dbus.h"
#include "logging.h"


/** variable for the connection the to system message bus or #NULL
 *  if we cannot connect or acquire the org.kernel.udev service
 */
static DBusConnection* sysbus_connection;

/** Disconnect from the system message bus */
void sysbus_disconnect(void)
{
	if (sysbus_connection == NULL)
		return;

	dbus_connection_disconnect(sysbus_connection);
	sysbus_connection = NULL;
}

/** Connect to the system message bus */
void sysbus_connect(void)
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
		printf("cannot acquire org.kernel.udev service, error %s: %s'",
		       error.name, error.message);
		sysbus_disconnect();
		return;
	}
}


/** Send out a signal that a device node is created
 *
 *  @param  dev                 udevice object
 *  @param  path                Sysfs path of device
 */
void sysbus_send_create(struct udevice *dev, const char *path)
{
	char filename[255];
	DBusMessage* message;
	DBusMessageIter iter;

	if (sysbus_connection == NULL)
		return;

	strncpy(filename, udev_root, sizeof(filename));
	strncat(filename, dev->name, sizeof(filename));

	/* object, interface, member */
	message = dbus_message_new_signal("/org/kernel/udev/NodeMonitor", 
					  "org.kernel.udev.NodeMonitor",
					  "NodeCreated");

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_append_string(&iter, filename);
	dbus_message_iter_append_string(&iter, path);

	if ( !dbus_connection_send(sysbus_connection, message, NULL) )
		dbg("error sending d-bus signal");

	dbus_message_unref(message);

	dbus_connection_flush(sysbus_connection);
}

/** Send out a signal that a device node is deleted
 *
 *  @param  name                Name of the device node, e.g. /udev/sda1
 *  @param  path                Sysfs path of device
 */
void sysbus_send_remove(const char* name, const char *path)
{
	char filename[255];
	DBusMessage* message;
	DBusMessageIter iter;

	if (sysbus_connection == NULL)
		return;

	strncpy(filename, udev_root, sizeof(filename));
	strncat(filename, name, sizeof(filename));

	/* object, interface, member */
	message = dbus_message_new_signal("/org/kernel/udev/NodeMonitor", 
					  "org.kernel.udev.NodeMonitor",
					  "NodeDeleted");

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_append_string(&iter, filename);
	dbus_message_iter_append_string(&iter, path);

	if ( !dbus_connection_send(sysbus_connection, message, NULL) )
		dbg("error sending d-bus signal");

	dbus_message_unref(message);

	dbus_connection_flush(sysbus_connection);
}
