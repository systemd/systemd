/* -*- Mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2008-2010 David Zeuthen <davidz@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "gudevclient.h"
#include "gudevdevice.h"
#include "gudevmarshal.h"
#include "gudevprivate.h"

/**
 * SECTION:gudevclient
 * @short_description: Query devices and listen to uevents
 *
 * #GUdevClient is used to query information about devices on a Linux
 * system from the Linux kernel and the udev device
 * manager.
 *
 * Device information is retrieved from the kernel (through the
 * <literal>sysfs</literal> filesystem) and the udev daemon (through a
 * <literal>tmpfs</literal> filesystem) and presented through
 * #GUdevDevice objects. This means that no blocking IO ever happens
 * (in both cases, we are essentially just reading data from kernel
 * memory) and as such there are no asynchronous versions of the
 * provided methods.
 *
 * To get #GUdevDevice objects, use
 * g_udev_client_query_by_subsystem(),
 * g_udev_client_query_by_device_number(),
 * g_udev_client_query_by_device_file(),
 * g_udev_client_query_by_sysfs_path(),
 * g_udev_client_query_by_subsystem_and_name()
 * or the #GUdevEnumerator type.
 *
 * To listen to uevents, connect to the #GUdevClient::uevent signal.
 */

struct _GUdevClientPrivate
{
  GSource *watch_source;
  struct udev *udev;
  struct udev_monitor *monitor;

  gchar **subsystems;
};

enum
{
  PROP_0,
  PROP_SUBSYSTEMS,
};

enum
{
  UEVENT_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (GUdevClient, g_udev_client, G_TYPE_OBJECT)

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
monitor_event (GIOChannel *source,
               GIOCondition condition,
               gpointer data)
{
  GUdevClient *client = (GUdevClient *) data;
  GUdevDevice *device;
  struct udev_device *udevice;

  if (client->priv->monitor == NULL)
    goto out;
  udevice = udev_monitor_receive_device (client->priv->monitor);
  if (udevice == NULL)
    goto out;

  device = _g_udev_device_new (udevice);
  udev_device_unref (udevice);
  g_signal_emit (client,
                 signals[UEVENT_SIGNAL],
                 0,
                 g_udev_device_get_action (device),
                 device);
  g_object_unref (device);

 out:
  return TRUE;
}

static void
g_udev_client_finalize (GObject *object)
{
  GUdevClient *client = G_UDEV_CLIENT (object);

  if (client->priv->watch_source != NULL)
    {
      g_source_destroy (client->priv->watch_source);
      client->priv->watch_source = NULL;
    }

  if (client->priv->monitor != NULL)
    {
      udev_monitor_unref (client->priv->monitor);
      client->priv->monitor = NULL;
    }

  if (client->priv->udev != NULL)
    {
      udev_unref (client->priv->udev);
      client->priv->udev = NULL;
    }

  g_strfreev (client->priv->subsystems);

  if (G_OBJECT_CLASS (g_udev_client_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (g_udev_client_parent_class)->finalize (object);
}

static void
g_udev_client_set_property (GObject      *object,
                            guint         prop_id,
                            const GValue *value,
                            GParamSpec   *pspec)
{
  GUdevClient *client = G_UDEV_CLIENT (object);

  switch (prop_id)
    {
    case PROP_SUBSYSTEMS:
      if (client->priv->subsystems != NULL)
        g_strfreev (client->priv->subsystems);
      client->priv->subsystems = g_strdupv (g_value_get_boxed (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
g_udev_client_get_property (GObject     *object,
                            guint        prop_id,
                            GValue      *value,
                            GParamSpec  *pspec)
{
  GUdevClient *client = G_UDEV_CLIENT (object);

  switch (prop_id)
    {
    case PROP_SUBSYSTEMS:
      g_value_set_boxed (value, client->priv->subsystems);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
g_udev_client_constructed (GObject *object)
{
  GUdevClient *client = G_UDEV_CLIENT (object);
  GIOChannel *channel;
  guint n;

  client->priv->udev = udev_new ();

  /* connect to event source */
  client->priv->monitor = udev_monitor_new_from_netlink (client->priv->udev, "udev");

  //g_debug ("ss = %p", client->priv->subsystems);

  if (client->priv->subsystems != NULL)
    {
      /* install subsystem filters to only wake up for certain events */
      for (n = 0; client->priv->subsystems[n] != NULL; n++)
        {
          gchar *subsystem;
          gchar *devtype;
          gchar *s;

          subsystem = g_strdup (client->priv->subsystems[n]);
          devtype = NULL;

          //g_debug ("s = '%s'", subsystem);

          s = strstr (subsystem, "/");
          if (s != NULL)
            {
              devtype = s + 1;
              *s = '\0';
            }

          if (client->priv->monitor != NULL)
              udev_monitor_filter_add_match_subsystem_devtype (client->priv->monitor, subsystem, devtype);

          g_free (subsystem);
        }

      /* listen to events, and buffer them */
      if (client->priv->monitor != NULL)
        {
          udev_monitor_enable_receiving (client->priv->monitor);
          channel = g_io_channel_unix_new (udev_monitor_get_fd (client->priv->monitor));
          client->priv->watch_source = g_io_create_watch (channel, G_IO_IN);
          g_io_channel_unref (channel);
          g_source_set_callback (client->priv->watch_source, (GSourceFunc) monitor_event, client, NULL);
          g_source_attach (client->priv->watch_source, g_main_context_get_thread_default ());
          g_source_unref (client->priv->watch_source);
        }
      else
        {
          client->priv->watch_source = NULL;
        }
    }

  if (G_OBJECT_CLASS (g_udev_client_parent_class)->constructed != NULL)
    G_OBJECT_CLASS (g_udev_client_parent_class)->constructed (object);
}


static void
g_udev_client_class_init (GUdevClientClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;

  gobject_class->constructed  = g_udev_client_constructed;
  gobject_class->set_property = g_udev_client_set_property;
  gobject_class->get_property = g_udev_client_get_property;
  gobject_class->finalize     = g_udev_client_finalize;

  /**
   * GUdevClient:subsystems:
   *
   * The subsystems to listen for uevents on.
   *
   * To listen for only a specific DEVTYPE for a given SUBSYSTEM, use
   * "subsystem/devtype". For example, to only listen for uevents
   * where SUBSYSTEM is usb and DEVTYPE is usb_interface, use
   * "usb/usb_interface".
   *
   * If this property is %NULL, then no events will be reported. If
   * it's the empty array, events from all subsystems will be
   * reported.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_SUBSYSTEMS,
                                   g_param_spec_boxed ("subsystems",
                                                       "The subsystems to listen for changes on",
                                                       "The subsystems to listen for changes on",
                                                       G_TYPE_STRV,
                                                       G_PARAM_CONSTRUCT_ONLY |
                                                       G_PARAM_READWRITE));

  /**
   * GUdevClient::uevent:
   * @client: The #GUdevClient receiving the event.
   * @action: The action for the uevent e.g. "add", "remove", "change", "move", etc.
   * @device: Details about the #GUdevDevice the event is for.
   *
   * Emitted when @client receives an uevent.
   *
   * This signal is emitted in the
   * <link linkend="g-main-context-push-thread-default">thread-default main loop</link>
   * of the thread that @client was created in.
   */
  signals[UEVENT_SIGNAL] = g_signal_new ("uevent",
                                         G_TYPE_FROM_CLASS (klass),
                                         G_SIGNAL_RUN_LAST,
                                         G_STRUCT_OFFSET (GUdevClientClass, uevent),
                                         NULL,
                                         NULL,
                                         g_udev_marshal_VOID__STRING_OBJECT,
                                         G_TYPE_NONE,
                                         2,
                                         G_TYPE_STRING,
                                         G_UDEV_TYPE_DEVICE);

  g_type_class_add_private (klass, sizeof (GUdevClientPrivate));
}

static void
g_udev_client_init (GUdevClient *client)
{
  client->priv = G_TYPE_INSTANCE_GET_PRIVATE (client,
                                              G_UDEV_TYPE_CLIENT,
                                              GUdevClientPrivate);
}

/**
 * g_udev_client_new:
 * @subsystems: (array zero-terminated=1) (element-type utf8) (transfer none) (allow-none): A %NULL terminated string array of subsystems to listen for uevents on, %NULL to not listen on uevents at all, or an empty array to listen to uevents on all subsystems. See the documentation for the #GUdevClient:subsystems property for details on this parameter.
 *
 * Constructs a #GUdevClient object that can be used to query
 * information about devices. Connect to the #GUdevClient::uevent
 * signal to listen for uevents. Note that signals are emitted in the
 * <link linkend="g-main-context-push-thread-default">thread-default main loop</link>
 * of the thread that you call this constructor from.
 *
 * Returns: A new #GUdevClient object. Free with g_object_unref().
 */
GUdevClient *
g_udev_client_new (const gchar * const *subsystems)
{
  return G_UDEV_CLIENT (g_object_new (G_UDEV_TYPE_CLIENT, "subsystems", subsystems, NULL));
}

/**
 * g_udev_client_query_by_subsystem:
 * @client: A #GUdevClient.
 * @subsystem: (allow-none): The subsystem to get devices for or %NULL to get all devices.
 *
 * Gets all devices belonging to @subsystem.
 *
 * Returns: (nullable) (element-type GUdevDevice) (transfer full): A
 * list of #GUdevDevice objects. The caller should free the result by
 * using g_object_unref() on each element in the list and then
 * g_list_free() on the list.
 */
GList *
g_udev_client_query_by_subsystem (GUdevClient  *client,
                                  const gchar  *subsystem)
{
  struct udev_enumerate *enumerate;
  struct udev_list_entry *l, *devices;
  GList *ret;

  g_return_val_if_fail (G_UDEV_IS_CLIENT (client), NULL);

  ret = NULL;

  /* prepare a device scan */
  enumerate = udev_enumerate_new (client->priv->udev);

  /* filter for subsystem */
  if (subsystem != NULL)
    udev_enumerate_add_match_subsystem (enumerate, subsystem);
  /* retrieve the list */
  udev_enumerate_scan_devices (enumerate);

  /* add devices to the list */
  devices = udev_enumerate_get_list_entry (enumerate);
  for (l = devices; l != NULL; l = udev_list_entry_get_next (l))
    {
      struct udev_device *udevice;
      GUdevDevice *device;

      udevice = udev_device_new_from_syspath (udev_enumerate_get_udev (enumerate),
                                              udev_list_entry_get_name (l));
      if (udevice == NULL)
        continue;
      device = _g_udev_device_new (udevice);
      udev_device_unref (udevice);
      ret = g_list_prepend (ret, device);
    }
  udev_enumerate_unref (enumerate);

  ret = g_list_reverse (ret);

  return ret;
}

/**
 * g_udev_client_query_by_device_number:
 * @client: A #GUdevClient.
 * @type: A value from the #GUdevDeviceType enumeration.
 * @number: A device number.
 *
 * Looks up a device for a type and device number.
 *
 * Returns: (nullable) (transfer full): A #GUdevDevice object or %NULL
 * if the device was not found. Free with g_object_unref().
 */
GUdevDevice *
g_udev_client_query_by_device_number (GUdevClient      *client,
                                      GUdevDeviceType   type,
                                      GUdevDeviceNumber number)
{
  struct udev_device *udevice;
  GUdevDevice *device;

  g_return_val_if_fail (G_UDEV_IS_CLIENT (client), NULL);

  device = NULL;
  udevice = udev_device_new_from_devnum (client->priv->udev, type, number);

  if (udevice == NULL)
    goto out;

  device = _g_udev_device_new (udevice);
  udev_device_unref (udevice);

 out:
  return device;
}

/**
 * g_udev_client_query_by_device_file:
 * @client: A #GUdevClient.
 * @device_file: A device file.
 *
 * Looks up a device for a device file.
 *
 * Returns: (nullable) (transfer full): A #GUdevDevice object or %NULL
 * if the device was not found. Free with g_object_unref().
 */
GUdevDevice *
g_udev_client_query_by_device_file (GUdevClient  *client,
                                    const gchar  *device_file)
{
  struct stat stat_buf;
  GUdevDevice *device;

  g_return_val_if_fail (G_UDEV_IS_CLIENT (client), NULL);
  g_return_val_if_fail (device_file != NULL, NULL);

  device = NULL;

  if (stat (device_file, &stat_buf) != 0)
    goto out;

  if (stat_buf.st_rdev == 0)
    goto out;

  if (S_ISBLK (stat_buf.st_mode))
    device = g_udev_client_query_by_device_number (client, G_UDEV_DEVICE_TYPE_BLOCK, stat_buf.st_rdev);
  else if (S_ISCHR (stat_buf.st_mode))
    device = g_udev_client_query_by_device_number (client, G_UDEV_DEVICE_TYPE_CHAR, stat_buf.st_rdev);

 out:
  return device;
}

/**
 * g_udev_client_query_by_sysfs_path:
 * @client: A #GUdevClient.
 * @sysfs_path: A sysfs path.
 *
 * Looks up a device for a sysfs path.
 *
 * Returns: (nullable) (transfer full): A #GUdevDevice object or %NULL
 * if the device was not found. Free with g_object_unref().
 */
GUdevDevice *
g_udev_client_query_by_sysfs_path (GUdevClient  *client,
                                   const gchar  *sysfs_path)
{
  struct udev_device *udevice;
  GUdevDevice *device;

  g_return_val_if_fail (G_UDEV_IS_CLIENT (client), NULL);
  g_return_val_if_fail (sysfs_path != NULL, NULL);

  device = NULL;
  udevice = udev_device_new_from_syspath (client->priv->udev, sysfs_path);
  if (udevice == NULL)
    goto out;

  device = _g_udev_device_new (udevice);
  udev_device_unref (udevice);

 out:
  return device;
}

/**
 * g_udev_client_query_by_subsystem_and_name:
 * @client: A #GUdevClient.
 * @subsystem: A subsystem name.
 * @name: The name of the device.
 *
 * Looks up a device for a subsystem and name.
 *
 * Returns: (nullable) (transfer full): A #GUdevDevice object or %NULL
 * if the device was not found. Free with g_object_unref().
 */
GUdevDevice *
g_udev_client_query_by_subsystem_and_name (GUdevClient  *client,
                                           const gchar  *subsystem,
                                           const gchar  *name)
{
  struct udev_device *udevice;
  GUdevDevice *device;

  g_return_val_if_fail (G_UDEV_IS_CLIENT (client), NULL);
  g_return_val_if_fail (subsystem != NULL, NULL);
  g_return_val_if_fail (name != NULL, NULL);

  device = NULL;
  udevice = udev_device_new_from_subsystem_sysname (client->priv->udev, subsystem, name);
  if (udevice == NULL)
    goto out;

  device = _g_udev_device_new (udevice);
  udev_device_unref (udevice);

 out:
  return device;
}

struct udev *
_g_udev_client_get_udev (GUdevClient *client)
{
  g_return_val_if_fail (G_UDEV_IS_CLIENT (client), NULL);
  return client->priv->udev;
}
