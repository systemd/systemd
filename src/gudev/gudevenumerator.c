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
#include "gudevenumerator.h"
#include "gudevdevice.h"
#include "gudevmarshal.h"
#include "gudevprivate.h"

/**
 * SECTION:gudevenumerator
 * @short_description: Lookup and sort devices
 *
 * #GUdevEnumerator is used to lookup and sort devices.
 *
 * Since: 165
 */

struct _GUdevEnumeratorPrivate
{
  GUdevClient *client;
  struct udev_enumerate *e;
};

enum
{
  PROP_0,
  PROP_CLIENT,
};

G_DEFINE_TYPE (GUdevEnumerator, g_udev_enumerator, G_TYPE_OBJECT)

/* ---------------------------------------------------------------------------------------------------- */

static void
g_udev_enumerator_finalize (GObject *object)
{
  GUdevEnumerator *enumerator = G_UDEV_ENUMERATOR (object);

  if (enumerator->priv->client != NULL)
    {
      g_object_unref (enumerator->priv->client);
      enumerator->priv->client = NULL;
    }

  if (enumerator->priv->e != NULL)
    {
      udev_enumerate_unref (enumerator->priv->e);
      enumerator->priv->e = NULL;
    }

  if (G_OBJECT_CLASS (g_udev_enumerator_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (g_udev_enumerator_parent_class)->finalize (object);
}

static void
g_udev_enumerator_set_property (GObject      *object,
                                guint         prop_id,
                                const GValue *value,
                                GParamSpec   *pspec)
{
  GUdevEnumerator *enumerator = G_UDEV_ENUMERATOR (object);

  switch (prop_id)
    {
    case PROP_CLIENT:
      if (enumerator->priv->client != NULL)
        g_object_unref (enumerator->priv->client);
      enumerator->priv->client = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
g_udev_enumerator_get_property (GObject     *object,
                                guint        prop_id,
                                GValue      *value,
                                GParamSpec  *pspec)
{
  GUdevEnumerator *enumerator = G_UDEV_ENUMERATOR (object);

  switch (prop_id)
    {
    case PROP_CLIENT:
      g_value_set_object (value, enumerator->priv->client);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
g_udev_enumerator_constructed (GObject *object)
{
  GUdevEnumerator *enumerator = G_UDEV_ENUMERATOR (object);

  g_assert (G_UDEV_IS_CLIENT (enumerator->priv->client));

  enumerator->priv->e = udev_enumerate_new (_g_udev_client_get_udev (enumerator->priv->client));

  if (G_OBJECT_CLASS (g_udev_enumerator_parent_class)->constructed != NULL)
    G_OBJECT_CLASS (g_udev_enumerator_parent_class)->constructed (object);
}

static void
g_udev_enumerator_class_init (GUdevEnumeratorClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;

  gobject_class->finalize     = g_udev_enumerator_finalize;
  gobject_class->set_property = g_udev_enumerator_set_property;
  gobject_class->get_property = g_udev_enumerator_get_property;
  gobject_class->constructed  = g_udev_enumerator_constructed;

  /**
   * GUdevEnumerator:client:
   *
   * The #GUdevClient to enumerate devices from.
   *
   * Since: 165
   */
  g_object_class_install_property (gobject_class,
                                   PROP_CLIENT,
                                   g_param_spec_object ("client",
                                                        "The client to enumerate devices from",
                                                        "The client to enumerate devices from",
                                                        G_UDEV_TYPE_CLIENT,
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_READWRITE));

  g_type_class_add_private (klass, sizeof (GUdevEnumeratorPrivate));
}

static void
g_udev_enumerator_init (GUdevEnumerator *enumerator)
{
  enumerator->priv = G_TYPE_INSTANCE_GET_PRIVATE (enumerator,
                                                  G_UDEV_TYPE_ENUMERATOR,
                                                  GUdevEnumeratorPrivate);
}

/**
 * g_udev_enumerator_new:
 * @client: A #GUdevClient to enumerate devices from.
 *
 * Constructs a #GUdevEnumerator object that can be used to enumerate
 * and sort devices. Use the add_match_*() and add_nomatch_*() methods
 * and execute the query to get a list of devices with
 * g_udev_enumerator_execute().
 *
 * Returns: A new #GUdevEnumerator object. Free with g_object_unref().
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_new (GUdevClient *client)
{
  g_return_val_if_fail (G_UDEV_IS_CLIENT (client), NULL);
  return G_UDEV_ENUMERATOR (g_object_new (G_UDEV_TYPE_ENUMERATOR, "client", client, NULL));
}


/**
 * g_udev_enumerator_add_match_subsystem:
 * @enumerator: A #GUdevEnumerator.
 * @subsystem: Wildcard for subsystem name e.g. 'scsi' or 'a*'.
 *
 * All returned devices will match the given @subsystem.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_match_subsystem (GUdevEnumerator  *enumerator,
                                       const gchar      *subsystem)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (subsystem != NULL, NULL);
  udev_enumerate_add_match_subsystem (enumerator->priv->e, subsystem);
  return enumerator;
}

/**
 * g_udev_enumerator_add_nomatch_subsystem:
 * @enumerator: A #GUdevEnumerator.
 * @subsystem: Wildcard for subsystem name e.g. 'scsi' or 'a*'.
 *
 * All returned devices will not match the given @subsystem.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_nomatch_subsystem (GUdevEnumerator  *enumerator,
                                         const gchar      *subsystem)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (subsystem != NULL, NULL);
  udev_enumerate_add_nomatch_subsystem (enumerator->priv->e, subsystem);
  return enumerator;
}

/**
 * g_udev_enumerator_add_match_sysfs_attr:
 * @enumerator: A #GUdevEnumerator.
 * @name: Wildcard filter for sysfs attribute key.
 * @value: Wildcard filter for sysfs attribute value.
 *
 * All returned devices will have a sysfs attribute matching the given @name and @value.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_match_sysfs_attr (GUdevEnumerator  *enumerator,
                                        const gchar      *name,
                                        const gchar      *value)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (value != NULL, NULL);
  udev_enumerate_add_match_sysattr (enumerator->priv->e, name, value);
  return enumerator;
}

/**
 * g_udev_enumerator_add_nomatch_sysfs_attr:
 * @enumerator: A #GUdevEnumerator.
 * @name: Wildcard filter for sysfs attribute key.
 * @value: Wildcard filter for sysfs attribute value.
 *
 * All returned devices will not have a sysfs attribute matching the given @name and @value.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_nomatch_sysfs_attr (GUdevEnumerator  *enumerator,
                                          const gchar      *name,
                                          const gchar      *value)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (value != NULL, NULL);
  udev_enumerate_add_nomatch_sysattr (enumerator->priv->e, name, value);
  return enumerator;
}

/**
 * g_udev_enumerator_add_match_property:
 * @enumerator: A #GUdevEnumerator.
 * @name: Wildcard filter for property name.
 * @value: Wildcard filter for property value.
 *
 * All returned devices will have a property matching the given @name and @value.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_match_property (GUdevEnumerator  *enumerator,
                                      const gchar      *name,
                                      const gchar      *value)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (value != NULL, NULL);
  udev_enumerate_add_match_property (enumerator->priv->e, name, value);
  return enumerator;
}

/**
 * g_udev_enumerator_add_match_name:
 * @enumerator: A #GUdevEnumerator.
 * @name: Wildcard filter for kernel name e.g. "sda*".
 *
 * All returned devices will match the given @name.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_match_name (GUdevEnumerator  *enumerator,
                                  const gchar      *name)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  udev_enumerate_add_match_sysname (enumerator->priv->e, name);
  return enumerator;
}

/**
 * g_udev_enumerator_add_sysfs_path:
 * @enumerator: A #GUdevEnumerator.
 * @sysfs_path: A sysfs path, e.g. "/sys/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda"
 *
 * Add a device to the list of devices, to retrieve it back sorted in dependency order.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_sysfs_path (GUdevEnumerator  *enumerator,
                                  const gchar      *sysfs_path)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (sysfs_path != NULL, NULL);
  udev_enumerate_add_syspath (enumerator->priv->e, sysfs_path);
  return enumerator;
}

/**
 * g_udev_enumerator_add_match_tag:
 * @enumerator: A #GUdevEnumerator.
 * @tag: A udev tag e.g. "udev-acl".
 *
 * All returned devices will match the given @tag.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_match_tag (GUdevEnumerator  *enumerator,
                                 const gchar      *tag)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  g_return_val_if_fail (tag != NULL, NULL);
  udev_enumerate_add_match_tag (enumerator->priv->e, tag);
  return enumerator;
}

/**
 * g_udev_enumerator_add_match_is_initialized:
 * @enumerator: A #GUdevEnumerator.
 *
 * All returned devices will be initialized.
 *
 * Returns: (transfer none): The passed in @enumerator.
 *
 * Since: 165
 */
GUdevEnumerator *
g_udev_enumerator_add_match_is_initialized (GUdevEnumerator  *enumerator)
{
  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);
  udev_enumerate_add_match_is_initialized (enumerator->priv->e);
  return enumerator;
}

/**
 * g_udev_enumerator_execute:
 * @enumerator: A #GUdevEnumerator.
 *
 * Executes the query in @enumerator.
 *
 * Returns: (element-type GUdevDevice) (transfer full): A list of #GUdevDevice objects. The caller should free the result by using g_object_unref() on each element in the list and then g_list_free() on the list.
 *
 * Since: 165
 */
GList *
g_udev_enumerator_execute (GUdevEnumerator  *enumerator)
{
  GList *ret;
  struct udev_list_entry *l, *devices;

  g_return_val_if_fail (G_UDEV_IS_ENUMERATOR (enumerator), NULL);

  ret = NULL;

  /* retrieve the list */
  udev_enumerate_scan_devices (enumerator->priv->e);

  devices = udev_enumerate_get_list_entry (enumerator->priv->e);
  for (l = devices; l != NULL; l = udev_list_entry_get_next (l))
    {
      struct udev_device *udevice;
      GUdevDevice *device;

      udevice = udev_device_new_from_syspath (udev_enumerate_get_udev (enumerator->priv->e),
                                              udev_list_entry_get_name (l));
      if (udevice == NULL)
        continue;

      device = _g_udev_device_new (udevice);
      udev_device_unref (udevice);
      ret = g_list_prepend (ret, device);
    }

  ret = g_list_reverse (ret);

  return ret;
}
