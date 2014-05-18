/* -*- Mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2008 David Zeuthen <davidz@redhat.com>
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

#include "gudevdevice.h"
#include "gudevprivate.h"

/**
 * SECTION:gudevdevice
 * @short_description: Get information about a device
 *
 * The #GUdevDevice class is used to get information about a specific
 * device. Note that you cannot instantiate a #GUdevDevice object
 * yourself. Instead you must use #GUdevClient to obtain #GUdevDevice
 * objects.
 *
 * To get basic information about a device, use
 * g_udev_device_get_subsystem(), g_udev_device_get_devtype(),
 * g_udev_device_get_name(), g_udev_device_get_number(),
 * g_udev_device_get_sysfs_path(), g_udev_device_get_driver(),
 * g_udev_device_get_action(), g_udev_device_get_seqnum(),
 * g_udev_device_get_device_type(), g_udev_device_get_device_number(),
 * g_udev_device_get_device_file(),
 * g_udev_device_get_device_file_symlinks().
 *
 * To navigate the device tree, use g_udev_device_get_parent() and
 * g_udev_device_get_parent_with_subsystem().
 *
 * To access udev properties for the device, use
 * g_udev_device_get_property_keys(),
 * g_udev_device_has_property(),
 * g_udev_device_get_property(),
 * g_udev_device_get_property_as_int(),
 * g_udev_device_get_property_as_uint64(),
 * g_udev_device_get_property_as_double(),
 * g_udev_device_get_property_as_boolean() and
 * g_udev_device_get_property_as_strv().
 *
 * To access sysfs attributes for the device, use
 * g_udev_device_get_sysfs_attr_keys(),
 * g_udev_device_has_sysfs_attr(),
 * g_udev_device_get_sysfs_attr(),
 * g_udev_device_get_sysfs_attr_as_int(),
 * g_udev_device_get_sysfs_attr_as_uint64(),
 * g_udev_device_get_sysfs_attr_as_double(),
 * g_udev_device_get_sysfs_attr_as_boolean() and
 * g_udev_device_get_sysfs_attr_as_strv().
 *
 * Note that all getters on #GUdevDevice are non-reffing – returned
 * values are owned by the object, should not be freed and are only
 * valid as long as the object is alive.
 *
 * By design, #GUdevDevice will not react to changes for a device – it
 * only contains a snapshot of information when the #GUdevDevice
 * object was created. To work with changes, you typically connect to
 * the #GUdevClient::uevent signal on a #GUdevClient and get a new
 * #GUdevDevice whenever an event happens.
 */

struct _GUdevDevicePrivate
{
  struct udev_device *udevice;

  /* computed ondemand and cached */
  gchar **device_file_symlinks;
  gchar **property_keys;
  gchar **sysfs_attr_keys;
  gchar **tags;
  GHashTable *prop_strvs;
  GHashTable *sysfs_attr_strvs;
};

G_DEFINE_TYPE (GUdevDevice, g_udev_device, G_TYPE_OBJECT)

static void
g_udev_device_finalize (GObject *object)
{
  GUdevDevice *device = G_UDEV_DEVICE (object);

  g_strfreev (device->priv->device_file_symlinks);
  g_strfreev (device->priv->property_keys);
  g_strfreev (device->priv->sysfs_attr_keys);
  g_strfreev (device->priv->tags);

  if (device->priv->udevice != NULL)
    udev_device_unref (device->priv->udevice);

  if (device->priv->prop_strvs != NULL)
    g_hash_table_unref (device->priv->prop_strvs);

  if (device->priv->sysfs_attr_strvs != NULL)
    g_hash_table_unref (device->priv->sysfs_attr_strvs);

  if (G_OBJECT_CLASS (g_udev_device_parent_class)->finalize != NULL)
    (* G_OBJECT_CLASS (g_udev_device_parent_class)->finalize) (object);
}

static void
g_udev_device_class_init (GUdevDeviceClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;

  gobject_class->finalize = g_udev_device_finalize;

  g_type_class_add_private (klass, sizeof (GUdevDevicePrivate));
}

static void
g_udev_device_init (GUdevDevice *device)
{
  device->priv = G_TYPE_INSTANCE_GET_PRIVATE (device,
                                              G_UDEV_TYPE_DEVICE,
                                              GUdevDevicePrivate);
}


GUdevDevice *
_g_udev_device_new (struct udev_device *udevice)
{
  GUdevDevice *device;

  device =  G_UDEV_DEVICE (g_object_new (G_UDEV_TYPE_DEVICE, NULL));
  device->priv->udevice = udev_device_ref (udevice);

  return device;
}

/**
 * g_udev_device_get_subsystem:
 * @device: A #GUdevDevice.
 *
 * Gets the subsystem for @device.
 *
 * Returns: The subsystem for @device.
 */
const gchar *
g_udev_device_get_subsystem (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_subsystem (device->priv->udevice);
}

/**
 * g_udev_device_get_devtype:
 * @device: A #GUdevDevice.
 *
 * Gets the device type for @device.
 *
 * Returns: The devtype for @device.
 */
const gchar *
g_udev_device_get_devtype (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_devtype (device->priv->udevice);
}

/**
 * g_udev_device_get_name:
 * @device: A #GUdevDevice.
 *
 * Gets the name of @device, e.g. "sda3".
 *
 * Returns: The name of @device.
 */
const gchar *
g_udev_device_get_name (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_sysname (device->priv->udevice);
}

/**
 * g_udev_device_get_number:
 * @device: A #GUdevDevice.
 *
 * Gets the number of @device, e.g. "3" if g_udev_device_get_name() returns "sda3".
 *
 * Returns: The number of @device.
 */
const gchar *
g_udev_device_get_number (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_sysnum (device->priv->udevice);
}

/**
 * g_udev_device_get_sysfs_path:
 * @device: A #GUdevDevice.
 *
 * Gets the sysfs path for @device.
 *
 * Returns: The sysfs path for @device.
 */
const gchar *
g_udev_device_get_sysfs_path (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_syspath (device->priv->udevice);
}

/**
 * g_udev_device_get_driver:
 * @device: A #GUdevDevice.
 *
 * Gets the name of the driver used for @device.
 *
 * Returns: (nullable): The name of the driver for @device or %NULL if
 * unknown.
 */
const gchar *
g_udev_device_get_driver (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_driver (device->priv->udevice);
}

/**
 * g_udev_device_get_action:
 * @device: A #GUdevDevice.
 *
 * Gets the most recent action (e.g. "add", "remove", "change", etc.) for @device.
 *
 * Returns: An action string.
 */
const gchar *
g_udev_device_get_action (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_action (device->priv->udevice);
}

/**
 * g_udev_device_get_seqnum:
 * @device: A #GUdevDevice.
 *
 * Gets the most recent sequence number for @device.
 *
 * Returns: A sequence number.
 */
guint64
g_udev_device_get_seqnum (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0);
  return udev_device_get_seqnum (device->priv->udevice);
}

/**
 * g_udev_device_get_device_type:
 * @device: A #GUdevDevice.
 *
 * Gets the type of the device file, if any, for @device.
 *
 * Returns: The device number for @device or #G_UDEV_DEVICE_TYPE_NONE if the device does not have a device file.
 */
GUdevDeviceType
g_udev_device_get_device_type (GUdevDevice *device)
{
  struct stat stat_buf;
  const gchar *device_file;
  GUdevDeviceType type;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), G_UDEV_DEVICE_TYPE_NONE);

  type = G_UDEV_DEVICE_TYPE_NONE;

  /* TODO: would be better to have support for this in libudev... */

  device_file = g_udev_device_get_device_file (device);
  if (device_file == NULL)
    goto out;

  if (stat (device_file, &stat_buf) != 0)
    goto out;

  if (S_ISBLK (stat_buf.st_mode))
    type = G_UDEV_DEVICE_TYPE_BLOCK;
  else if (S_ISCHR (stat_buf.st_mode))
    type = G_UDEV_DEVICE_TYPE_CHAR;

 out:
  return type;
}

/**
 * g_udev_device_get_device_number:
 * @device: A #GUdevDevice.
 *
 * Gets the device number, if any, for @device.
 *
 * Returns: The device number for @device or 0 if unknown.
 */
GUdevDeviceNumber
g_udev_device_get_device_number (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0);
  return udev_device_get_devnum (device->priv->udevice);
}

/**
 * g_udev_device_get_device_file:
 * @device: A #GUdevDevice.
 *
 * Gets the device file for @device.
 *
 * Returns: (nullable): The device file for @device or %NULL if no
 * device file exists.
 */
const gchar *
g_udev_device_get_device_file (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  return udev_device_get_devnode (device->priv->udevice);
}

/**
 * g_udev_device_get_device_file_symlinks:
 * @device: A #GUdevDevice.
 *
 * Gets a list of symlinks (in <literal>/dev</literal>) that points to
 * the device file for @device.
 *
 * Returns: (transfer none) (array zero-terminated=1) (element-type utf8): A %NULL terminated string array of symlinks. This array is owned by @device and should not be freed by the caller.
 */
const gchar * const *
g_udev_device_get_device_file_symlinks (GUdevDevice *device)
{
  struct udev_list_entry *l;
  GPtrArray *p;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);

  if (device->priv->device_file_symlinks != NULL)
    goto out;

  p = g_ptr_array_new ();
  for (l = udev_device_get_devlinks_list_entry (device->priv->udevice); l != NULL; l = udev_list_entry_get_next (l))
    {
      g_ptr_array_add (p, g_strdup (udev_list_entry_get_name (l)));
    }
  g_ptr_array_add (p, NULL);
  device->priv->device_file_symlinks = (gchar **) g_ptr_array_free (p, FALSE);

 out:
  return (const gchar * const *) device->priv->device_file_symlinks;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * g_udev_device_get_parent:
 * @device: A #GUdevDevice.
 *
 * Gets the immediate parent of @device, if any.
 *
 * Returns: (nullable) (transfer full): A #GUdevDevice or %NULL if
 * @device has no parent. Free with g_object_unref().
 */
GUdevDevice *
g_udev_device_get_parent (GUdevDevice  *device)
{
  GUdevDevice *ret;
  struct udev_device *udevice;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);

  ret = NULL;

  udevice = udev_device_get_parent (device->priv->udevice);
  if (udevice == NULL)
    goto out;

  ret = _g_udev_device_new (udevice);

 out:
  return ret;
}

/**
 * g_udev_device_get_parent_with_subsystem:
 * @device: A #GUdevDevice.
 * @subsystem: The subsystem of the parent to get.
 * @devtype: (allow-none): The devtype of the parent to get or %NULL.
 *
 * Walks up the chain of parents of @device and returns the first
 * device encountered where @subsystem and @devtype matches, if any.
 *
 * Returns: (nullable) (transfer full): A #GUdevDevice or %NULL if
 * @device has no parent with @subsystem and @devtype. Free with
 * g_object_unref().
 */
GUdevDevice *
g_udev_device_get_parent_with_subsystem (GUdevDevice  *device,
                                         const gchar  *subsystem,
                                         const gchar  *devtype)
{
  GUdevDevice *ret;
  struct udev_device *udevice;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  g_return_val_if_fail (subsystem != NULL, NULL);

  ret = NULL;

  udevice = udev_device_get_parent_with_subsystem_devtype (device->priv->udevice,
                                                           subsystem,
                                                           devtype);
  if (udevice == NULL)
    goto out;

  ret = _g_udev_device_new (udevice);

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * g_udev_device_get_property_keys:
 * @device: A #GUdevDevice.
 *
 * Gets all keys for properties on @device.
 *
 * Returns: (transfer none) (array zero-terminated=1) (element-type utf8): A %NULL terminated string array of property keys. This array is owned by @device and should not be freed by the caller.
 */
const gchar* const *
g_udev_device_get_property_keys (GUdevDevice *device)
{
  struct udev_list_entry *l;
  GPtrArray *p;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);

  if (device->priv->property_keys != NULL)
    goto out;

  p = g_ptr_array_new ();
  for (l = udev_device_get_properties_list_entry (device->priv->udevice); l != NULL; l = udev_list_entry_get_next (l))
    {
      g_ptr_array_add (p, g_strdup (udev_list_entry_get_name (l)));
    }
  g_ptr_array_add (p, NULL);
  device->priv->property_keys = (gchar **) g_ptr_array_free (p, FALSE);

 out:
  return (const gchar * const *) device->priv->property_keys;
}


/**
 * g_udev_device_has_property:
 * @device: A #GUdevDevice.
 * @key: Name of property.
 *
 * Check if a the property with the given key exists.
 *
 * Returns: %TRUE only if the value for @key exist.
 */
gboolean
g_udev_device_has_property (GUdevDevice  *device,
                            const gchar  *key)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), FALSE);
  g_return_val_if_fail (key != NULL, FALSE);
  return udev_device_get_property_value (device->priv->udevice, key) != NULL;
}

/**
 * g_udev_device_get_property:
 * @device: A #GUdevDevice.
 * @key: Name of property.
 *
 * Look up the value for @key on @device.
 *
 * Returns: (nullable): The value for @key or %NULL if @key doesn't
 * exist on @device. Do not free this string, it is owned by @device.
 */
const gchar *
g_udev_device_get_property (GUdevDevice  *device,
                            const gchar  *key)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  g_return_val_if_fail (key != NULL, NULL);
  return udev_device_get_property_value (device->priv->udevice, key);
}

/**
 * g_udev_device_get_property_as_int:
 * @device: A #GUdevDevice.
 * @key: Name of property.
 *
 * Look up the value for @key on @device and convert it to an integer
 * using strtol().
 *
 * Returns: The value for @key or 0 if @key doesn't exist or
 * isn't an integer.
 */
gint
g_udev_device_get_property_as_int (GUdevDevice  *device,
                                   const gchar  *key)
{
  gint result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0);
  g_return_val_if_fail (key != NULL, 0);

  result = 0;
  s = g_udev_device_get_property (device, key);
  if (s == NULL)
    goto out;

  result = strtol (s, NULL, 0);
out:
  return result;
}

/**
 * g_udev_device_get_property_as_uint64:
 * @device: A #GUdevDevice.
 * @key: Name of property.
 *
 * Look up the value for @key on @device and convert it to an unsigned
 * 64-bit integer using g_ascii_strtoull().
 *
 * Returns: The value  for @key or 0 if @key doesn't  exist or isn't a
 * #guint64.
 */
guint64
g_udev_device_get_property_as_uint64 (GUdevDevice  *device,
                                      const gchar  *key)
{
  guint64 result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0);
  g_return_val_if_fail (key != NULL, 0);

  result = 0;
  s = g_udev_device_get_property (device, key);
  if (s == NULL)
    goto out;

  result = g_ascii_strtoull (s, NULL, 0);
out:
  return result;
}

/**
 * g_udev_device_get_property_as_double:
 * @device: A #GUdevDevice.
 * @key: Name of property.
 *
 * Look up the value for @key on @device and convert it to a double
 * precision floating point number using strtod().
 *
 * Returns: The value for @key or 0.0 if @key doesn't exist or isn't a
 * #gdouble.
 */
gdouble
g_udev_device_get_property_as_double (GUdevDevice  *device,
                                      const gchar  *key)
{
  gdouble result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0.0);
  g_return_val_if_fail (key != NULL, 0.0);

  result = 0.0;
  s = g_udev_device_get_property (device, key);
  if (s == NULL)
    goto out;

  result = strtod (s, NULL);
out:
  return result;
}

/**
 * g_udev_device_get_property_as_boolean:
 * @device: A #GUdevDevice.
 * @key: Name of property.
 *
 * Look up the value for @key on @device and convert it to an
 * boolean. This is done by doing a case-insensitive string comparison
 * on the string value against "1" and "true".
 *
 * Returns: The value for @key or %FALSE if @key doesn't exist or
 * isn't a #gboolean.
 */
gboolean
g_udev_device_get_property_as_boolean (GUdevDevice  *device,
                                       const gchar  *key)
{
  gboolean result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), FALSE);
  g_return_val_if_fail (key != NULL, FALSE);

  result = FALSE;
  s = g_udev_device_get_property (device, key);
  if (s == NULL)
    goto out;

  if (strcmp (s, "1") == 0 || g_ascii_strcasecmp (s, "true") == 0)
    result = TRUE;
 out:
  return result;
}

static gchar **
split_at_whitespace (const gchar *s)
{
  gchar **result;
  guint n;
  guint m;

  result = g_strsplit_set (s, " \v\t\r\n", 0);

  /* remove empty strings, thanks GLib */
  for (n = 0; result[n] != NULL; n++)
    {
      if (strlen (result[n]) == 0)
        {
          g_free (result[n]);
          for (m = n; result[m] != NULL; m++)
            result[m] = result[m + 1];
          n--;
        }
    }

  return result;
}

/**
 * g_udev_device_get_property_as_strv:
 * @device: A #GUdevDevice.
 * @key: Name of property.
 *
 * Look up the value for @key on @device and return the result of
 * splitting it into non-empty tokens split at white space (only space
 * (' '), form-feed ('\f'), newline ('\n'), carriage return ('\r'),
 * horizontal tab ('\t'), and vertical tab ('\v') are considered; the
 * locale is not taken into account).
 *
 * Returns: (nullable) (transfer none) (array zero-terminated=1) (element-type utf8):
 * The value of @key on @device split into tokens or %NULL if @key
 * doesn't exist. This array is owned by @device and should not be
 * freed by the caller.
 */
const gchar* const *
g_udev_device_get_property_as_strv (GUdevDevice  *device,
                                    const gchar  *key)
{
  gchar **result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  g_return_val_if_fail (key != NULL, NULL);

  if (device->priv->prop_strvs != NULL)
    {
      result = g_hash_table_lookup (device->priv->prop_strvs, key);
      if (result != NULL)
        goto out;
    }

  result = NULL;
  s = g_udev_device_get_property (device, key);
  if (s == NULL)
    goto out;

  result = split_at_whitespace (s);
  if (result == NULL)
    goto out;

  if (device->priv->prop_strvs == NULL)
    device->priv->prop_strvs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_strfreev);
  g_hash_table_insert (device->priv->prop_strvs, g_strdup (key), result);

out:
  return (const gchar* const *) result;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * g_udev_device_get_sysfs_attr_keys:
 * @device: A #GUdevDevice.
 *
 * Gets all keys for sysfs attributes on @device.
 *
 * Returns: (transfer none) (array zero-terminated=1) (element-type utf8): A %NULL terminated string array of sysfs attribute keys. This array is owned by @device and should not be freed by the caller.
 */
const gchar * const *
g_udev_device_get_sysfs_attr_keys (GUdevDevice *device)
{
  struct udev_list_entry *l;
  GPtrArray *p;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);

  if (device->priv->sysfs_attr_keys != NULL)
    goto out;

  p = g_ptr_array_new ();
  for (l = udev_device_get_sysattr_list_entry (device->priv->udevice); l != NULL; l = udev_list_entry_get_next (l))
    {
      g_ptr_array_add (p, g_strdup (udev_list_entry_get_name (l)));
    }
  g_ptr_array_add (p, NULL);
  device->priv->sysfs_attr_keys = (gchar **) g_ptr_array_free (p, FALSE);

 out:
  return (const gchar * const *) device->priv->sysfs_attr_keys;
}

/**
 * g_udev_device_has_sysfs_attr:
 * @device: A #GUdevDevice.
 * @key: Name of sysfs attribute.
 *
 * Check if a the sysfs attribute with the given key exists.
 *
 * Returns: %TRUE only if the value for @key exist.
 */
gboolean
g_udev_device_has_sysfs_attr (GUdevDevice  *device,
                            const gchar  *key)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), FALSE);
  g_return_val_if_fail (key != NULL, FALSE);
  return udev_device_get_sysattr_value (device->priv->udevice, key) != NULL;
}

/**
 * g_udev_device_get_sysfs_attr:
 * @device: A #GUdevDevice.
 * @name: Name of the sysfs attribute.
 *
 * Look up the sysfs attribute with @name on @device.
 *
 * Returns: (nullable): The value of the sysfs attribute or %NULL if
 * there is no such attribute. Do not free this string, it is owned by
 * @device.
 */
const gchar *
g_udev_device_get_sysfs_attr (GUdevDevice  *device,
                              const gchar  *name)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  return udev_device_get_sysattr_value (device->priv->udevice, name);
}

/**
 * g_udev_device_get_sysfs_attr_as_int:
 * @device: A #GUdevDevice.
 * @name: Name of the sysfs attribute.
 *
 * Look up the sysfs attribute with @name on @device and convert it to an integer
 * using strtol().
 *
 * Returns: The value of the sysfs attribute or 0 if there is no such
 * attribute.
 */
gint
g_udev_device_get_sysfs_attr_as_int (GUdevDevice  *device,
                                     const gchar  *name)
{
  gint result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0);
  g_return_val_if_fail (name != NULL, 0);

  result = 0;
  s = g_udev_device_get_sysfs_attr (device, name);
  if (s == NULL)
    goto out;

  result = strtol (s, NULL, 0);
out:
  return result;
}

/**
 * g_udev_device_get_sysfs_attr_as_uint64:
 * @device: A #GUdevDevice.
 * @name: Name of the sysfs attribute.
 *
 * Look up the sysfs attribute with @name on @device and convert it to an unsigned
 * 64-bit integer using g_ascii_strtoull().
 *
 * Returns: The value of the sysfs attribute or 0 if there is no such
 * attribute.
 */
guint64
g_udev_device_get_sysfs_attr_as_uint64 (GUdevDevice  *device,
                                        const gchar  *name)
{
  guint64 result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0);
  g_return_val_if_fail (name != NULL, 0);

  result = 0;
  s = g_udev_device_get_sysfs_attr (device, name);
  if (s == NULL)
    goto out;

  result = g_ascii_strtoull (s, NULL, 0);
out:
  return result;
}

/**
 * g_udev_device_get_sysfs_attr_as_double:
 * @device: A #GUdevDevice.
 * @name: Name of the sysfs attribute.
 *
 * Look up the sysfs attribute with @name on @device and convert it to a double
 * precision floating point number using strtod().
 *
 * Returns: The value of the sysfs attribute or 0.0 if there is no such
 * attribute.
 */
gdouble
g_udev_device_get_sysfs_attr_as_double (GUdevDevice  *device,
                                        const gchar  *name)
{
  gdouble result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0.0);
  g_return_val_if_fail (name != NULL, 0.0);

  result = 0.0;
  s = g_udev_device_get_sysfs_attr (device, name);
  if (s == NULL)
    goto out;

  result = strtod (s, NULL);
out:
  return result;
}

/**
 * g_udev_device_get_sysfs_attr_as_boolean:
 * @device: A #GUdevDevice.
 * @name: Name of the sysfs attribute.
 *
 * Look up the sysfs attribute with @name on @device and convert it to an
 * boolean. This is done by doing a case-insensitive string comparison
 * on the string value against "1" and "true".
 *
 * Returns: The value of the sysfs attribute or %FALSE if there is no such
 * attribute.
 */
gboolean
g_udev_device_get_sysfs_attr_as_boolean (GUdevDevice  *device,
                                         const gchar  *name)
{
  gboolean result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), FALSE);
  g_return_val_if_fail (name != NULL, FALSE);

  result = FALSE;
  s = g_udev_device_get_sysfs_attr (device, name);
  if (s == NULL)
    goto out;

  if (strcmp (s, "1") == 0 || g_ascii_strcasecmp (s, "true") == 0)
    result = TRUE;
 out:
  return result;
}

/**
 * g_udev_device_get_sysfs_attr_as_strv:
 * @device: A #GUdevDevice.
 * @name: Name of the sysfs attribute.
 *
 * Look up the sysfs attribute with @name on @device and return the result of
 * splitting it into non-empty tokens split at white space (only space (' '),
 * form-feed ('\f'), newline ('\n'), carriage return ('\r'), horizontal
 * tab ('\t'), and vertical tab ('\v') are considered; the locale is
 * not taken into account).
 *
 * Returns: (nullable) (transfer none) (array zero-terminated=1) (element-type utf8):
 * The value of the sysfs attribute split into tokens or %NULL if
 * there is no such attribute. This array is owned by @device and
 * should not be freed by the caller.
 */
const gchar * const *
g_udev_device_get_sysfs_attr_as_strv (GUdevDevice  *device,
                                      const gchar  *name)
{
  gchar **result;
  const gchar *s;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);
  g_return_val_if_fail (name != NULL, NULL);

  if (device->priv->sysfs_attr_strvs != NULL)
    {
      result = g_hash_table_lookup (device->priv->sysfs_attr_strvs, name);
      if (result != NULL)
        goto out;
    }

  result = NULL;
  s = g_udev_device_get_sysfs_attr (device, name);
  if (s == NULL)
    goto out;

  result = split_at_whitespace (s);
  if (result == NULL)
    goto out;

  if (device->priv->sysfs_attr_strvs == NULL)
    device->priv->sysfs_attr_strvs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_strfreev);
  g_hash_table_insert (device->priv->sysfs_attr_strvs, g_strdup (name), result);

out:
  return (const gchar* const *) result;
}

/**
 * g_udev_device_get_tags:
 * @device: A #GUdevDevice.
 *
 * Gets all tags for @device.
 *
 * Returns: (transfer none) (array zero-terminated=1) (element-type utf8): A %NULL terminated string array of tags. This array is owned by @device and should not be freed by the caller.
 *
 * Since: 165
 */
const gchar* const *
g_udev_device_get_tags (GUdevDevice  *device)
{
  struct udev_list_entry *l;
  GPtrArray *p;

  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), NULL);

  if (device->priv->tags != NULL)
    goto out;

  p = g_ptr_array_new ();
  for (l = udev_device_get_tags_list_entry (device->priv->udevice); l != NULL; l = udev_list_entry_get_next (l))
    {
      g_ptr_array_add (p, g_strdup (udev_list_entry_get_name (l)));
    }
  g_ptr_array_add (p, NULL);
  device->priv->tags = (gchar **) g_ptr_array_free (p, FALSE);

 out:
  return (const gchar * const *) device->priv->tags;
}

/**
 * g_udev_device_get_is_initialized:
 * @device: A #GUdevDevice.
 *
 * Gets whether @device has been initalized.
 *
 * Returns: Whether @device has been initialized.
 *
 * Since: 165
 */
gboolean
g_udev_device_get_is_initialized (GUdevDevice  *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), FALSE);
  return udev_device_get_is_initialized (device->priv->udevice);
}

/**
 * g_udev_device_get_usec_since_initialized:
 * @device: A #GUdevDevice.
 *
 * Gets number of micro-seconds since @device was initialized.
 *
 * This only works for devices with properties in the udev
 * database. All other devices return 0.
 *
 * Returns: Number of micro-seconds since @device was initialized or 0 if unknown.
 *
 * Since: 165
 */
guint64
g_udev_device_get_usec_since_initialized (GUdevDevice *device)
{
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), 0);
  return udev_device_get_usec_since_initialized (device->priv->udevice);
}
