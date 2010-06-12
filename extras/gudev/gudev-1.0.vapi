/* gudev-1.0.vapi
 *
 * (C) 2010 Martin Pitt <martin.pitt@ubuntu.com>
 * Based on vapigen output, with fixes to array/list semantics and
 * include file names.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

[CCode (cprefix = "GUdev", lower_case_cprefix = "g_udev_")]
namespace GUdev {
	[CCode (cheader_filename = "gudev/gudev.h")]
	public class Client : GLib.Object {
		public weak GLib.Object parent;
		public GUdev.ClientPrivate priv;
		[CCode (has_construct_function = false)]
		public Client ([CCode (array_length = false, array_null_terminated = true)] string[]? subsystems);
		[CCode (cname = "g_udev_client_query_by_device_file")]
		public GUdev.Device query_by_device_file (string device_file);
		[CCode (cname = "g_udev_client_query_by_device_number")]
		public GUdev.Device query_by_device_number (GUdev.DeviceType type, GUdev.DeviceNumber number);
		[CCode (cname = "g_udev_client_query_by_subsystem")]
		public GLib.List<Device> query_by_subsystem (string? subsystem);
		[CCode (cname = "g_udev_client_query_by_subsystem_and_name")]
		public GUdev.Device query_by_subsystem_and_name (string subsystem, string name);
		[CCode (cname = "g_udev_client_query_by_sysfs_path")]
		public GUdev.Device query_by_sysfs_path (string sysfs_path);
		public signal void uevent (string action, GUdev.Device device);
	}
	[CCode (cheader_filename = "gudev/gudev.h")]
	public class Device : GLib.Object {
		public weak GLib.Object parent;
		public GUdev.DevicePrivate priv;
		[CCode (cname = "g_udev_device_get_action")]
		public unowned string get_action ();
		[CCode (cname = "g_udev_device_get_device_file")]
		public unowned string get_device_file ();
		[CCode (cname = "g_udev_device_get_device_file_symlinks", array_length = false, array_null_terminated = true)]
		public unowned  string[] get_device_file_symlinks ();
		[CCode (cname = "g_udev_device_get_device_number")]
		public GUdev.DeviceNumber get_device_number ();
		[CCode (cname = "g_udev_device_get_device_type")]
		public GUdev.DeviceType get_device_type ();
		[CCode (cname = "g_udev_device_get_devtype")]
		public unowned string get_devtype ();
		[CCode (cname = "g_udev_device_get_driver")]
		public unowned string get_driver ();
		[CCode (cname = "g_udev_device_get_name")]
		public unowned string get_name ();
		[CCode (cname = "g_udev_device_get_number")]
		public unowned string get_number ();
		[CCode (cname = "g_udev_device_get_parent")]
		public GUdev.Device get_parent ();
		[CCode (cname = "g_udev_device_get_parent_with_subsystem")]
		public GUdev.Device get_parent_with_subsystem (string subsystem, string? devtype);
		[CCode (cname = "g_udev_device_get_property")]
		public unowned string get_property (string key);
		[CCode (cname = "g_udev_device_get_property_as_boolean")]
		public bool get_property_as_boolean (string key);
		[CCode (cname = "g_udev_device_get_property_as_double")]
		public double get_property_as_double (string key);
		[CCode (cname = "g_udev_device_get_property_as_int")]
		public int get_property_as_int (string key);
		[CCode (cname = "g_udev_device_get_property_as_strv", array_length = false, array_null_terminated = true)]
		public unowned string[] get_property_as_strv (string key);
		[CCode (cname = "g_udev_device_get_property_as_uint64")]
		public uint64 get_property_as_uint64 (string key);
		[CCode (cname = "g_udev_device_get_property_keys", array_length = false, array_null_terminated = true)]
		public unowned string[] get_property_keys ();
		[CCode (cname = "g_udev_device_get_seqnum")]
		public uint64 get_seqnum ();
		[CCode (cname = "g_udev_device_get_subsystem")]
		public unowned string get_subsystem ();
		[CCode (cname = "g_udev_device_get_sysfs_attr")]
		public unowned string get_sysfs_attr (string name);
		[CCode (cname = "g_udev_device_get_sysfs_attr_as_boolean")]
		public bool get_sysfs_attr_as_boolean (string name);
		[CCode (cname = "g_udev_device_get_sysfs_attr_as_double")]
		public double get_sysfs_attr_as_double (string name);
		[CCode (cname = "g_udev_device_get_sysfs_attr_as_int")]
		public int get_sysfs_attr_as_int (string name);
		[CCode (cname = "g_udev_device_get_sysfs_attr_as_strv", array_length = false, array_null_terminated = true)]
		public unowned string[] get_sysfs_attr_as_strv (string name);
		[CCode (cname = "g_udev_device_get_sysfs_attr_as_uint64")]
		public uint64 get_sysfs_attr_as_uint64 (string name);
		[CCode (cname = "g_udev_device_get_sysfs_path")]
		public unowned string get_sysfs_path ();
		[CCode (cname = "g_udev_device_has_property")]
		public bool has_property (string key);
	}
	[CCode (type_id = "GUDEV_TYPE_CLIENT_PRIVATE", cheader_filename = "gudev/gudev.h")]
	public struct ClientPrivate {
	}
	[CCode (cheader_filename = "gudev/gudev.h")]
	[SimpleType]
	[IntegerType (rank = 0)]
	public struct DeviceNumber : uint64 {
	}
	[CCode (type_id = "GUDEV_TYPE_DEVICE_PRIVATE", cheader_filename = "gudev/gudev.h")]
	public struct DevicePrivate {
	}
	[CCode (cprefix = "G_UDEV_DEVICE_TYPE_", cheader_filename = "gudev/gudev.h")]
	public enum DeviceType {
		NONE,
		BLOCK,
		CHAR
	}
	[CCode (cheader_filename = "gudev/gudev.h")]
	public const int GUDEV_INSIDE_GUDEV_H;
}
