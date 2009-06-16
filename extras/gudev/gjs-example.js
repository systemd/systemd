#!/usr/bin/env gjs-console

// This currently depends on the following patches to gjs
//
// http://bugzilla.gnome.org/show_bug.cgi?id=584558
// http://bugzilla.gnome.org/show_bug.cgi?id=584560
// http://bugzilla.gnome.org/show_bug.cgi?id=584568

const GUdev = imports.gi.GUdev;
const Mainloop = imports.mainloop;

function print_device (device) {
  print ("  subsystem:             " + device.get_subsystem ());
  print ("  devtype:               " + device.get_devtype ());
  print ("  name:                  " + device.get_name ());
  print ("  number:                " + device.get_number ());
  print ("  sysfs_path:            " + device.get_sysfs_path ());
  print ("  driver:                " + device.get_driver ());
  print ("  action:                " + device.get_action ());
  print ("  seqnum:                " + device.get_seqnum ());
  print ("  device type:           " + device.get_device_type ());
  print ("  device number:         " + device.get_device_number ());
  print ("  device file:           " + device.get_device_file ());
  print ("  device file symlinks:  " + device.get_device_file_symlinks ());
  print ("  foo: " + device.get_sysfs_attr_as_strv ("stat"));
  var keys = device.get_property_keys ();
  for (var n = 0; n < keys.length; n++) {
    print ("    " + keys[n] + "=" + device.get_property (keys[n]));
  }
}

function on_uevent (client, action, device) {
  print ("action " + action + " on device " + device.get_sysfs_path());
  print_device (device);
  print ("");
}

var client = new GUdev.Client ({subsystems: ["block", "usb/usb_interface"]});
client.connect ("uevent", on_uevent);

var block_devices = client.query_by_subsystem ("block");
for (var n = 0; n < block_devices.length; n++) {
  print ("block device: " + block_devices[n].get_device_file ());
}

var d;

d = client.query_by_device_number (GUdev.DeviceType.BLOCK, 0x0810);
if (d == null) {
  print ("query_by_device_number 0x810 -> null");
} else {
  print ("query_by_device_number 0x810 -> " + d.get_device_file ());
  var dd = d.get_parent_with_subsystem ("usb", null);
  print_device (dd);
  print ("--------------------------------------------------------------------------");
  while (d != null) {
    print_device (d);
    print ("");
    d = d.get_parent ();
  }
}

d = client.query_by_sysfs_path ("/sys/block/sda/sda1");
print ("query_by_sysfs_path (\"/sys/block/sda1\") -> " + d.get_device_file ());

d = client.query_by_subsystem_and_name ("block", "sda2");
print ("query_by_subsystem_and_name (\"block\", \"sda2\") -> " + d.get_device_file ());

d = client.query_by_device_file ("/dev/sda");
print ("query_by_device_file (\"/dev/sda\") -> " + d.get_device_file ());

d = client.query_by_device_file ("/dev/block/8:0");
print ("query_by_device_file (\"/dev/block/8:0\") -> " + d.get_device_file ());

Mainloop.run('udev-example');
