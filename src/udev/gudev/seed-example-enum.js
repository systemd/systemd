#!/usr/bin/env seed

const GLib = imports.gi.GLib;
const GUdev = imports.gi.GUdev;

function print_device(device) {
  print("  initialized:            " + device.get_is_initialized());
  print("  usec since initialized: " + device.get_usec_since_initialized());
  print("  subsystem:              " + device.get_subsystem());
  print("  devtype:                " + device.get_devtype());
  print("  name:                   " + device.get_name());
  print("  number:                 " + device.get_number());
  print("  sysfs_path:             " + device.get_sysfs_path());
  print("  driver:                 " + device.get_driver());
  print("  action:                 " + device.get_action());
  print("  seqnum:                 " + device.get_seqnum());
  print("  device type:            " + device.get_device_type());
  print("  device number:          " + device.get_device_number());
  print("  device file:            " + device.get_device_file());
  print("  device file symlinks:   " + device.get_device_file_symlinks());
  print("  tags:                   " + device.get_tags());
  var keys = device.get_property_keys();
  for (var n = 0; n < keys.length; n++) {
    print("    " + keys[n] + "=" + device.get_property(keys[n]));
  }
}

var client = new GUdev.Client({subsystems: []});
var enumerator = new GUdev.Enumerator({client: client});
enumerator.add_match_subsystem('b*')

var devices = enumerator.execute();

for (var n=0; n < devices.length; n++) {
    var device = devices[n];
    print_device(device);
    print("");
}
