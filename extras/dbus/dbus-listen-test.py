#!/usr/bin/python

# receives and prints the messages udev_dbus sent
# to the org.kernel.udev.NodeMonitor interface

import dbus
import gtk

def udev_signal_received(dbus_iface, member, service, object_path, message):
	[filename, sysfs_path] = message.get_args_list()
	if member=='NodeCreated':
		print 'Node %s created for %s'%(filename, sysfs_path)
	elif member=='NodeDeleted':
		print 'Node %s deleted for %s'%(filename, sysfs_path)

def main():
	bus = dbus.Bus(dbus.Bus.TYPE_SYSTEM)
	bus.add_signal_receiver(udev_signal_received,
		'org.kernel.udev.NodeMonitor',		# interface
		'org.kernel.udev',			# service
		'/org/kernel/udev/NodeMonitor')		# object
	gtk.mainloop()

if __name__ == '__main__':
	main()

