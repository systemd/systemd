# SPDX-License-Identifier: LGPL-2.1-or-later

name = fs.name(meson.current_source_dir())
unit = configure_file(
        input : files('../test.service.in'),
        output : '@0@.service'.format(name),
        # Disable user service manager by default for performance.
        configuration : integration_test_template['configuration'] + {
              'wants' : '',
              'after' : '',
        },
)

udev_storage_tests = []

cmdline = []
qemu_args = ['-device', 'virtio-scsi-pci,id=scsi0']

foreach i : range(4)
        id = f'drivebtrfsbasic@i@'
        size = i == 0 ? '350M' : '128M'
        cmdline += [f'--drive=@id@:@size@::cache=unsafe']
        qemu_args += ['-device', f'scsi-hd,drive=@id@,vendor=systemd,product=foobar,serial=deadbeefbtrfs@i@']
endforeach

udev_storage_tests += {
        'name' : 'btrfs_basic',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = []
qemu_args = ['-device', 'virtio-scsi-pci,id=scsi0']

foreach i : range(4)
        id = f'driveiscsibasic@i@'
        size = i == 0 ? '150M' : '70M'
        cmdline += [f'--drive=@id@:@size@::cache=unsafe']
        qemu_args += ['-device', f'scsi-hd,drive=@id@,vendor=systemd,product=foobar,serial=deadbeefiscsi@i@']
endforeach

udev_storage_tests += {
        'name' : 'iscsi_lvm',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = ['--drive=drive0:64M::cache=unsafe']
qemu_args = ['-device', 'pci-bridge,id=pci_bridge0,chassis_nr=64']

# Create 25 additional PCI bridges, each one connected to the previous one
# (basically a really long extension cable), and attach a virtio drive to
# the last one. This should force udev into attempting to create a device
# unit with a _really_ long name.
foreach bridge : range(1, 26)
        bus = bridge - 1
        chassis = 64 + bridge
        qemu_args += ['-device', f'pci-bridge,id=pci_bridge@bridge@,bus=pci_bridge@bus@,chassis_nr=@chassis@,addr=1']
endforeach

qemu_args += ['-device', 'virtio-blk-pci,drive=drive0,bus=pci_bridge25,addr=1,serial=long-sysfs-path']

udev_storage_tests += {
        'name' : 'long_sysfs_path',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = []
qemu_args = ['-device', 'virtio-scsi-pci,id=scsi0']

foreach i : range(4)
        id = f'drivelvmbasic@i@'
        cmdline += [f'--drive=@id@:32M::cache=unsafe']
        qemu_args += ['-device', f'scsi-hd,drive=@id@,vendor=systemd,product=foobar,serial=deadbeeflvm@i@']
endforeach

udev_storage_tests += {
        'name' : 'lvm_basic',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = []
qemu_args = ['-device', 'virtio-scsi-pci,id=scsi0']

foreach i : range(5)
        id = f'drivemdadmbasic@i@'
        cmdline += [f'--drive=@id@:64M::cache=unsafe']
        qemu_args += ['-device', f'scsi-hd,drive=@id@,vendor=systemd,product=foobar,serial=deadbeefmdadm@i@']
endforeach

udev_storage_tests += {
        'name' : 'mdadm_basic',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = []
qemu_args = ['-device', 'virtio-scsi-pci,id=scsi0']

foreach i : range(5)
        id = f'drivemdadmlvm@i@'
        cmdline += [f'--drive=@id@:64M::cache=unsafe']
        qemu_args += ['-device', f'scsi-hd,drive=@id@,vendor=systemd,product=foobar,serial=deadbeefmdadmlvm@i@']
endforeach

udev_storage_tests += {
        'name' : 'mdadm_lvm',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = []
qemu_args = []

# Add 16 multipath devices, each backed by 4 paths
foreach ndisk : range(16)
        ndiskfmt = ndisk >= 10 ? f'00@ndisk@' : f'000@ndisk@'
        wwn = f'0xDEADDEADBEEF@ndiskfmt@'
        size = ndisk == 0 ? '16M' : '1M'

        foreach nback : range(4)
                id = f'drive@ndisk@x@nback@'
                cmdline += [f'--drive=@id@:@size@::cache=unsafe:@ndisk@']
                qemu_args += ['-device', f'scsi-hd,drive=@id@,serial=MPIO@ndisk@,wwn=@wwn@']
        endforeach
endforeach

udev_storage_tests += {
        'name' : 'multipath_basic_failover',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = []
qemu_args = []

foreach i : range(10)
        id = f'drivesimultaneousevents@i@'
        cmdline += [f'--drive=@id@:128M::cache=unsafe']
        qemu_args += ['-device', f'scsi-hd,drive=@id@,serial=deadbeeftest@i@']
endforeach

udev_storage_tests += {
        'name' : 'simultaneous_events',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

cmdline = []
qemu_args = []

foreach i : range(4)
        qemu_args += ['-device', f'virtio-scsi-pci,id=scsi@i@']
endforeach

foreach i : range(128)
        id = f'drive@i@'
        cmdline += [f'--drive=@id@:1M::cache=unsafe']
        div = i / 32
        mod = i % 32
        qemu_args += ['-device', f'scsi-hd,drive=@id@,bus=scsi@div@.0,channel=0,scsi-id=@mod@,lun=0']
endforeach

udev_storage_tests += {
        'name' : 'virtio_scsi_basic',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
}

qemu = find_program('qemu-system-@0@'.format(host_machine.cpu_family()), 'qemu-kvm', dirs : ['/usr/libexec'], native : true)
if qemu.found()
        devices = run_command(qemu, '-device', 'help', check : true).stdout().strip()
        if devices.contains('name "nvme"')
                cmdline = []
                qemu_args = []

                foreach i : range(20)
                        cmdline += [f'--drive=nvme@i@:1M::cache=unsafe']
                endforeach

                foreach i : range(5)
                        qemu_args += ['-device', f'nvme,drive=nvme@i@,serial=deadbeef@i@,max_ioqpairs=8']
                endforeach

                foreach i : range(5, 10)
                        qemu_args += ['-device', f'"nvme,drive=nvme@i@,serial=    deadbeef  @i@   ,max_ioqpairs=8"']
                endforeach

                foreach i : range(10, 15)
                        qemu_args += ['-device', f'"nvme,drive=nvme@i@,serial=    dead/beef/@i@   ,max_ioqpairs=8"']
                endforeach

                foreach i : range(15, 20)
                        qemu_args += ['-device', f'"nvme,drive=nvme@i@,serial=dead/../../beef/@i@,max_ioqpairs=8"']
                endforeach

                udev_storage_tests += {
                        'name' : 'nvme_basic',
                        'cmdline' : cmdline,
                        'qemu-args' : qemu_args,
                }

                cmdline = []

                foreach id : ['nvme0', 'nvme1']
                        cmdline += [f'--drive=@id@:1M::cache=unsafe']
                endforeach

                qemu_args = [
                        # Create an NVM Subsystem Device
                        '-device', 'nvme-subsys,id=nvme-subsys-64,nqn=subsys64',
                        # Attach two NVM controllers to it
                        '-device', 'nvme,subsys=nvme-subsys-64,serial=deadbeef',
                        '-device', 'nvme,subsys=nvme-subsys-64,serial=deadbeef',
                        # And create two shared namespaces attached to both controllers
                        '-device', 'nvme-ns,drive=nvme0,nsid=16,shared=on',
                        '-device', 'nvme-ns,drive=nvme1,nsid=17,shared=on',
                ]

                udev_storage_tests += {
                        'name' : 'nvme_subsystem',
                        'cmdline' : cmdline,
                        'qemu-args' : qemu_args,
                }
        endif

        if devices.contains('name "virtio-scsi-pci"')
                cmdline = []
                qemu_args = ['-device', 'virtio-scsi-pci,id=scsi0,num_queues=4']

                foreach i : range(16)
                        id = f'drive@i@'
                        cmdline += [f'--drive=@id@:40M::cache=unsafe']
                        qemu_args += ['-device', f'scsi-hd,drive=@id@,bus=scsi0.0,channel=0,scsi-id=0,lun=@i@']
                endforeach

                udev_storage_tests += {
                        'name' : 'virtio_scsi_identically_named_partitions',
                        'cmdline' : cmdline,
                        'qemu-args' : qemu_args,
                }
        endif
endif


foreach testcase : udev_storage_tests
        qemu_args = ' '.join(testcase['qemu-args'])
        cmdline = testcase['cmdline'] + [f'--qemu-args=@qemu_args@']

        integration_tests += [
                integration_test_template + {
                        'name' : '@0@-@1@'.format(name, testcase['name']),
                        # Make sure the service is still named TEST-64-UDEV-STORAGE.service.
                        'unit' : unit,
                        'cmdline' : integration_test_template['cmdline'] + [
                                'systemd.setenv=TEST_FUNCTION_NAME=testcase_@0@'.format(testcase['name'])
                        ],
                        'mkosi-args' : integration_test_template['mkosi-args'] + cmdline,
                        'priority' : 10,
                        'vm' : true,
                        # Suppress ASan error
                        # 'multipathd[1820]: ==1820==ERROR: AddressSanitizer: Joining already joined thread, aborting.'
                        'sanitizer-exclude-regex' : 'multipathd'
                },
        ]
endforeach
