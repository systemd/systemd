# SPDX-License-Identifier: LGPL-2.1-or-later

name = fs.name(meson.current_source_dir())
udev_storage_tests = []
udev_storage_test_template = {
        'enabled' : true,
}

qemu = find_program('qemu-system-@0@'.format(host_machine.cpu_family()), 'qemu-kvm', dirs : ['/usr/libexec'], native : true, required : false)
if qemu.found() and host_machine.cpu_family() == 'aarch64'
        # qemu-system-aarch64 errors out if no machine is specified
        devices = run_command(qemu, '-device', 'help', '-machine', 'virt', check : true).stdout().strip()
elif qemu.found()
        devices = run_command(qemu, '-device', 'help', check : true).stdout().strip()
else
        devices = ''
endif

cmdline = []
qemu_args = []

foreach i : range(10)
        id = f'drivesimultaneousevents@i@'
        cmdline += [f'--drive=@id@:128M::']
        qemu_args += ['-device', f'scsi-hd,drive=@id@,serial=deadbeeftest@i@']
endforeach

udev_storage_tests += udev_storage_test_template + {
        'name' : 'simultaneous_events',
        'cmdline' : cmdline,
        'qemu-args' : qemu_args,
        'priority' : 10,
}

foreach testcase : udev_storage_tests
        qemu_args = ' '.join(testcase['qemu-args'])
        cmdline = testcase['cmdline'] + [f'--qemu-args=@qemu_args@']

        integration_tests += [
                integration_test_template + {
                        'name' : '@0@-@1@'.format(name, testcase['name']),
                        # Disable user service manager by default for performance.
                        'configuration' : integration_test_template['configuration'] + {
                                'wants' : '',
                                'after' : '',
                                'command' : f'/usr/lib/systemd/tests/testdata/units/@name@.sh',
                                'env' : integration_test_template['configuration']['env'] + {
                                        'TEST_FUNCTION_NAME': 'testcase_@0@'.format(testcase['name']),
                                },
                        },
                        'mkosi-args' : integration_test_template['mkosi-args'] + cmdline,
                        'priority' : testcase.get('priority', 0),
                        'vm' : true,
                        # Suppress ASan error
                        # 'multipathd[1820]: ==1820==ERROR: AddressSanitizer: Joining already joined thread, aborting.'
                        'sanitizer-exclude-regex' : 'multipathd',
                        'enabled' : testcase['enabled'],
                },
        ]
endforeach
