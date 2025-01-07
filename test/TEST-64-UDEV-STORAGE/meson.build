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

foreach testcase : [
        'btrfs_basic',
        'iscsi_lvm',
        'long_sysfs_path',
        'lvm_basic',
        'mdadm_basic',
        'mdadm_lvm',
        'multipath_basic_failover',
        'nvme_basic',
        'nvme_subsystem',
        'simultaneous_events',
        'virtio_scsi_basic',
        'virtio_scsi_identically_named_partitions',
]
        integration_tests += [
                integration_test_template + {
                        'name' : '@0@-@1@'.format(name, testcase),
                        # Make sure the service is still named TEST-64-UDEV-STORAGE.service.
                        'unit' : unit,
                        'cmdline' : integration_test_template['cmdline'] + [
                                'systemd.setenv=TEST_FUNCTION_NAME=testcase_@0@'.format(testcase)
                        ],
                        'mkosi-args' : integration_test_template['mkosi-args'] + [
                                '--configure-script', files('@0@.configure'.format(testcase)),
                        ],
                        'priority' : 10,
                        'vm' : true,
                        # Suppress ASan error
                        # 'multipathd[1820]: ==1820==ERROR: AddressSanitizer: Joining already joined thread, aborting.'
                        'sanitizer-exclude-regex' : 'multipathd'
                },
        ]
endforeach
