# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'cmdline' : integration_test_template['cmdline'] + [
                        'rd.systemd.wants=initrd-run-mount.service',
                ],
                'exit-code' : 124,
                'vm' : true,
        },
]
