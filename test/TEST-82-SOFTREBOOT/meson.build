# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'unit' : files('TEST-82-SOFTREBOOT.service'),
                'cmdline' : ['systemd.set_credential=kernelcmdlinecred:uff'],
                'storage' : 'persistent',
                'vm' : true,
        },
]
