# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'mkosi-args' : integration_test_template['mkosi-args'] + [
                        '--configure-script', meson.current_source_dir() / 'mkosi.configure',
                ],
                'vm' : true,
        },
]
