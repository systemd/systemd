# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template
        + {
                'name': fs.name(meson.current_source_dir()),
                'vm': true,
                'firmware': 'auto',
                'cmdline': integration_test_template['cmdline'] + ['root=tmpfs'],
                'mkosi-args': integration_test_template['mkosi-args'] + ['--profile=usr-only'],
        },
]
