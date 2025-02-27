# SPDX-License-Identifier: LGPL-2.1-or-later
# VM-specific auxiliary tests. Container-based ones go in TEST-74-AUX-UTILS.

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'storage': 'persistent',
                'coredump-exclude-regex' : '/(test-usr-dump|test-dump|bash)$',
                'vm' : true,
        },
]
