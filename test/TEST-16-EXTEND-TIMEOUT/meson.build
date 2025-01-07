# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'unit' : files('TEST-16-EXTEND-TIMEOUT.service'),
                'coredump-exclude-regex' : '/(bash|sleep)$',
        },
]

testdata_subdirs += [meson.current_source_dir() / 'TEST-16-EXTEND-TIMEOUT.units']
