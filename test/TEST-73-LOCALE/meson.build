# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'priority' : 10,
                # TODO: Remove when https://github.com/systemd/systemd/issues/35335 is fixed.
                'coredump-exclude-regex' : '/systemd-localed',
        },
]
