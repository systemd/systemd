# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'coredump-exclude-regex' : '/(coreutils|sleep|bash|systemd-notify)$',
        },
]
