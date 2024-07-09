# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'storage' : 'persistent',
                # FIXME: Figure out why reboot sometimes hangs with 'linux' firmware.
                # Use 'auto' to automatically fallback on non-uefi architectures.
                'firmware' : 'auto',
        },
]
