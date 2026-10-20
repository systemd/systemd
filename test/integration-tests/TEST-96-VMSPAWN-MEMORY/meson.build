# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'vm' : true,
                # Boots full guests from the built image inside the test VM.
                'vm-images' : true,
        },
]
