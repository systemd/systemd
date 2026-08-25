# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                # The nspawn subtest boots a container, which is unreliable when nested inside the nspawn-based
                # test container
                'vm' : true,
        },
]
