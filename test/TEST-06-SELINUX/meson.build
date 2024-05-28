# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'cmdline' : integration_test_template['cmdline'] + ['selinux=1', 'lsm=selinux'],
                # FIXME; Figure out why reboot sometimes hangs with 'linux' firmware.
                'firmware' : 'uefi',
                'vm' : true,
        },
]

testdata_subdirs += [meson.current_source_dir() / 'TEST-06-SELINUX.units']
