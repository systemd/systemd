# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'cmdline' : integration_test_template['cmdline'] + ['selinux=1', 'enforcing=0', 'lsm=selinux'],
                # FIXME; Figure out why reboot sometimes hangs with 'linux' firmware.
                # Use 'auto' to automatically fallback on non-uefi architectures.
                'firmware' : 'auto',
                'vm' : true,
                # Make sure we don't mount anything with virtiofs as otherwise fixfiles will try to relabel
                # it.
                'mkosi-args' : integration_test_template['mkosi-args'] + ['--runtime-build-sources=no'],
        },
]

testdata_subdirs += [meson.current_source_dir() / 'TEST-06-SELINUX.units']
