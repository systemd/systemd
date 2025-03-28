# SPDX-License-Identifier: LGPL-2.1-or-later

id = find_program('id', required : true)
uid = run_command(id, '-u', check : true).stdout().strip().to_int()

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
                'enabled' : uid == 0,
        },
]
