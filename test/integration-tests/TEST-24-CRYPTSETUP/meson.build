# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'credentials' : integration_test_template['credentials'] + [
                        'fstab.extra="/dev/mapper/test24_varcrypt /var ext4 defaults 0 1"',
                        # Order sysroot.mount and the keydev mount behind systemd-modules-load.service,
                        # which loads ext4 early (rd.modules-load= below), so that neither mount races
                        # on the kernel's lazy ext4 module load. The backslash in the escaped unit name
                        # of the keydev mount is doubled: once for meson, once for mkosi's shlex based
                        # credential parsing.
                        'systemd.unit-dropin.sysroot.mount="[Unit]\nAfter=systemd-modules-load.service\n"',
                        'systemd.unit-dropin.run-systemd-cryptsetup-keydev\\\\x2dtest24_varcrypt.mount="[Unit]\nAfter=systemd-modules-load.service\n"',
                ],
                'cmdline' : [
                        'rd.systemd.wants=encrypted-var.service',
                        'rd.luks=1',
                        'luks.name=0d318174-56b0-4d6e-a324-ac1e7e7d235d=test24_varcrypt',
                        'luks.key=0d318174-56b0-4d6e-a324-ac1e7e7d235d=/keyfile:LABEL=varcrypt_keydev',
                        'luks.options=0d318174-56b0-4d6e-a324-ac1e7e7d235d=x-initrd.attach',
                        # The initrd sets up two ext4 file systems (the root and the key device for
                        # the encrypted /var) and they race on the kernel's lazy ext4 module load.
                        # Load it early, and order both mounts behind systemd-modules-load.service
                        # (see the unit drop-in credentials above), to avoid a spurious "unknown
                        # filesystem type 'ext4'" failure.
                        'rd.modules-load=ext4',
                ],
                'qemu-args' : [
                        '-drive', 'id=keydev,if=none,format=raw,cache=unsafe,file=@0@'.format(meson.project_build_root() / 'mkosi.output/keydev.raw'),
                        '-device', 'virtio-blk-pci,drive=keydev,serial=keydev',
                ],
                'mkosi-args' : integration_test_template['mkosi-args'] + [
                        '--runtime-size=11G',
                ],
                'vm' : true,
                'firmware' : 'linux',
        },
]
