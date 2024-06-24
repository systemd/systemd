# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'credentials' : integration_test_template['credentials'] + [
                        files('keyfile'),
                        'fstab.extra="/dev/mapper/test24_varcrypt /var ext4 defaults 0 1"',
                ],
                'cmdline' : [
                        'rd.systemd.wants=encrypted-var.service',
                        'rd.luks=1',
                        'luks.name=0d318174-56b0-4d6e-a324-ac1e7e7d235d=test24_varcrypt',
                        'luks.key=0d318174-56b0-4d6e-a324-ac1e7e7d235d=/keyfile:LABEL=varcrypt_keydev',
                        'luks.options=0d318174-56b0-4d6e-a324-ac1e7e7d235d=x-initrd.attach',
                ],
                'qemu-args' : [
                        '-drive', 'id=keydev,if=none,format=raw,cache=unsafe,file=@0@'.format(project_build_root / 'mkosi.output/keydev.raw'),
                        '-device', 'scsi-hd,drive=keydev',
                ],
                'mkosi-args' : integration_test_template['mkosi-args'] + [
                        '--runtime-size=11G',
                ],
                'vm' : true,
        },
]
