# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'cmdline' : integration_test_template['cmdline'] + [
                        'systemd.set_credential=kernelcmdlinecred:uff',
                        'systemd.set_credential=sysctl.extra:kernel.domainname=sysctltest',
                        'systemd.set_credential=login.motd:hello',
                        'systemd.set_credential=login.issue:welcome',
                        'systemd.set_credential_binary=waldi:d29vb29mZmZ3dWZmZnd1ZmYK',
                        'rd.systemd.import_credentials=no',
                        'rd.systemd.wants=initrdcred.service',
                ],
                'credentials' : integration_test_template['credentials'] + [
                        'mynspawncredential=strangevalue',
                        files('systemd.extra-unit.my-service.service'),
                        files('systemd.unit-dropin.my-service.service'),
                        files('systemd.unit-dropin.my-service.service~30-named.service'),
                        'smbioscredential=magicdata',
                        'binarysmbioscredential=magicbinarydata',
                        'sysusers.extra="u credtestuser"',
                        'tmpfiles.extra="f /tmp/sourcedfromcredential - - - - tmpfilessecret"',
                        'fstab.extra="injected /injected tmpfs X-mount.mkdir 0 0"',
                        'getty.ttys.container=idontexist',
                ],
                'qemu-args' : integration_test_template['qemu-args'] + [
                        '-fw_cfg', 'name=opt/io.systemd.credentials/myqemucredential,string=othervalue',
                ],
                'firmware' : 'auto',
        },
]
