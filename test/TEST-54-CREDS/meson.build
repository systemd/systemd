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
                ],
                'qemu-args' : integration_test_template['qemu-args'] + [
                        '-fw_cfg', 'name=opt/io.systemd.credentials/myqemucredential,string=othervalue',
                        '-smbios', 'type=11,value=io.systemd.credential:smbioscredential=magicdata',
                        '-smbios', 'type=11,value=io.systemd.credential.binary:binarysmbioscredential=bWFnaWNiaW5hcnlkYXRh',
                        '-smbios', 'type=11,value=io.systemd.credential.binary:sysusers.extra=dSBjcmVkdGVzdHVzZXIK',
                        '-smbios', 'type=11,value=io.systemd.credential.binary:tmpfiles.extra=ZiAvdG1wL3NvdXJjZWRmcm9tY3JlZGVudGlhbCAtIC0gLSAtIHRtcGZpbGVzc2VjcmV0Cg==',
                        '-smbios', 'type=11,value=io.systemd.credential.binary:fstab.extra=aW5qZWN0ZWQgL2luamVjdGVkIHRtcGZzIFgtbW91bnQubWtkaXIgMCAwCg==',
                        '-smbios', 'type=11,value=io.systemd.credential:getty.ttys.container=idontexist',
                ],
        },
]
