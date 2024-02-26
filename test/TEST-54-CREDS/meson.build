test_params += {
        'mkosi_image_name': 'testsuite-54-creds-system',
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        'systemd.set_credential=kernelcmdlinecred:uff',
                        'systemd.set_credential=sysctl.extra:kernel.domainname=sysctltest',
                        'systemd.set_credential=login.motd:hello',
                        'systemd.set_credential=login.issue:welcome',
                        'systemd.set_credential_binary=waldi:d29vb29mZmZ3dWZmZnd1ZmYK',
                        'rd.systemd.import_credentials=no',
                        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-54.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-54.service',
                        'systemd.wants=end.service',
                ]),
                '--qemu-args=' + ' '.join([
                        '-fw_cfg name=opt/io.systemd.credentials/myqemucredential,string=othervalue',
                        '-smbios type=11,value=io.systemd.credential:smbioscredential=magicdata',
                        '-smbios type=11,value=io.systemd.credential.binary:binarysmbioscredential=bWFnaWNiaW5hcnlkYXRh',
                        '-smbios type=11,value=io.systemd.credential.binary:sysusers.extra=dSBjcmVkdGVzdHVzZXIK',
                        '-smbios type=11,value=io.systemd.credential.binary:tmpfiles.extra=ZiAvdG1wL3NvdXJjZWRmcm9tY3JlZGVudGlhbCAtIC0gLSAtIHRtcGZpbGVzc2VjcmV0Cg==',
                        '-smbios type=11,value=io.systemd.credential.binary:fstab.extra=aW5qZWN0ZWQgL2luamVjdGVkIHRtcGZzIFgtbW91bnQubWtkaXIgMCAwCg==',
                        '-smbios type=11,value=io.systemd.credential:getty.ttys.container=idontexist',
                ]),
        ],
}
testsuite_54_creds_mkosi = custom_target('testsuite_54_creds_mkosi',
        build_always_stale : true,
        output : 'testsuite_54_creds',
        command: [build_system_mkosi_wrapper, test_params['mkosi_image_name'], '@OUTPUT@']
)
test_params += {
        'mkosi_output_path': testsuite_54_creds_mkosi,
        'depends': [testsuite_54_creds_mkosi, executables_by_name['systemd-dissect']],
}
