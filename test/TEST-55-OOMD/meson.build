test_params += {
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-55.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-55.service',
                        'systemd.wants=end.service',
                        'systemd.mount-extra=/usr/share/testsuite-55-oomd.raw:/run/extensions/testsuite-55-oomd.raw::bind',
                ]),
        ],
}
