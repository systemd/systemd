test_params += {
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-82.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-82.service',
                ]),
        ],
}
