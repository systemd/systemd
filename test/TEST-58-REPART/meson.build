test_params += {
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-58.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-58.service',
                        'systemd.wants=end.service',
                        # Host repart config interferes with the test
                        # so this sysext replaces it with empty files.
                        'systemd.mount-extra=/usr/share/testsuite-58-repart.raw:/run/extensions/testsuite-58-repart.raw::bind',
                ]),
        ],
}
