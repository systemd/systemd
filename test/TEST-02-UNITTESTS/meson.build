test_params += {
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-02.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-02.service',
                        'systemd.wants=end.service',
                        '''
frobnicate!

systemd.setenv=TEST_CMDLINE_NEWLINE=foo
systemd.setenv=TEST_CMDLINE_NEWLINE=bar

''',
                ]),
        ],
}
