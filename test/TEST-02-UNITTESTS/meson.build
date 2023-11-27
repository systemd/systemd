test(
    dirname,
    integration_test_wrapper,
    env : test_env,
    args : [
        'system',
        f'testsuite-02.service',
        '--kernel-command-line-extra=' + ' '.join([
            f'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-02.units:/usr/lib/systemd/tests/testdata/units:',
            'systemd.unit=testsuite.target',
            f'systemd.wants=testsuite-02.service',
            'noresume',
            'oops=panic',
            'panic=1',
            'systemd.wants=end.service',
        ]) + '''
frobnicate!

systemd.setenv=TEST_CMDLINE_NEWLINE=foo
systemd.setenv=TEST_CMDLINE_NEWLINE=bar

''',
        'qemu',
    ],
    depends : [system_mkosi],
    timeout : 0,
    suite : 'integration-tests',
    is_parallel : false)
