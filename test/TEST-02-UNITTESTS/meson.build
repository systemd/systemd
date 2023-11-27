test(
    dirname,
    integration_test_wrapper,
    env : test_env,
    args : [
        system_mkosi,
        f'testsuite-02.service',
        f'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-02.units:/usr/lib/systemd/tests/testdata/units:',
        'systemd.unit=testsuite.target',
        f'systemd.wants=testsuite-02.service',
        'systemd.wants=end.service',
        '''
frobnicate!

systemd.setenv=TEST_CMDLINE_NEWLINE=foo
systemd.setenv=TEST_CMDLINE_NEWLINE=bar

''',
    ],
    depends : [system_mkosi],
    timeout : 0,
    suite : 'integration-tests')
