test(
    dirname,
    integration_test_wrapper,
    env : test_env,
    args : [
        system_mkosi,
        'testsuite-02.service',
        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-02.units:/usr/lib/systemd/tests/testdata/units:',
        'systemd.unit=testsuite.target',
        'systemd.wants=testsuite-02.service',
        'systemd.wants=end.service',
        '''
frobnicate!

systemd.setenv=TEST_CMDLINE_NEWLINE=foo
systemd.setenv=TEST_CMDLINE_NEWLINE=bar

''',
    ],
    depends : [system_mkosi, executables_by_name['systemd-dissect']],
    timeout : 2400,
    suite : 'integration-tests')
