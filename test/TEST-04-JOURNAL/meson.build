# Can be flaky on starting the journal-remote
args = [
        system_mkosi,
        'testsuite-04.service',
]
if get_option('tests-interactive-debug') == true
        stdout_conf = configure_file(
            input : '99-stdout.conf',
            output : '99-stdout.conf',
            copy : true,
        )
        args += ['--credential-tmpfile', '/run/systemd/system/testsuite-04.service.d/99-stdout.conf', stdout_conf]
endif
args += [
        '--kernel-command-line-extra=' + ' '.join([
            'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-04.units:/usr/lib/systemd/tests/testdata/units:',
            'systemd.unit=testsuite.target',
            'systemd.wants=testsuite-04.service',
            'systemd.wants=end.service',
        ])
]
test(
    dirname,
    integration_test_wrapper,
    env : test_env,
    args : args,
    depends : [system_mkosi, executables_by_name['systemd-dissect']],
    timeout : 600,
    suite : 'integration-tests')
