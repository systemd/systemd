# Can be flaky on starting the journal-remote
args = [
        '--kernel-command-line-extra=' + ' '.join([
                'apparmor=0',
                'selinux=0',
                'enforcing=0',
                'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-04.units:/usr/lib/systemd/tests/testdata/units:',
                'systemd.unit=testsuite.target',
                'systemd.wants=testsuite-04.service',
                'systemd.wants=end.service',
        ])
]
if get_option('tests-interactive-debug') == true
        args += [
                '--kernel-command-line-extra',
                ' '.join([
                        'systemd.mount-extra=/usr/share/testsuite-04-journal-interactive-debug.raw:/run/extensions/testsuite-04-journal-interactive-debug.raw::bind',
                        'systemd.wants=systemd-sysext.service',
                ]),
        ]
endif
test_params += {
        'mkosi_args': args,
}
