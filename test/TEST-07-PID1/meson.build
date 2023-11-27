test_params += {
  'mkosi_image_name': 'testsuite-07-pid1-system',
}
testsuite_07_pid1_mkosi = custom_target('testsuite_07_pid1_mkosi',
        build_always_stale : true,
        output : 'testsuite_07_pid1',
        console : true,
        command: [build_system_mkosi_wrapper, test_params['mkosi_image_name'], '@OUTPUT@']
)
args = []
if get_option('b_coverage') == true
       args += [
                'systemd.mount-extra=/usr/share/testsuite-07-pid1-triggerlimitinterval.raw:/run/extensions/testsuite-07-pid1-triggerlimitinterval.raw::bind',
                'systemd.wants=systemd-sysext.service',
        ]
endif
args += [
        '--kernel-command-line-extra=' + ' '.join([
                'apparmor=0',
                'selinux=0',
                'enforcing=0',
                'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-07.units:/usr/lib/systemd/tests/testdata/units:',
                'systemd.unit=testsuite.target',
                'systemd.wants=testsuite-07.service',
                'systemd.wants=end.service',
        ])
]
test_params += {
        'mkosi_output_path': testsuite_07_pid1_mkosi,
        'mkosi_args': args,
        'depends': [testsuite_07_pid1_mkosi, executables_by_name['systemd-dissect']],
}
