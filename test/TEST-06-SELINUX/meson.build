test_params += {
        'mkosi_image_name': 'testsuite-06-selinux-system',
}
testsuite_06_mkosi = custom_target('testsuite_06_mkosi',
        build_always_stale : true,
        output : 'testsuite_06',
        command: [build_system_mkosi_wrapper, test_params['mkosi_image_name'], '@OUTPUT@']
)
test_params += {
        'mkosi_output_path': testsuite_06_mkosi,
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-06.service',
                        'systemd.wants=end.service',
                ]),
        ],
        'depends': [testsuite_06_mkosi, executables_by_name['systemd-dissect']],
}
