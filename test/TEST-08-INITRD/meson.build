testsuite_08_initrd_mkosi = custom_target('testsuite_08_initrd_mkosi',
        build_always_stale : true,
        output : 'testsuite_08_initrd',
        command: [build_system_mkosi_wrapper, 'testsuite-08-initrd-system', '@OUTPUT@']
)
testsuite_08_hook = configure_file(
        input : 'hook.py',
        output : 'hook.py',
        copy : true,
)
test_params += {
        'mkosi_image_name': 'testsuite-08-initrd-system',
        'mkosi_output_path': testsuite_08_initrd_mkosi,
        'depends': [testsuite_08_initrd_mkosi, executables_by_name['systemd-dissect']],
        'hook_module': testsuite_08_hook,
}
