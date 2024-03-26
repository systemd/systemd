testsuite_08_initrd_mkosi = custom_target('testsuite_08_initrd_mkosi',
        build_always_stale : true,
        output : 'testsuite_08_initrd',
        console : true,
        command: [build_system_mkosi_wrapper, 'testsuite-08-initrd-system', '@OUTPUT@']
)
test_params += {
        'mkosi_image_name': 'testsuite-08-initrd-system',
        'mkosi_output_path': testsuite_08_initrd_mkosi,
        'depends': [testsuite_08_initrd_mkosi, executables_by_name['systemd-dissect']],
        'hook_module': meson.current_source_dir() / 'hook.py',
}
