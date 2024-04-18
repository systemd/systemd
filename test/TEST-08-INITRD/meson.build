test_params += {
        'mkosi_image_name': 'testsuite-08-initrd-system',
}
testsuite_08_initrd_mkosi = custom_target('testsuite_08_initrd_mkosi',
        build_always_stale : true,
        output : 'testsuite_08_initrd',
        console : true,
        command : ['mkosi', '-C', meson.project_source_root(), '--image', test_params['mkosi_image_name'], '--format=disk', '--output-dir', meson.project_build_root() / '@OUTPUT@', '--without-tests', '-fi', 'build'],
        depends : [executables_by_name['bootctl'], executables_by_name['systemd-measure'], executables_by_name['systemd-repart'], ukify],
)
test_params += {
        'mkosi_output_path': testsuite_08_initrd_mkosi,
        'depends': [testsuite_08_initrd_mkosi],
        'hook_module': meson.current_source_dir() / 'hook.py',
}
