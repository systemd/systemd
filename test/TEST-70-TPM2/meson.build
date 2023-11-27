system_no_secure_boot_mkosi = custom_target('system_no_secure_boot_mkosi',
        build_always_stale : true,
        output : 'system_no_secure_boot_mkosi',
        console : true,
        command: [build_system_mkosi_wrapper, test_params['mkosi_image_name'], '@OUTPUT@', '--secure-boot=no'],
)
test_params += {
        'mkosi_output_path' : system_no_secure_boot_mkosi,
        'depends' : [system_no_secure_boot_mkosi, executables_by_name['systemd-dissect']],
}
