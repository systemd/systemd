# TODO: Use runtime switch instead
system_no_secure_boot_mkosi = custom_target('system_no_secure_boot_mkosi',
        build_always_stale : true,
        output : 'system_no_secure_boot_mkosi',
        console : true,
        command : ['mkosi', '-C', meson.project_source_root(), '--image', test_params['mkosi_image_name'], '--format=disk', '--secure-boot=no', '--output-dir', meson.project_build_root() / '@OUTPUT@', '--without-tests', '-fi', 'build'],
        depends : [executables_by_name['bootctl'], executables_by_name['systemd-measure'], executables_by_name['systemd-repart'], ukify],
)
test_params += {
        'mkosi_output_path' : system_no_secure_boot_mkosi,
        'depends' : [system_no_secure_boot_mkosi],
}
