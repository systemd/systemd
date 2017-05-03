if conf.get('ENABLE_HOSTNAMED', false)
        install_data('org.freedesktop.hostname1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.hostname1.service',
                     install_dir : dbussystemservicedir)

        custom_target(
                'org.freedesktop.hostname1.policy',
                input : 'org.freedesktop.hostname1.policy.in',
                output : 'org.freedesktop.hostname1.policy',
                command : intltool_command,
                install : install_polkit,
                install_dir : polkitpolicydir)
endif
