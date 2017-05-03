if conf.get('ENABLE_TIMEDATED', false)
        install_data('org.freedesktop.timedate1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.timedate1.service',
                     install_dir : dbussystemservicedir)

        custom_target(
                'org.freedesktop.timedate1.policy',
                input : 'org.freedesktop.timedate1.policy.in',
                output : 'org.freedesktop.timedate1.policy',
                command : intltool_command,
                install : install_polkit,
                install_dir : polkitpolicydir)
endif
