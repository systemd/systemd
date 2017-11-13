if conf.get('ENABLE_HOSTNAMED') == 1
        install_data('org.freedesktop.hostname1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.hostname1.service',
                     install_dir : dbussystemservicedir)

        i18n.merge_file(
                'org.freedesktop.hostname1.policy',
                input : 'org.freedesktop.hostname1.policy.in',
                output : 'org.freedesktop.hostname1.policy',
                po_dir : po_dir,
                install : install_polkit,
                install_dir : polkitpolicydir)
endif
