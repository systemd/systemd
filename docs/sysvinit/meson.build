file = configure_file(
        input : 'README.in',
        output : 'README',
        configuration : substs)

if conf.get('HAVE_SYSV_COMPAT', 0) == 1
        install_data(file,
                     install_dir : sysvinit_path)
endif
