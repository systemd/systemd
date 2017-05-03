file = configure_file(
        input : 'README.in',
        output : 'README',
        configuration : substs)

if conf.get('HAVE_SYSV_COMPAT', false)
        install_data(file,
                     install_dir : varlogdir)
endif
