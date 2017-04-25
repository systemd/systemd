gen = configure_file(
        input : 'systemd-sulogin-shell.in',
        output : 'systemd-sulogin-shell',
        configuration : substs)

install_data(gen,
             install_dir : rootlibexecdir)
