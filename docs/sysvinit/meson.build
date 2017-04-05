# -*- mode: meson -*-

file = configure_file(
    input : 'README.in',
    output : 'README',
    configuration : substs)
install_data(file,
             install_dir : sysvinit_path)
