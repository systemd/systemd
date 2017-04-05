# -*- mode: meson -*-

libudev_sources = '''
  libudev-private.h
  libudev-device-internal.h
  libudev.c
  libudev-list.c
  libudev-util.c
  libudev-device.c
  libudev-device-private.c
  libudev-enumerate.c
  libudev-monitor.c
  libudev-queue.c
  libudev-hwdb.c
'''.split()

############################################################

libudev_sym = meson.current_source_dir() + '/libudev.sym'

libudev = shared_library(
    'udev',
    libudev_sources,
    version : '1.6.6',
    include_directories : includes,
    link_args : ['-shared',
                 '-Wl,--version-script=' + libudev_sym],
    link_with : [libbasic,
                 libsystemd],
    install : true,
    install_dir : rootlibdir)

libudev_internal = static_library(
    'udev',
    libudev_sources,
    include_directories : includes,
    link_with : [libbasic,
                 libsystemd])

install_headers('libudev.h')

libudev_pc = configure_file(
    input : 'libudev.pc.in',
    output : 'libudev.pc',
    configuration : substs)
install_data(libudev_pc,
             install_dir : pkgconfiglibdir)
