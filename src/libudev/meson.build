# SPDX-License-Identifier: LGPL-2.1-or-later

libudev_sources = files(
        'libudev-device.c',
        'libudev-enumerate.c',
        'libudev-hwdb.c',
        'libudev-list.c',
        'libudev-monitor.c',
        'libudev-queue.c',
        'libudev-util.c',
        'libudev.c',
)

sources += libudev_sources

############################################################

libudev_includes = [includes, include_directories('.')]

libudev_dir_path = meson.current_source_dir()

libudev_sym = files('libudev.sym')
libudev_sym_path = libudev_dir_path / 'libudev.sym'

install_headers('libudev.h')
libudev_h_path = libudev_dir_path / 'libudev.h'

libudev_basic = static_library(
        'udev-basic',
        libudev_sources,
        include_directories : includes,
        implicit_include_directories : false,
        dependencies : userspace,
        c_args : ['-fvisibility=default'],
        build_by_default : false)

static_libudev = get_option('static-libudev')
static_libudev_pic = static_libudev == 'true' or static_libudev == 'pic'

libudev_pc = custom_target(
        'libudev.pc',
        input : 'libudev.pc.in',
        output : 'libudev.pc',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pkgconfiglibdir != 'no',
        install_tag : 'devel',
        install_dir : pkgconfiglibdir)
