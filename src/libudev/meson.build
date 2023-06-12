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

libraries += [[
        {
                'name' : 'udev',
        },
        {
                'version' : libudev_version,
                'include_directories' : includes,
                'link_args' : ['-shared',
                               '-Wl,--version-script=' + libudev_sym_path],
                'link_with' : [libsystemd_static, libshared_static],
                'link_whole' : libudev_basic,
                'dependencies' : [threads,
                                  userspace],
                'link_depends' : libudev_sym,
                'install' : true,
                'install_tag' : 'libudev',
                'install_dir' : libdir,
        },
        {
                'sources' : basic_sources +
                            fundamental_sources +
                            shared_sources +
                            libsystemd_sources +
                            libudev_sources,
                'include_directories' : includes,
                'build_by_default' : static_libudev != 'false',
                'install' : static_libudev != 'false',
                'install_tag' : 'libudev',
                'install_dir' : libdir,
                'link_depends' : libudev_sym,
                'dependencies' : [libmount,
                                  libshared_deps,
                                  userspace,
                                  versiondep],
                'c_args' : static_libudev_pic ? [] : ['-fno-PIC'],
                'pic' : static_libudev_pic,
        },
]]

############################################################

tests += [
        {
                'sources' : files('test-libudev.c'),
                'link_with' : [
                        libshared,
                        libudev_basic,
                ],
        },
]
