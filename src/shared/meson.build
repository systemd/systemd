# SPDX-License-Identifier: LGPL-2.1+

shared_sources = files('''
        acl-util.h
        acpi-fpdt.c
        acpi-fpdt.h
        apparmor-util.c
        apparmor-util.h
        ask-password-api.c
        ask-password-api.h
        base-filesystem.c
        base-filesystem.h
        boot-timestamps.c
        boot-timestamps.h
        bootspec.c
        bootspec.h
        bus-unit-util.c
        bus-unit-util.h
        bus-util.c
        bus-util.h
        cgroup-show.c
        cgroup-show.h
        clean-ipc.c
        clean-ipc.h
        condition.c
        condition.h
        conf-parser.c
        conf-parser.h
        dev-setup.c
        dev-setup.h
        dissect-image.c
        dissect-image.h
        dns-domain.c
        dns-domain.h
        dropin.c
        dropin.h
        efivars.c
        efivars.h
        enable-mempool.c
        fdset.c
        fdset.h
        firewall-util.h
        fstab-util.c
        fstab-util.h
        generator.c
        generator.h
        gpt.h
        id128-print.c
        id128-print.h
        ima-util.c
        ima-util.h
        import-util.c
        import-util.h
        initreq.h
        install-printf.c
        install-printf.h
        install.c
        install.h
        journal-util.c
        journal-util.h
        logs-show.c
        logs-show.h
        loop-util.c
        loop-util.h
        machine-image.c
        machine-image.h
        machine-pool.c
        machine-pool.h
        module-util.h
        nsflags.c
        nsflags.h
        output-mode.c
        output-mode.h
        path-lookup.c
        path-lookup.h
        ptyfwd.c
        ptyfwd.h
        resolve-util.c
        resolve-util.h
        seccomp-util.h
        serialize.c
        serialize.h
        sleep-config.c
        sleep-config.h
        spawn-ask-password-agent.c
        spawn-ask-password-agent.h
        spawn-polkit-agent.c
        spawn-polkit-agent.h
        specifier.c
        specifier.h
        switch-root.c
        switch-root.h
        sysctl-util.c
        sysctl-util.h
        tomoyo-util.c
        tomoyo-util.h
        udev-util.c
        udev-util.h
        uid-range.c
        uid-range.h
        utmp-wtmp.h
        vlan-util.c
        vlan-util.h
        volatile-util.c
        volatile-util.h
        watchdog.c
        watchdog.h
        wireguard-netlink.h
'''.split())

if get_option('tests') != 'false'
        shared_sources += files('tests.c', 'tests.h')
endif

test_tables_h = files('test-tables.h')
shared_sources += test_tables_h

if conf.get('HAVE_ACL') == 1
        shared_sources += files('acl-util.c')
endif

if conf.get('ENABLE_UTMP') == 1
        shared_sources += files('utmp-wtmp.c')
endif

if conf.get('HAVE_SECCOMP') == 1
        shared_sources += files('seccomp-util.c')
endif

if conf.get('HAVE_LIBIPTC') == 1
        shared_sources += files('firewall-util.c')
endif

if conf.get('HAVE_KMOD') == 1
        shared_sources += files('module-util.c')
endif

libshared_name = 'systemd-shared-@0@'.format(meson.project_version())

libshared_deps = [threads,
                  librt,
                  libcap,
                  libacl,
                  libcryptsetup,
                  libgcrypt,
                  libiptc,
                  libkmod,
                  libseccomp,
                  libselinux,
                  libidn,
                  libxz,
                  liblz4,
                  libblkid]

libshared_sym_path = '@0@/libshared.sym'.format(meson.current_source_dir())

libshared_static = static_library(
        libshared_name,
        shared_sources,
        include_directories : includes,
        dependencies : libshared_deps,
        c_args : ['-fvisibility=default'])

libshared = shared_library(
        libshared_name,
        libudev_sources,
        include_directories : includes,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libshared_sym_path],
        link_whole : [libshared_static,
                      libbasic,
                      libbasic_gcrypt,
                      libsystemd_static,
                      libjournal_client],
        c_args : ['-fvisibility=default'],
        dependencies : libshared_deps,
        install : true,
        install_dir : rootlibexecdir)
