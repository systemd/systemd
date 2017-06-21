shared_sources = '''
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
        fdset.c
        fdset.h
        firewall-util.h
        fstab-util.c
        fstab-util.h
        gcrypt-util.c
        gcrypt-util.h
        generator.c
        generator.h
        gpt.h
        ima-util.c
        ima-util.h
        import-util.c
        import-util.h
        initreq.h
        install.c
        install.h
        install-printf.c
        install-printf.h
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
        nsflags.c
        nsflags.h
        output-mode.c
        output-mode.h
        pager.c
        pager.h
        path-lookup.c
        path-lookup.h
        ptyfwd.c
        ptyfwd.h
        resolve-util.c
        resolve-util.h
        seccomp-util.h
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
        tests.c
        tests.h
        udev-util.h
        udev-util.c
        uid-range.c
        uid-range.h
        utmp-wtmp.h
        vlan-util.c
        vlan-util.h
        volatile-util.c
        volatile-util.h
        watchdog.c
        watchdog.h
'''.split()

test_tables_h = files('test-tables.h')
shared_sources += [test_tables_h]

if conf.get('HAVE_ACL', false)
        shared_sources += ['acl-util.c']
endif

if conf.get('HAVE_UTMP', false)
        shared_sources += ['utmp-wtmp.c']
endif

if conf.get('HAVE_SECCOMP', false)
        shared_sources += ['seccomp-util.c']
endif

if conf.get('HAVE_LIBIPTC', false)
        shared_sources += ['firewall-util.c']
endif

libshared_name = 'systemd-shared-@0@'.format(meson.project_version())

libshared_deps = [threads,
                  librt,
                  libcap,
                  libacl,
                  libcryptsetup,
                  libgcrypt,
                  libiptc,
                  libseccomp,
                  libselinux,
                  libidn,
                  libxz,
                  liblz4,
                  libblkid]

libshared = shared_library(
        libshared_name,
        shared_sources,
        basic_sources,
        journal_internal_sources,
        libsystemd_internal_sources,
        libudev_sources,
        include_directories : includes,
        link_args : ['-shared'],
        c_args : ['-fvisibility=default'],
        dependencies : libshared_deps,
        install : true,
        install_dir : rootlibexecdir)

libshared_static = static_library(
        libshared_name,
        shared_sources,
        basic_sources,
        include_directories : includes,
        dependencies : libshared_deps)
