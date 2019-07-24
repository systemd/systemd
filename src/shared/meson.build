# SPDX-License-Identifier: LGPL-2.1+

shared_sources = files('''
        acl-util.h
        acpi-fpdt.c
        acpi-fpdt.h
        apparmor-util.c
        apparmor-util.h
        ask-password-api.c
        ask-password-api.h
        barrier.c
        barrier.h
        base-filesystem.c
        base-filesystem.h
        bitmap.c
        bitmap.h
        blkid-util.h
        boot-timestamps.c
        boot-timestamps.h
        bootspec.c
        bootspec.h
        bpf-program.c
        bpf-program.h
        bus-unit-procs.c
        bus-unit-procs.h
        bus-unit-util.c
        bus-unit-util.h
        bus-util.c
        bus-util.h
        bus-wait-for-jobs.c
        bus-wait-for-jobs.h
        bus-wait-for-units.c
        bus-wait-for-units.h
        calendarspec.c
        calendarspec.h
        cgroup-show.c
        cgroup-show.h
        clean-ipc.c
        clean-ipc.h
        clock-util.c
        clock-util.h
        condition.c
        condition.h
        conf-parser.c
        conf-parser.h
        cpu-set-util.c
        cpu-set-util.h
        crypt-util.c
        crypt-util.h
        daemon-util.h
        dev-setup.c
        dev-setup.h
        dissect-image.c
        dissect-image.h
        dm-util.c
        dm-util.h
        dns-domain.c
        dns-domain.h
        dropin.c
        dropin.h
        efivars.c
        efivars.h
        enable-mempool.c
        env-file-label.c
        env-file-label.h
        ethtool-util.c
        ethtool-util.h
        exec-util.c
        exec-util.h
        exit-status.c
        exit-status.h
        fdset.c
        fdset.h
        fileio-label.c
        fileio-label.h
        firewall-util.h
        format-table.c
        format-table.h
        fsck-util.h
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
        ip-protocol-list.c
        ip-protocol-list.h
        journal-importer.c
        journal-importer.h
        journal-util.c
        journal-util.h
        json-internal.h
        json.c
        json.h
        libmount-util.h
        linux/auto_dev-ioctl.h
        linux/bpf.h
        linux/bpf_common.h
        linux/bpf_insn.h
        linux/dm-ioctl.h
        linux/ethtool.h
        local-addresses.c
        local-addresses.h
        lockfile-util.c
        lockfile-util.h
        log-link.h
        logs-show.c
        logs-show.h
        loop-util.c
        loop-util.h
        machine-image.c
        machine-image.h
        machine-pool.c
        machine-pool.h
        main-func.h
        module-util.h
        mount-util.c
        mount-util.h
        nscd-flush.c
        nscd-flush.h
        nsflags.c
        nsflags.h
        os-util.c
        os-util.h
        output-mode.c
        output-mode.h
        pager.c
        pager.h
        path-lookup.c
        path-lookup.h
        pe-header.h
        pretty-print.c
        pretty-print.h
        ptyfwd.c
        ptyfwd.h
        reboot-util.c
        reboot-util.h
        resolve-util.c
        resolve-util.h
        seccomp-util.h
        securebits-util.c
        securebits-util.h
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
        tmpfile-util-label.c
        tmpfile-util-label.h
        tomoyo-util.c
        tomoyo-util.h
        udev-util.c
        udev-util.h
        uid-range.c
        uid-range.h
        unit-file.c
        unit-file.h
        utmp-wtmp.h
        varlink.c
        varlink.h
        verbs.c
        verbs.h
        vlan-util.c
        vlan-util.h
        volatile-util.c
        volatile-util.h
        watchdog.c
        watchdog.h
        web-util.c
        web-util.h
        xml.c
        xml.h
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

generate_ip_protocol_list = find_program('generate-ip-protocol-list.sh')
ip_protocol_list_txt = custom_target(
        'ip-protocol-list.txt',
        output : 'ip-protocol-list.txt',
        command : [generate_ip_protocol_list, cpp],
        capture : true)

fname = 'ip-protocol-from-name.gperf'
gperf_file = custom_target(
        fname,
        input : ip_protocol_list_txt,
        output : fname,
        command : [generate_gperfs, 'ip_protocol', 'IPPROTO_', '@INPUT@'],
        capture : true)

fname = 'ip-protocol-from-name.h'
target1 = custom_target(
        fname,
        input : gperf_file,
        output : fname,
        command : [gperf,
                   '-L', 'ANSI-C', '-t', '--ignore-case',
                   '-N', 'lookup_ip_protocol',
                   '-H', 'hash_ip_protocol_name',
                   '-p', '-C',
                   '@INPUT@'],
        capture : true)

fname = 'ip-protocol-to-name.h'
awkscript = 'ip-protocol-to-name.awk'
target2 = custom_target(
        fname,
        input : [awkscript, ip_protocol_list_txt],
        output : fname,
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

shared_generated_gperf_headers = [target1, target2]
shared_sources += shared_generated_gperf_headers

libshared_name = 'systemd-shared-@0@'.format(meson.project_version())

libshared_deps = [threads,
                  librt,
                  libcap,
                  libacl,
                  libcryptsetup,
                  libgcrypt,
                  libiptc,
                  libkmod,
                  libmount,
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
