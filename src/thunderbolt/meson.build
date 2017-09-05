tbtctl_sources = files('''
        device.c
        store.c
        tbtctl.c
'''.split())


thunderbolt_rules = configure_file(
        input : '70-thunderbolt.rules.in',
        output : '70-thunderbolt.rules',
        configuration : substs)

install_data(thunderbolt_rules,
             install_dir : udevrulesdir)
