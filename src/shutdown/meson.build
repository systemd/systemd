systemd_shutdown_sources = files('''
        shutdown.c
        umount.c
        umount.h
'''.split())

tests += [
        [['src/shutdown/test-umount.c',
          'src/shutdown/umount.c',
          'src/shutdown/umount.h'],
         [],
         [libmount]],
]
