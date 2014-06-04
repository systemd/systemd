import itertools
import os
import subprocess

def GetFlagsFromMakefile(varname):
  return subprocess.check_output([
      "make", "-s", "print-%s" % varname]).decode().split()


def Flatten(lists):
  return list(itertools.chain.from_iterable(lists))


def DirectoryOfThisScript():
  return os.path.dirname(os.path.abspath(__file__))


def MakeRelativePathsInFlagsAbsolute(flags, working_directory):
  if not working_directory:
    return flags
  new_flags = []
  make_next_absolute = False
  path_flags = [ '-isystem', '-I', '-iquote', '--sysroot=' ]
  for flag in flags:
    new_flag = flag

    if make_next_absolute:
      make_next_absolute = False
      if not flag.startswith('/'):
        new_flag = os.path.join(working_directory, flag)

    for path_flag in path_flags:
      if flag == path_flag:
        make_next_absolute = True
        break

      if flag.startswith(path_flag):
        path = flag[ len(path_flag): ]
        new_flag = path_flag + os.path.join(working_directory, path)
        break

    if new_flag:
      new_flags.append(new_flag)
  return new_flags


def FlagsForFile(filename):
  relative_to = DirectoryOfThisScript()

  return {
    'flags': MakeRelativePathsInFlagsAbsolute(flags, relative_to),
    'do_cache': True
  }

flags = Flatten(map(GetFlagsFromMakefile, [
  'AM_CPPFLAGS',
  'CPPFLAGS',
  'AM_CFLAGS',
  'CFLAGS',
]))

# these flags cause crashes in libclang, so remove them
flags.remove('-Wlogical-op')
flags.remove('-Wsuggest-attribute=noreturn')
flags.remove('-Wdate-time')

# vim: set et ts=2 sw=2:
