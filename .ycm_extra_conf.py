#!/usr/bin/env python

# SPDX-License-Identifier: Unlicense
#
# Based on the template file provided by the 'YCM-Generator' project authored by
# Reuben D'Netto.
# Jiahui Xie has re-reformatted and expanded the original script in accordance
# to the requirements of the PEP 8 style guide and 'systemd' project,
# respectively.
#
# The original license is preserved as it is.
#
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>

"""
YouCompleteMe configuration file tailored to support the 'meson' build system
used by the 'systemd' project.
"""

import glob
import os
import ycm_core


SOURCE_EXTENSIONS = (".C", ".cpp", ".cxx", ".cc", ".c", ".m", ".mm")
HEADER_EXTENSIONS = (".H", ".h", ".hxx", ".hpp", ".hh")


def DirectoryOfThisScript():
    """
    Return the absolute path of the parent directory containing this
    script.
    """
    return os.path.dirname(os.path.abspath(__file__))


def GuessBuildDirectory():
    """
    Guess the build directory using the following heuristics:

    1. Returns the current directory of this script plus 'build'
    subdirectory in absolute path if this subdirectory exists.

    2. Otherwise, probes whether there exists any directory
    containing '.ninja_log' file two levels above the current directory;
    returns this single directory only if there is one candidate.
    """
    result = os.path.join(DirectoryOfThisScript(), "build")

    if os.path.exists(result):
        return result

    result = glob.glob(os.path.join(DirectoryOfThisScript(),
                                    "..", "..", "*", ".ninja_log"))

    if not result:
        return ""

    if 1 != len(result):
        return ""

    return os.path.split(result[0])[0]


def TraverseByDepth(root, include_extensions):
    """
    Return a set of child directories of the 'root' containing file
    extensions specified in 'include_extensions'.

    NOTE:
        1. The 'root' directory itself is excluded from the result set.
        2. No subdirectories would be excluded if 'include_extensions' is left
           to 'None'.
        3. Each entry in 'include_extensions' must begin with string '.'.
    """
    is_root = True
    result = set()
    # Perform a depth first top down traverse of the given directory tree.
    for root_dir, subdirs, file_list in os.walk(root):
        if not is_root:
            # print("Relative Root: ", root_dir)
            # print(subdirs)
            if include_extensions:
                get_ext = os.path.splitext
                subdir_extensions = {
                    get_ext(f)[-1] for f in file_list if get_ext(f)[-1]
                }
                if subdir_extensions & include_extensions:
                    result.add(root_dir)
            else:
                result.add(root_dir)
        else:
            is_root = False

    return result


_project_src_dir = os.path.join(DirectoryOfThisScript(), "src")
_include_dirs_set = TraverseByDepth(_project_src_dir, frozenset({".h"}))
flags = [
    "-x",
    "c"
    # The following flags are partially redundant due to the existence of
    # 'compile_commands.json'.
    #    '-Wall',
    #    '-Wextra',
    #    '-Wfloat-equal',
    #    '-Wpointer-arith',
    #    '-Wshadow',
    #    '-std=gnu99',
]

for include_dir in _include_dirs_set:
    flags.append("-I" + include_dir)

# Set this to the absolute path to the folder (NOT the file!) containing the
# compile_commands.json file to use that instead of 'flags'. See here for
# more details: http://clang.llvm.org/docs/JSONCompilationDatabase.html
#
# You can get CMake to generate this file for you by adding:
#   set( CMAKE_EXPORT_COMPILE_COMMANDS 1 )
# to your CMakeLists.txt file.
#
# Most projects will NOT need to set this to anything; you can just change the
# 'flags' list of compilation flags. Notice that YCM itself uses that approach.
compilation_database_folder = GuessBuildDirectory()

if os.path.exists(compilation_database_folder):
    database = ycm_core.CompilationDatabase(compilation_database_folder)
else:
    database = None


def MakeRelativePathsInFlagsAbsolute(flags, working_directory):
    """
    Iterate through 'flags' and replace the relative paths prefixed by
    '-isystem', '-I', '-iquote', '--sysroot=' with absolute paths
    start with 'working_directory'.
    """
    if not working_directory:
        return list(flags)
    new_flags = []
    make_next_absolute = False
    path_flags = ["-isystem", "-I", "-iquote", "--sysroot="]
    for flag in flags:
        new_flag = flag

        if make_next_absolute:
            make_next_absolute = False
            if not flag.startswith("/"):
                new_flag = os.path.join(working_directory, flag)

        for path_flag in path_flags:
            if flag == path_flag:
                make_next_absolute = True
                break

            if flag.startswith(path_flag):
                path = flag[len(path_flag):]
                new_flag = path_flag + os.path.join(working_directory, path)
                break

        if new_flag:
            new_flags.append(new_flag)
    return new_flags


def IsHeaderFile(filename):
    """
    Check whether 'filename' is considered as a header file.
    """
    extension = os.path.splitext(filename)[1]
    return extension in HEADER_EXTENSIONS


def GetCompilationInfoForFile(filename):
    """
    Helper function to look up compilation info of 'filename' in the 'database'.
    """
    # The compilation_commands.json file generated by CMake does not have
    # entries for header files. So we do our best by asking the db for flags for
    # a corresponding source file, if any. If one exists, the flags for that
    # file should be good enough.
    if not database:
        return None

    if IsHeaderFile(filename):
        basename = os.path.splitext(filename)[0]
        for extension in SOURCE_EXTENSIONS:
            replacement_file = basename + extension
            if os.path.exists(replacement_file):
                compilation_info = \
                    database.GetCompilationInfoForFile(replacement_file)
                if compilation_info.compiler_flags_:
                    return compilation_info
        return None
    return database.GetCompilationInfoForFile(filename)


def FlagsForFile(filename, **kwargs):
    """
    Callback function to be invoked by YouCompleteMe in order to get the
    information necessary to compile 'filename'.

    It returns a dictionary with a single element 'flags'. This element is a
    list of compiler flags to pass to libclang for the file 'filename'.
    """
    if database:
        # Bear in mind that compilation_info.compiler_flags_ does NOT return a
        # python list, but a "list-like" StringVec object
        compilation_info = GetCompilationInfoForFile(filename)
        if not compilation_info:
            return None

        final_flags = MakeRelativePathsInFlagsAbsolute(
            compilation_info.compiler_flags_,
            compilation_info.compiler_working_dir_)

    else:
        relative_to = DirectoryOfThisScript()
        final_flags = MakeRelativePathsInFlagsAbsolute(flags, relative_to)

    return {
        "flags": final_flags,
        "do_cache": True
    }
