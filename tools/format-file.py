#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

import collections
import sys
import os.path
import re
import getopt

clangFormatCmd = "clang-format"

def run_clang_format(file):
	cmd = clangFormatCmd + " -i -style=file " + file
	os.system(cmd)

def run_post_clang_format(file):
	content = open(file, "r").read()
	# this fixes the enum breaking issue (move the brace next to the enum keyword)
	content = re.sub('(\s*enum)\n\s*{', r'\1 {', content)
	# this fixes typedef enums breaking issue (move the brace next to the enum alias)
	content = re.sub('(\s*typedef enum [a-zA-Z0-9]+)\n\s*{', r'\1 {', content)
	# this fixes the undesired space between the name and the brace of a foreach macro
	content = re.sub('(\s*[A-Z0-9_]*FOREACH[A-Z0-9_]*)\s*(\()', r'\1\2', content)
	file = open(file, "w").write(content)

if __name__ == '__main__':
	opts, args = getopt.getopt(sys.argv[1:], '', ['clang-format='])
	for opt, arg in opts:
		if opt in ('--clang-format'):
			clangFormatCmd = arg
	files = args
	for file in files:
		print("formatting: " + file)
		run_clang_format(file)
		run_post_clang_format(file)
