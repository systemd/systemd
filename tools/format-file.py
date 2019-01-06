#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

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
	# reindent pragma conditionals with two spaces as indent
	content = re.sub('\n# {32}', r'\n#        ', content)
	content = re.sub('\n# {24}', r'\n#      ', content)
	content = re.sub('\n# {16}', r'\n#    ', content)
	content = re.sub('\n# {8}', r'\n#  ', content)
	# align table like structures with spaces
	content = spaceAlignTableStructures(content)
	open(file, "w").write(content)

def spaceAlignTableStructures(content):
	spaces = ' '*1000
	pattern = re.compile(r'\n( *).*({\s*(?:{.*},\s*)+{}\s*};)')
	for (indent, occurence) in re.findall(pattern, content):
		rows = occurence.strip().split('},')
		cells = []
		for (r, row) in enumerate(rows):
			cellsRaw = row.strip().replace('{', '').replace('}', '').replace(';', '').split(',')
			cellsCleaned = []
			for (c, cell) in enumerate(cellsRaw):
				cell = cellsRaw[c];
				# cell = re.sub('\/\*\*\**\/', r'', cell)
				cellsCleaned.append(cell.strip())
			cells.append(cellsCleaned)
		cells = list(filter(None, cells))
		firstRow = cells[0]
		for (c, col) in enumerate(firstRow):
			maxlen = 0
			for (r, row) in enumerate(cells):
				if(len(row) > c and len(row[c]) > maxlen):
					maxlen = len(row[c])

			for (r, row) in enumerate(cells):
				a = ""
				if(len(row) > c):
					fill = spaces[0:(maxlen - len(row[c]))]
					cells[r][c] = row[c];
					if(len(row) == (c + 1)):
						cells[r][c] += ' '
					else:
						cells[r][c] += ','
					cells[r][c] += fill
		lineGlue = '},\n' + indent + '        ' + '{ '
		tableStart = '{\n' + indent + '        ' + '{ '
		tableInner = lineGlue.join([' '.join([item for item in row]) for row in cells])
		tableEnd = '}\n' + indent + '};'
		table = tableStart +  tableInner + tableEnd
		table = re.sub('{\s*}', r'{}', table)
		content = content.replace(occurence, table)
	return content

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
