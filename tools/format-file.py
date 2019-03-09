#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

import sys
import os.path
import re
import getopt
import shutil
from subprocess import check_output
from shlex import split
import filecmp

clangFormatCmd = "clang-format"

def printHelp():
	print("""
Usage: format-file.py [OPTION]... [FILE]...
Formats .c and .h files in systemd with clang-format
and some custom style rules.

Options:
  -c --clang-format <path> Specify the path to the clang-format version to use.
                           Systemd uses clang-format version 6.0.0. This may be
                           available in your package manager, otherwise you can
                           download the proper binary directly from LLVM:
                           https://releases.llvm.org/download.html
  -d --dry                 Do not modify files but only show which files would
                           be changed by the script.
  -h --help                Show this help message

Example:
$ tools/format-file.py -d -c clang-format-6.0 src/*/*.c

If you experience any issues please:
- contact the mailing list (systemd-devel@lists.freedesktop.org)
- or file an issue on github (https://github.com/systemd/systemd/issues)
""")
	sys.exit()

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
	#rewrap the line breaks of the help texts
	content = rewrapLinebreaksOfHelpText(content)
	# align table like typedef enum with spaces
	content = spaceAlignEnumTypedefs(content)
	# align binary operators, which are a concatenation of binary flags
	content = indentAlignBinaryFlag(content)
	# write contents back to the file
	open(file, "w").write(content)

def indentAlignBinaryFlag(content):
	# see regex eplanation here: https://regex101.com/r/Ngubb2/2
	pattern = re.compile(r'\n( *?)([a-zA-Z.]+\s*=(?:\s*[a-zA-Z0-9_() ]+\s*<<\s*[a-zA-Z0-9_() ]+\|?)+[,;])')
	for (indent, occurence) in re.findall(pattern, content):
		occurenceX = occurence
		binaryOperands = occurenceX.split('|')
		binaryOperandsTrimmed = []
		for (r, binaryOperand) in enumerate(binaryOperands):
			binaryOperandsTrimmed.append(binaryOperand.strip())
		occurenceX = (" |\n" + indent + "        ").join(binaryOperandsTrimmed)
		content = content.replace(occurence, occurenceX)
	return content

def spaceAlignEnumTypedefs(content):
	spaces = ' '*1000
	pattern = re.compile(r'(typedef enum [A-Za-z]+ {[^}]+} [A-Za-z]+;)')
	for (occurence) in re.findall(pattern, content):
		lines = occurence.split('\n')
		newLines = []
		leftWidth = 0
		for line in lines:
			leftWidth = max(leftWidth, line.find('='))
		for line in lines:
			pos = line.find('=')
			if(pos >= 0):
				fill = spaces[0:(leftWidth - pos)]
				line = re.sub('=', r'' + fill + '=', line)
			newLines.append(line)
		content = content.replace(occurence, '\n'.join(newLines))
	return content

def rewrapLinebreaksOfHelpText(content):
	# see regex eplanation here: https://regex101.com/r/8fQvP9/2
	pattern = re.compile(r'\n( *?)(printf\([^;]+?,\s*program_invocation_short_name(?:,\s*link)?\);)')
	for (indent, occurence) in re.findall(pattern, content):
		occurenceX = occurence
		occurenceX = re.sub(',(\s*)(program_invocation_short_name)', r'\1, \2', occurenceX)
		occurenceX = re.sub(',(\s*)(link)', r'\1, \2', occurenceX)
		occurenceX = re.sub('\s*\);', r'\n' + indent + ');', occurenceX)
		content = content.replace(occurence, occurenceX)
	return content

def spaceAlignTableStructures(content):
	spaces = ' '*1000
	# identify table like structure
	# see regex eplanation here: https://regex101.com/r/MiyJKq/4
	pattern = re.compile(r'\n( *).*({\s*(?:{[^}]*},\s*?(?:\/\*[\s\S]*?\*\/\s*)?)+(?:{})?\s*};)')
	for (indent, occurence) in re.findall(pattern, content):
		# parse all "cells" in the table
		rows = occurence.strip().split('},')
		cells = []
		lineComments = []
		for (r, row) in enumerate(rows):
			cellsRawLine = row.strip().replace('{', '').replace('}', '').replace(';', '')
			cellsRaw = re.split(r',\s*(?![^()]*\))', cellsRawLine)
			# find line comments
			match = re.search('\s*/\*.*\*\/', row)
			lineComment = ""
			if(match != None): lineComment = match.group(0)
			lineComments.append(lineComment)
			# read comma-separated cells and trim them
			cellsCleaned = []
			for (c, cell) in enumerate(cellsRaw):
				cell = cellsRaw[c];
				cell = re.sub('/\*.*\*\/', r'', cell)
				cellsCleaned.append(cell.strip())
			cells.append(cellsCleaned)
		lineComments = lineComments[1:]
		colWidth = max(len(cell) for cell in cells)

		# for each column append padding to cells
		for c in range(0, colWidth):
			# find maxlen of the column -> column width
			maxlen = 0
			for (r, row) in enumerate(cells):
				if(len(row) > c and len(row[c]) > maxlen):
					maxlen = len(row[c])
			# replace cells of column with padded string
			for (r, row) in enumerate(cells):
				if(len(row) > c):
					cell = row[c]
					if(cell == ""): continue
					if(len(row) == (c + 1)):
						cell += ' ' # no comma after last cell in row
					else:
						cell += ','
					fill = spaces[0:(maxlen - len(row[c]))]
					cell += fill
					cells[r][c] = cell

		# put cells back together to a table
		tableInner = ""
		for (r, row) in enumerate(cells):
			tableInner += '{ ' + ' '.join([item for item in row]) + '}'
			lineComment = ''
			if(len(lineComments) > r):
				# print('lc: ' + str(r) + ' --> ' + lineComments[r])
				lineComment = lineComments[r]
				# reindent multiline comments
				lineComment = re.sub('\n\s*', r'\n' + indent + '        ', lineComment)
			if(len(cells) > (r + 1)):
				tableInner += ',' + lineComment + '\n' + indent + '        '

		# write table
		tableStart = '{\n' + indent + '        '
		tableEnd = '\n' + indent + '};'
		table = tableStart +  tableInner + tableEnd
		table = re.sub('{\s*}', r'{}', table)
		content = content.replace(occurence, table)
	return content

if __name__ == '__main__':
	opts, args = getopt.getopt(sys.argv[1:], 'c:hd', ['clang-format=', 'help', 'dry'])
	dry = False
	for opt, arg in opts:
		if opt in ('--help'):
			printHelp()
		if opt in ('--clang-format'):
			clangFormatCmd = arg
		if opt in ('--dry'):
			dry = True
	files = args

	if(len(files) <= 0):
		print('error: no file given')
		printHelp()

	if (shutil.which(clangFormatCmd) is None):
		print('error: "' + clangFormatCmd + '" not executable')
		printHelp()

	versionString = str(check_output(split(clangFormatCmd + ' -version')))
	if ("version 6.0" not in versionString):
		print('error: "' + clangFormatCmd + '" not in correct version, expecting version 6.0.x')
		print('got version: "' + versionString)
		printHelp()

	infoText = "FORMATTING: "
	if(dry): infoText += "(DRY RUN)"
	print(infoText)
	for file in files:
		print(file.ljust(40), end="", flush=True)
		if(not os.path.isfile(file)):
			print(' [Skipping non existing file]')
			continue
		if(file.find('MurmurHash2') > 0):
			print(' [Skipping MurmurHash2 file]')
			continue
		fileTmp = file + '.tmp'
		shutil.copyfile(file, fileTmp)
		run_clang_format(fileTmp)
		run_post_clang_format(fileTmp)
		fileUnchanged = filecmp.cmp(file, fileTmp)
		if(fileUnchanged):
			print(' [UNCHANGED]')
		else:
			print(' [CHANGED]')
		if not dry and not fileUnchanged:
			shutil.move(fileTmp, file)
		else:
			os.remove(fileTmp)
	print("ALL DONE")

