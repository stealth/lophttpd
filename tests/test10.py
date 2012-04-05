#!/usr/bin/python

import os
import sys
import errno

def usage():
	print('\ntest10.py <dir> to create 100k files inside <dir>\n')
	exit(1)

def die(arg, e):
	print(arg, os.strerror(e.errno))
	exit(e.errno)

def main():
	if len(sys.argv) == 1:
		usage()

	try:
		os.mkdir(sys.argv[1], 0755)
	except Exception as e:
		if e.errno == errno.EEXIST:
			pass
		else:
			die('Failed to create directory.', e)

	try:
		os.chdir(sys.argv[1])
		for i in range(100000):
			f = open('file-%s' % i, 'w')
			f.write('X'*1024)
			f.close()
	except Exception as e:
		die('Failed to create the files.', e)


if __name__ == '__main__':
	main()


