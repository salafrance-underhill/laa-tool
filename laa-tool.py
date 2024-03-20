"""
				MIT License

Copyright (c) 2024 Salafrance Underhill <doppelsonnenuhr@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


"""
#############################################################################
#
# 				laa-tool.py
#
#
# A quick hack to inspect or set/unset the Large Address Awareness flag for 
# 32-bit Microsoft PE executables.
#
# Specifically, I wrote it so that I could play Dragon Age: Origins on a 
# modern system with acceptable resolution (without it crashing at Ostagar).
#
# It is heavily cribbed from a Visual Basic for Access utility written by
# Philipp Stiefel (phil@codekabinett.com) of https://www.codekabinett.com/
#
# Run it without the set/unset flags to inpect the LAA status.
#
#   python laa-tool.py <path to executable
#
# To obtain a safe version of Python, consider installing Chocolatey
# and installing the official Python package listed thereon.
#
# If this breaks your favourite toys, that's on  you. Use caution.
#############################################################################

import os
import sys
import argparse

# The Large Address Awareness bit flag
LAA = 0x20

class EChunkSize(Exception):
	pass

class ERange(Exception):
	pass

class ENotExecutable(Exception):
	pass

# Returns a positive integer representing the little-endian value of the passed 2-byte bytes string
def bytes2word(bytebuffer):
	if len(bytebuffer) != 2:
		raise EChunkSize('word expected')
	return int.from_bytes(bytebuffer, byteorder = 'little', signed = False)

# Take a positive integer in the range 0-65535 and return a Python bytes string of length 2
def word2bytes(word):
	if word != abs(word):
		raise ERange('Number out of range')

	if word > 65535:
		raise ERange('Number out of range')
	
	return word.to_bytes(length = 2, byteorder = 'little', signed = False)

# Returns a positive integer representing the little-endian value of the passed single byte bytes string
def bytes2byte(bytebuffer):
	if len(bytebuffer) != 1:
		raise EChunkSize('byte expected')
	return int.from_bytes(bytebuffer, byteorder = 'little', signed = False)

# Take a positive integer in the range 0-255 and return a Python bytes string of length 1
def byte2bytes(bite):
	if bite != abs(bite):
		raise ERange('Number out of range')

	if bite > 255:
		raise ERange('Number out of range')
	
	return bite.to_bytes(length = 1, byteorder = 'little', signed = False)

# Debugging
def dumpbin(bytebuffer):
	for b in bytebuffer:
		print("0x{:02x}".format(int(b)))

# Locates the LAA flag byte and returns it as a seek index
def getLAAPosition(fdobj):
	MZ = 0x5a4d
	PE = 0x4550

	position_PE_location = 0x3c
	offset_LAA_from_PE = 22

	# Reading "MZ" flag of .exe header

	fdobj.seek(0, os.SEEK_SET)
	rdbuf = fdobj.read(2)
	flag = bytes2word(rdbuf)

	# print("value returned was {:02x}".format(flag))

	if flag != MZ:
		err = "{} is not a valid executable".format(os.path.basename(fdobj.name))
		raise ENotExecutable(err)


	# Get the offset of the PE flag, and then read and check it
	fdobj.seek(position_PE_location, os.SEEK_SET)
	rdbuf = fdobj.read(2)
	peoff = bytes2word(rdbuf)
	fdobj.seek(peoff, os.SEEK_SET)
	rdbuf = fdobj.read(2)
	flag = bytes2word(rdbuf)

	if flag != PE:
		err = "{} is not a valid PE file".format(os.path.basename(fdobj.name))
		raise ENotExecutable(err)

	# The LAA flag byte is a fixed number of bytes 
	# offset from the PE flag word, so that's what we return
	return peoff + offset_LAA_from_PE

# Returns the integer value of the LAA flag byte
def getLAAFlagByte(fdobj):
	laapos = getLAAPosition(fdobj)

	fdobj.seek(laapos, os.SEEK_SET)
	rdbuf = fdobj.read(1)

	flagbyte = bytes2byte(rdbuf)

	return flagbyte
	
# Returns True/False according to whether the flag is set/unset
def getLAAStatus(fdobj):
	flagbyte = getLAAFlagByte(fdobj)

	laaset = ((flagbyte & LAA) == LAA)

	return laaset

# Toggles the LAA bit in the flag byte
def toggleLAAStatus(fdobj):
	laapos = getLAAPosition(fdobj)

	fdobj.seek(laapos, os.SEEK_SET)
	rdbuf = fdobj.read(1)

	orgbyte = bytes2byte(rdbuf)
	modbyte = (orgbyte ^ LAA)
	wrbuf = byte2bytes(modbyte)

	fdobj.seek(laapos, os.SEEK_SET)
	fdobj.write(wrbuf)


if __name__=='__main__':
	ap = argparse.ArgumentParser(prog="laa-tool", description="get/set large address aware flag for the given microsoft executable")

	ap.add_argument('filename', nargs=1, type=str, help='path to the executable file you wish to modify or inspect')
	ap.add_argument('-s', '--set', help='set the LAA flag', action='store_true')
	ap.add_argument('-u', '--unset', help='unset the LAA flag', action='store_true')

	args = ap.parse_args()

	if args.set and args.unset:
		print("You are attempting both to set and to unset the LAA flag for this executable - exiting with no changes")
		sys.exit(1)

	fdobj = open(args.filename[0], 'rb', buffering=0)
	flagbyte = getLAAFlagByte(fdobj)
	laaset = getLAAStatus(fdobj)
	fdobj.close()

	if args.set:
		if laaset:
			print("This executable is already Large Address Aware - exiting with no changes")
			sys.exit(1)
		else:
			fdobj = open(args.filename[0], 'r+b', buffering=0)
			toggleLAAStatus(fdobj)
			fdobj.close()
			print("Large Address Awareness is now enabled for this executable")
	else:
		if args.unset:
			if not laaset:
				print("This executable is not Large Address Aware - exiting with no changes")
				sys.exit(1)
			else:
				fdobj = open(args.filename[0], 'r+b', buffering=0)
				toggleLAAStatus(fdobj)
				fdobj.close()
				print("Large Address Awareness is now disabled for this executable")
		else:
			print("This executable {} Large Address Aware (flag byte = 0x{:02x})".format("is" if laaset else "is not", flagbyte))

	sys.exit(0)



