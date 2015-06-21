#!/usr/bin/python
from sys import argv
from struct import unpack, pack

#
# Author : shmuel.yr
# Note : This project is under building.. Meanwhile, it will not work
#

class Infects:
	__name__ = ""
	__data__ = ""
	__jmp__ = ""
	__urCode__ = ""
	__nonUsageMem__ = 0
	__entryPoint__ = 0

	def __init__(self, name):
		self.__name__ = name
		with open(name, "rb") as f:
			self.__data__ = f.read()
		self.setEP()
		self.getNonUsageMem()
		self.genJmp()
		self.patchInfectsCode()
		
	def infects(self):
		self.copyMem()
		self.writeJmp()

	def setEP(self):
		d = ord(self.__data__[0x3c]) 
		AddressOfEntryPoint = unpack("<I", self.__data__[d + 0x28 : d + 0x28 + 4])[0] # 0x28 is offset to AddressOfEntryPoint header
		d = self.__data__.find(".text\x00") + 8 # to reach .text section
		d = d + 4
		VirtualAddress = unpack("<I", self.__data__[d : d + 4])[0] # reach VirtualAddress fild
		d += 8
		PoinerToRawData = unpack("<I", self.__data__[d : d + 4])[0] # reach PoinerToRawData fild
		self.__entryPoint__ = AddressOfEntryPoint - VirtualAddress + PoinerToRawData
		print "[+] VA Entry Point : 0x%x" % self.__entryPoint__

	def getNonUsageMem(self):
		rva = raw_input("Enter RAV addr for the code (RAV should be after EP) : ")
		va = self.extractRVA(int(rva))
		if va > self.__entryPoint__:
			print "[-] Ur addr is not valid, plz enter another addr"
			self.getNonUsageMem()
		else:
			print "[+] VA addr for infects action is : 0x%x" % va
			self.__nonUsageMem__ = va

	def extractRVA(self, addr):
		d = ord(self.__data__[0x3c]) 
		AddressOfEntryPoint = unpack("<I", self.__data__[d + 0x28 : d + 0x28 + 4])[0] # 0x28 is offset to AddressOfEntryPoint header
		d = self.__data__.find(".text\x00") + 8 # to reach .text section
		d = d + 4
		VirtualAddress = unpack("<I", self.__data__[d : d + 4])[0]
		d += 8
		ImageBase = raw_input("Enter ImageBase(in Hex) : ")
		ImageBase = int(ImageBase, 16)
		print "ImageBase %x" % ImageBase
		PoinerToRawData = unpack("<I", self.__data__[d : d + 4])[0]
		return addr - ImageBase - VirtualAddress + PoinerToRawData

	def genJmp(self):
		byte2jmp = self.__nonUsageMem__ - self.__entryPoint__
		print "The distance between EP and ur space is : 0x%x(%d)" % (byte2jmp, byte2jmp)
		self.__jmp__ = "\xe9" + pack("<I", byte2jmp)

	def patchInfectsCode(self):
		self.__urCode__ = "\x90\xcc\x90"

	def copyMem(self):
		d = self.__data__
		d = d[:self.__entryPoint__] + self.__urCode__ + d[self.__entryPoint__ + len(self.__urCode__):]
		self.__data__ = d


if __name__ == "__main__":
	if len(argv) > 1:
		p = Infects(argv[1])
	else:
		print "arg err"

