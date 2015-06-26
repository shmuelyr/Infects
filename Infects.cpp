#include <iostream>
#include <stdio.h>
#include <windows.h>

using namespace std;
//
// Author : shmuel.yr
// Note : This project is under building.. Meanwhile, it will not work
//
int main(int ac, char **av) {
	if(ac < 2) {
		cout << "usage : " << av[0] << " <name_of_file>";
		return 1;
	}
	
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
	
	for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++) {
		cout << "Section : " << section->Name << endl;	
		if(section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			char *mem = fileContant + section->PointerToRawData;
			char *oldMem = mem;

			int maxCaveSize = 0;
			for(int j = 0; j < section->SizeOfRawData; j++) { //this section is executeable.
				int caveSize = 0;
				//printf("start check from : %x\n", oldMem);
				
				while(*oldMem == 0)
					oldMem++, j++, caveSize++;
			
				if (caveSize > section->SizeOfRawData) //check overflow to the next section.
					caveSize -= section->SizeOfRawData;
				
				if(caveSize > maxCaveSize) { //to maximize the size.
					mem = oldMem;
					maxCaveSize = caveSize;
				}
				oldMem++;
			}
			if(maxCaveSize > 0) {
				cout << "\t[+] Founded " << maxCaveSize << "byte in this section\n";			
			}
	}
}
	UnmapViewOfFile(fileContant);
	CloseHandle(hFileMap);
	CloseHandle(hFile);
	return 0;
}
