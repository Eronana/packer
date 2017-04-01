#pragma once

#include "windows.h"
#define DEFINE_STRING(NAME,STR) char NAME[sizeof(STR)]=STR

struct SectionInfo
{
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
};

struct PEInfo
{
	DWORD ImageBase;
	DWORD AddressOfEntryPoint;
	DWORD NumberOfSections;
	DWORD LoadLibraryA;
	DWORD GetProcAddress;
	DWORD IIDVirtualAddress;
	DWORD UncompressSize;
	struct
	{
#include "shell_data.h"
	}data;
};

DWORD __stdcall shell_main(DWORD pPeInfo);
void shell_end();

