#pragma once

#include "windows.h"
#define DEFINE_STRING(NAME,STR) char NAME[sizeof(STR)]=STR
#define PEINFO_FIELD(NAME) DWORD NAME;
#define DEFINE_SHELL_API_FUNC(NAME) decltype(&NAME) NAME = *(decltype(NAME)*)peInfo.NAME;
#define DEFINE_SHELL_API() API_LIST(DEFINE_SHELL_API_FUNC)

#define API_LIST_BEGIN
#define API_LIST_END 
#define API_LIST(T) \
API_LIST_BEGIN \
T(LoadLibraryA)\
T(GetProcAddress)\
T(VirtualAlloc)\
T(VirtualFree)\
API_LIST_END

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
	DWORD IIDVirtualAddress;
	DWORD NodeTotal;
	DWORD UncompressSize;

	// IMPORT API
	API_LIST(PEINFO_FIELD)
	struct
	{
#include "shell_data.h"
	}data;
};

DWORD __stdcall shell_main(DWORD pPeInfo);
void shell_end();

