#include "shell.h"

/*
 * VS won't optimize naked function,
 * so use normal function to get optimized code
 * and use a shell code loader(in packer.cpp) to call it
 *
 * Notice: don't use any abosolute address resources like "string"
 */
DWORD __stdcall shell_main(DWORD pPeInfo)
{
	// set peInfo address
	PEInfo &peInfo = *(PEInfo*)pPeInfo;
	// set sectionInfo address
	SectionInfo *sections = (SectionInfo*)(&peInfo + 1);
	// set section data address
	BYTE *section_data = (BYTE*)(sections + peInfo.NumberOfSections);
	// set shell data
	decltype(peInfo.data) &data = peInfo.data;

	// get addresses of LoadLibraryA and GetProcess
	// define API
	DEFINE_SHELL_API()


	// restore sections
	for (int i = 0; i < peInfo.NumberOfSections; i++)
	{
		BYTE *data = (BYTE*)(peInfo.ImageBase + sections[i].VirtualAddress);
		for (int j = 0; j < sections[i].SizeOfRawData; j++)data[j] = *section_data++;
	}

	// resotre original IAT
	for(IMAGE_IMPORT_DESCRIPTOR *IID = (IMAGE_IMPORT_DESCRIPTOR*)(peInfo.IIDVirtualAddress + peInfo.ImageBase);;IID++)
	{
		DWORD RealFirstThunk = IID->OriginalFirstThunk;
		if(!RealFirstThunk)RealFirstThunk= IID->FirstThunk;
		if (!RealFirstThunk)break;

		char *DllName = (char*)(peInfo.ImageBase + IID->Name);
		HMODULE hModule = LoadLibraryA(DllName);
		if (!hModule)continue;

		DWORD *OriginalFirstThunk = (DWORD*)(peInfo.ImageBase + RealFirstThunk);
		DWORD *FirstThunk = (DWORD*)(peInfo.ImageBase + IID->FirstThunk);
		for (int i = 0; OriginalFirstThunk[i]; i++)
		{
			DWORD ProcName;
			if (OriginalFirstThunk[i] & IMAGE_ORDINAL_FLAG)ProcName = IMAGE_ORDINAL(OriginalFirstThunk[i]);
			else ProcName = peInfo.ImageBase + OriginalFirstThunk[i] + 2;
			FirstThunk[i] = (DWORD)GetProcAddress(hModule, (LPCSTR)ProcName);
		}
	}
	
	// show a message box
	HMODULE hModule = LoadLibraryA(data.user32);
	decltype(&MessageBoxA) MyMessageBoxA;
	MyMessageBoxA = (decltype(MyMessageBoxA))GetProcAddress(hModule, data.MessageBoxA);
	MyMessageBoxA(NULL, data.content, data.title, NULL);

	// return oep
	return peInfo.ImageBase + peInfo.AddressOfEntryPoint;
}

// a empty function to calculate the size of shell_main
// this function will be located behind shell_main in VS Community 2015
__declspec(naked) void shell_end()
{
	__asm int 3
}
