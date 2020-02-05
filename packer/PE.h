#pragma once

#include "windows.h"
#include <cstdio>
#include <vector>
#include <memory>


typedef std::unique_ptr<BYTE[]> AUTO_BYTE;
#define THROW(S) throw std::string(S)
#define THROW_S(S,A) throw std::string(S)+A

struct PE_SECTION
{
	IMAGE_SECTION_HEADER header;
	AUTO_BYTE data;
};

class PE
{
private:
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS nt_header;
	AUTO_BYTE dos_stub;
	std::vector<PE_SECTION> sections;
	DWORD overlay_size;
	AUTO_BYTE overlay;
	void init();
	void setSizeOfImage();
public:
	PE();
	PE(const char *filename);
	~PE();
	void load(const char *filename);
	void save(const char *filename);
	bool wipeReloc();
	void wipeBoundImport();
	void clear();
	void addSection(BYTE name[], DWORD VirtualSize, DWORD SizeOfRawData,DWORD Characteristics);
	bool removeSection(DWORD VirtualSize);
	DWORD getPESize();
	DWORD getNextSectionRva();
	int getSectionByRva(DWORD rva);
	void *getDataByRva(DWORD rva);
	void *getDataByRaw(DWORD raw);
	void compactRawData(DWORD PointerToRawData, DWORD SizeOfRawData);
	IMAGE_DOS_HEADER &getDosHeader();
	IMAGE_NT_HEADERS &getNtHeader();
	BYTE *getDosStub();
	std::vector<PE_SECTION> &getSections();
	BYTE *getOverlay();
};