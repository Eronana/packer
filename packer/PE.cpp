#include "PE.h"
#include <string>

PE::PE()
{
	init();
}

PE::PE(const char *filename) :PE()
{
	load(filename);
}

PE::~PE()
{
	clear();
}
void PE::init()
{
	overlay_size = 0;
}
bool read(void *buffer, size_t size, FILE *fp, long offset = -1)
{
	if (~offset&&fseek(fp, offset, SEEK_SET))return false;
	return fread(buffer, size, 1, fp) == 1;
}

bool write(void *buffer, size_t size, FILE *fp, long offset = -1)
{
	if (~offset&&fseek(fp, offset, SEEK_SET))return false;
	return fwrite(buffer, size, 1, fp) == 1;
}

DWORD align(DWORD n, DWORD m)
{
	return (n + m - 1) / m*m;
}

void PE::load(const char *filename)
{
	FILE *fp = fopen(filename, "rb");
	if (!fp)THROW_S("cannot open file ", filename);
	try
	{
		// read dos header
		if (!read(&dos_header, sizeof(dos_header), fp))THROW("cannot read DOS header");
		// check "MZ"
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)THROW("incorrect DOS signature");
		// calculate dos stub size
		int dos_stub_size = dos_header.e_lfanew - sizeof(dos_header);
		if (dos_stub_size > 0)
		{
			// new a space to store dos stub
			dos_stub = AUTO_BYTE(new BYTE[dos_stub_size]);
			// read dos stub
			if (!read(dos_stub.get(), dos_stub_size, fp))THROW("cannot read DOS stub");
		}
		// read nt header
		if (!read(&nt_header, sizeof(nt_header), fp))THROW("cannot NT header");
		// check "PE"
		if (nt_header.Signature != IMAGE_NT_SIGNATURE)THROW("incorrect NT signature");
		// check whether it's 32-bit
		if (nt_header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)THROW_S(filename, " is not a valid 32-bit PE file");
		// check whether it's a dll file
		if (nt_header.FileHeader.Characteristics&IMAGE_FILE_DLL)THROW_S(filename, " is not a valid exe file");

		// read section headers
		int NumberOfSections = nt_header.FileHeader.NumberOfSections;
		sections.resize(NumberOfSections);
		for (auto &section : sections)
			if (!read(&section.header, sizeof(section.header), fp))
				THROW("cannot section headers");

		// read section datas
		for (auto &section : sections)if(section.header.SizeOfRawData)
		{
			section.data = AUTO_BYTE(new BYTE[section.header.SizeOfRawData]);
			if (!read(section.data.get(), section.header.SizeOfRawData, fp, section.header.PointerToRawData))
				THROW("cannot section datas");
		}

		// read overlay data
		fseek(fp, 0, SEEK_END);
		size_t file_size = ftell(fp);
		DWORD pe_size = getPESize();
		if (pe_size < file_size)
		{
			overlay_size = file_size - pe_size;
			overlay = AUTO_BYTE(new BYTE[overlay_size]);
			if (!read(overlay.get(), overlay_size, fp, pe_size))THROW("cannot read overlay data");
		}
	}
	catch (...)
	{
		fclose(fp);
		clear();
		throw;
	}
	fclose(fp);
}

void PE::save(const char *filename)
{
	FILE *fp = fopen(filename, "wb");
	if (!fp)THROW_S("cannot open file ", filename);
	try
	{
		// write dos header
		if (!write(&dos_header, sizeof(dos_header), fp))THROW("cannot write DOS header");

		// read dos stub
		int dos_stub_size = dos_header.e_lfanew - sizeof(dos_header);
		if (dos_stub_size > 0 && !write(dos_stub.get(), dos_stub_size, fp))THROW("cannot write DOS stub");

		// read nt header
		if (!write(&nt_header, sizeof(nt_header), fp))THROW("cannot write NT header");

		// write section headers
		for (auto &section : sections)
			if (!write(&section.header, sizeof(section.header), fp))
				THROW("cannot write section headers");

		// write section datas
		for (auto &section : sections)
			if (section.header.SizeOfRawData&&!write(section.data.get(), section.header.SizeOfRawData, fp, section.header.PointerToRawData))
				THROW("cannot write section datas");

		// write overlay data
		if (overlay_size&&!write(overlay.get(), overlay_size, fp))THROW("cannot write overlay data");
	}
	catch (...)
	{
		fclose(fp);
		throw;
	}
	fclose(fp);
}

bool PE::wipeReloc()
{
	auto &BaseReloc = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (BaseReloc.VirtualAddress)
	{
		// try to remove .reloc
		if (!removeSection(BaseReloc.VirtualAddress))return false;
		BaseReloc.VirtualAddress = 0;
		BaseReloc.Size = 0;
	}
	// clear reloc info
	nt_header.FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
	for (auto &sec : sections)sec.header.NumberOfRelocations = 0;
	return true;
}

void PE::wipeBoundImport()
{
	auto &boundImport = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	boundImport.VirtualAddress = boundImport.Size = 0;
}

void PE::setSizeOfImage()
{
	nt_header.OptionalHeader.SizeOfImage = getNextSectionRva();
}

void PE::addSection(BYTE Name[], DWORD VirtualSize, DWORD SizeOfRawData, DWORD Characteristics)
{
	// calculate aligned SizeOfRawData
	SizeOfRawData = align(SizeOfRawData, nt_header.OptionalHeader.FileAlignment);
	// calculate new SizeOfHeaders
	DWORD newSizeOfHeaders = align(dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*(sections.size() + 1), nt_header.OptionalHeader.FileAlignment);
	
	// if necessary, relocate PointerToRawData of sections and increment SizeOfHeaders
	int soh_detal = newSizeOfHeaders - nt_header.OptionalHeader.SizeOfHeaders;
	if (soh_detal > 0)
	{
		for (auto &sec : sections)
			if (sec.header.PointerToRawData >= nt_header.OptionalHeader.SizeOfHeaders)
				sec.header.PointerToRawData += soh_detal;
		nt_header.OptionalHeader.SizeOfHeaders += soh_detal;
	}
	
	PE_SECTION section = {
		{
			{ }, // Name
			{ VirtualSize }, // Misc
			getNextSectionRva(), // VirtualAddress
			SizeOfRawData, // SizeOfRawData
			getPESize(), // PointerToRawData
			0, 0, 0, 0, // PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers
			Characteristics
		},
		AUTO_BYTE(new BYTE[SizeOfRawData]())
	};
	// copy Name
	for (int i = 0; i < 8 && Name[i]; i++)section.header.Name[i] = Name[i];
	// add section to sections 
	sections.push_back(std::move(section));
	// increment NumberOfSections
	nt_header.FileHeader.NumberOfSections++;
	// set SizeOfImage
	setSizeOfImage();
}

bool PE::removeSection(DWORD VirtualAddress)
{
	PE_SECTION d_section;
	int i;
	for (i = 0; i < sections.size(); i++)
	{
		// find section by VirutalAddress
		if (sections[i].header.VirtualAddress == VirtualAddress)
		{
			d_section = std::move(sections[i]);
			// reset VirtualSize
			if (i&&i != sections.size() - 1)
				sections[i - 1].header.Misc.VirtualSize += align(sections[i].header.Misc.VirtualSize, nt_header.OptionalHeader.SectionAlignment);
			// move subsequent sections
			for (int j = i + 1; j < sections.size(); j++)sections[j - 1] = std::move(sections[j]);
			break;
		}
	}
	// cannot found the matching section
	if (i == sections.size())return false;

	// decrement size of sections 
	sections.resize(sections.size() - 1);

	DWORD d_PointerToRawData = d_section.header.PointerToRawData;
	DWORD d_SizeOfRawData = d_section.header.SizeOfRawData;
	// Compact raw data
	compactRawData(d_PointerToRawData, d_SizeOfRawData);

	// decrement NumberOfSections
	nt_header.FileHeader.NumberOfSections--;
	// set SizeOfImage
	setSizeOfImage();
	return true;
}

void PE::compactRawData(DWORD PointerToRawData, DWORD SizeOfRawData)
{
	for (auto &sec : sections)
		if (sec.header.PointerToRawData > PointerToRawData)
			sec.header.PointerToRawData -= SizeOfRawData;
}

DWORD PE::getPESize()
{
	DWORD pe_size = 0;
	for (auto &section : sections)
		if (section.header.SizeOfRawData)
			pe_size = max(pe_size, section.header.PointerToRawData + section.header.SizeOfRawData);
	pe_size = align(pe_size, nt_header.OptionalHeader.FileAlignment);
	return pe_size;
}

DWORD PE::getNextSectionRva()
{
	auto &header = sections.rbegin()->header;
	return header.VirtualAddress + align(header.Misc.VirtualSize, nt_header.OptionalHeader.SectionAlignment);
}

int PE::getSectionByRva(DWORD rva)
{
	for (int i = 0; i < sections.size();i++)
	{
		auto &section = sections[i];
		if (rva >= section.header.VirtualAddress&&rva < section.header.VirtualAddress + section.header.Misc.VirtualSize)return i;
	}
	return -1;
}

void *PE::getDataByRva(DWORD rva)
{
	int idx = getSectionByRva(rva);
	if (idx == -1)return NULL;
	return sections[idx].data.get() + (rva - sections[idx].header.VirtualAddress);
}

void *PE::getDataByRaw(DWORD raw)
{
	for (auto &section : sections)
	{
		if (section.header.PointerToRawData >= raw&&raw < section.header.PointerToRawData + section.header.SizeOfRawData)
		{
			return section.data.get() + (raw - section.header.PointerToRawData);
		}
	}
	return NULL;
}

IMAGE_DOS_HEADER &PE::getDosHeader()
{
	return dos_header;
}

IMAGE_NT_HEADERS &PE::getNtHeader()
{
	return nt_header;
}

BYTE *PE::getDosStub()
{
	return dos_stub.get();
}

std::vector<PE_SECTION> &PE::getSections()
{
	return sections;
}

BYTE *PE::getOverlay()
{
	return overlay.get();
}
void PE::clear()
{
	// free dos stub
	dos_stub.reset();
	// free section 
	sections.clear();
	// free overlay data
	overlay.reset();
	// init
	init();
}
