#include "shell.h"
#include "../compressor/uncompressor.h"
#include "../compressor/compressor.h"


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

	// define API
	DEFINE_SHELL_API();
	/*
	// show a message box
	HMODULE hModule = LoadLibraryA(data.user32);
	decltype(&MessageBoxA) MyMessageBoxA;
	MyMessageBoxA = (decltype(MyMessageBoxA))GetProcAddress(hModule, data.MessageBoxA);
	MyMessageBoxA(NULL, data.content, data.title, NULL);
	*/
	// uncompress
#define VALLOC(SIZE) VirtualAlloc(NULL, SIZE, MEM_COMMIT, PAGE_READWRITE)
#define VFREE(ADDR) VirtualFree(ADDR, 0, MEM_RELEASE)
#define newHNode() (hNodes[node_cnt].value=-1,hNodes[node_cnt].child[0]=hNodes[node_cnt].child[1]=NULL,hNodes+node_cnt++)
	HNode *hNodes = (HNode*)VALLOC(peInfo.NodeTotal*sizeof(HNode));
	int node_cnt = 0;
	BYTE *src = section_data;

	WORD tree_size = *(WORD*)src;
	src += 2;
	WORD len_size_size = *(WORD*)src;
	src += 2;
	DWORD d_buf_size = *(DWORD*)src;
	src += 4;
	DWORD l_buf_size = *(DWORD*)src;
	src += 4;
	WORD *tree = (WORD*)src;
	src += tree_size*sizeof(tree[0]);
	LenSizeType *len_size = (LenSizeType*)src;
	src += len_size_size*sizeof(len_size[0]);
	BYTE *bit_stream = src;

	HNode *huffman = newHNode();
	int code = 0, last_len = 0;
	for (int i = 0, a = 0; i<len_size_size; i++)
	{
		int len = len_size[i].len;
		int size = len_size[i].size;
		code <<= (len - last_len);
		last_len = len;
		// rebuild buffman tree
		while(size--)
		{
			HNode *node = huffman;
			for (int j = len - 1; ~j; j--)
			{
				int v = !!(code&(1 << j));
				if (!node->child[v])node->child[v] = newHNode();
				node = node->child[v];
			}
			node->value = tree[a++];
			code++;
		}
	}

	WORD *d_buf = (WORD*)VALLOC(sizeof(WORD)*d_buf_size);
	BYTE *l_buf = (BYTE*)VALLOC(l_buf_size);

	int byte_count = 0;
	for (int i = 0; i<d_buf_size; i++)
	{
		HNode *node = huffman;
		for (; node->value == -1; byte_count++)node = node->child[!!(bit_stream[byte_count / 8] & (1 << (7 - byte_count % 8)))];
		d_buf[i] = node->value;
	}
	for (int i = 0; i<l_buf_size; i++)
	{
		HNode *node = huffman;
		for (; node->value == -1; byte_count++)node = node->child[!!(bit_stream[byte_count / 8] & (1 << (7 - byte_count % 8)))];
		l_buf[i] = node->value;
	}
	VFREE(hNodes);
	
	section_data = (BYTE*)VALLOC(peInfo.UncompressSize);
	// unlz77
	int x = 0;
	int next = 0;
	for (int i = 0; i<d_buf_size; i++)
	{
		int dis = d_buf[i] - 256;
		if (dis<0) section_data[next++] = d_buf[i];
		else
		{
			BYTE *buf = section_data + next - dis;
			for (int j = 0; j<l_buf[x] + MIN_REPEAT_LENGTH; j++)section_data[next++] = buf[j];
			x++;
		}
	}

	VFREE(l_buf);
	VFREE(d_buf);
	
	// restore sections
	for (int i = 0; i < peInfo.NumberOfSections; i++)
	{
		BYTE *data = (BYTE*)(peInfo.ImageBase + sections[i].VirtualAddress);
		for (int j = 0; j < sections[i].SizeOfRawData; j++)data[j] = *section_data++;
	}

	VFREE(section_data);

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
	
	// return oep
	return peInfo.ImageBase + peInfo.AddressOfEntryPoint;
}

// a empty function to calculate the size of shell_main
// this function will be located behind shell_main in VS Community 2015
__declspec(naked) void shell_end()
{
	__asm int 3
}
