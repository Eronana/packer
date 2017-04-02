#include <cstdio>
#include <cstring>
#include "packer.h"
#include "windows.h"
#include "../compressor/utils.h"

void getOutFile(const char *in, char *out)
{
	size_t slen = strlen(in);
	if (!strcmp(in + slen - 4, ".exe"))
	{
		sprintf(out, "%s.exe", in);
		strcpy(out + slen - 3, "packed.exe");
	}
	else sprintf(out, "%s.packed.exe", in);
}

size_t getFileSize(const char *file)
{
	FILE *fp = fopen(file, "rb");
	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fclose(fp);
	return size;
}

int usage(char *s)
{
	printf("Usage: %s a.exe [options]\n", s);
	puts("Options:");
	printf("  -level: compression level. 0 for store, %lu for highest\n", config_count - 1);
	printf("          compression ratio. default is %d.\n", DEFAULT_LEVEL);
	printf("  -lazy : set max lazy match, default is %d.\n", config[DEFAULT_LEVEL].lazy_match);
	printf("  -chain: set max length of find in hash chain, default is %d.\n\n", config[DEFAULT_LEVEL].max_chain);
	puts("Notice: lazy and chain will be ignored if you setted level.");
	return 1;
}
void header()
{
	puts("[ Packer ]");
	puts("A win32 exe packer");
	puts("Homepage: https://github.com/Eronana/packer");
	puts("-------------------------------------------");
}
int main(int argc, char **argv)
{
	header();
	if (argc < 2)return usage(argv[0]);
	char *in = argv[1];
	char out[256];
	getOutFile(in, out);
	try
	{
		printf("IN : %s\n", in);
		printf("OUT: %s\n", out);
		puts("Packing...");
		double t = GetTickCount();
		auto result = pack(in, out, argc, argv);
		printf("Finished in %.2fs.\n", (GetTickCount() - t) / 1000);
		size_t in_size = getFileSize(in);
		size_t out_size = getFileSize(out);
		printf("Unpacked Sections: %zu\n", result.unpacked_sections);
		printf("Compress ratio: %.2f%%\n", out_size*100.0 / in_size);
		printf("Original file size: %zu\n", in_size);
		printf("Packed File Size: %zu\n", out_size);
		printf("Original Entry Point: %p\n", result.oep);
		printf("New Entry Point: %p\n", result.new_ep);
	}
	catch (std::string &s)
	{
		printf("err: %s\n", s.c_str());
		return 1;
	}
	return 0;
}
