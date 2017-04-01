#include <cstdio>
#include <cstring>
#include "packer.h"
#include "windows.h"

void getOutFile(const char *in, char *out)
{
	size_t slen = strlen(in);
	if (!strcmp(in + slen - 4, ".exe"))
	{
		sprintf(out, "%s.exe", in);
		out[slen - 3] = 'o';
		out[slen - 2] = 'u';
		out[slen - 1] = 't';
	}
	else sprintf(out, "%s.out.exe", in);
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
	printf("Usage: %s a.exe\n", s);
	return 1;
}
int main(int argc, char **argv)
{
	if (argc < 2)return usage(argv[0]);
	char *in = argv[1];
	char out[100];
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
