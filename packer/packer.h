#pragma once

#include "windows.h"
#include "PE.h"
#include "shell.h"
#include <string>
#include <vector>

#define SIZEOF(A) (sizeof(A)/sizeof(A[0]))
#define PACKER_SECTION_NAME ".packer"

struct PackResult
{
	size_t unpacked_sections;
	DWORD oep;
	DWORD new_ep;
};
PackResult pack(char *in, char *out, int argc, char **argv);
