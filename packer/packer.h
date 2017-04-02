#pragma once

#include "windows.h"
#include "PE.h"
#include "shell.h"
#include <string>
#include <vector>

#define SIZEOF(A) (sizeof(A)/sizeof(A[0]))
#define PACKER_SECTION_NAME ".packer"
#define DEFINE_API(S) struct{WORD Hint=NULL;DEFINE_STRING(name, #S);}S
#define IAT_FIELD_FUNC(NAME) DEFINE_API(NAME);
#define IAT_FIELD() API_LIST(IAT_FIELD_FUNC)
#define API_OFFSET_FUNC(NAME) offsetof(IAT_TYPE,NAME),
#define API_OFFSET() API_LIST(API_OFFSET_FUNC)
#define API_SIZE_FUNC(NAME) 1+
#define API_SIZE() (API_LIST(API_SIZE_FUNC)0)

struct PackResult
{
	size_t unpacked_sections;
	DWORD oep;
	DWORD new_ep;
};
PackResult pack(char *in, char *out, int argc, char **argv);
