#pragma once
#include <utility>

static __forceinline constexpr unsigned int CalcHash(const char* str, size_t len) {
	unsigned int result = 0xFFFFFFFF;
	for (size_t i = 0; i < len; ++i) {
		result = str[i] + (result << 5) + result;
	}
	return result;
}

#define ENCRY_API(name) \
    constexpr unsigned int name##_E = CalcHash(#name, sizeof(#name) - 1);

enum class DLL
{
	USER32 = 0x12345678,
	NTDLL,
	KERNELBASE,
};

__forceinline static void* GetAPI(HMODULE module, unsigned int hash) {
	ULONG_PTR baseAddress = (ULONG_PTR)module;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* functions = (DWORD*)(baseAddress + exportDirectory->AddressOfFunctions);
	DWORD* names = (DWORD*)(baseAddress + exportDirectory->AddressOfNames);
	WORD* ordinals = (WORD*)(baseAddress + exportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
		const char* functionName = (const char*)(baseAddress + names[i]);
		if (CalcHash(functionName, strlen(functionName)) == hash)
			return (FARPROC)(baseAddress + functions[ordinals[i]]);
	}
	return 0;
}


namespace EncryptIAT {
	using fnFreeCall = unsigned __int64(__fastcall*)(...);
	template <typename... Params>
	static auto ApiRoutine(DLL dllEnum, unsigned int hash, Params&&... params) {
		char dllName[256]{ 0 };
		switch (dllEnum)
		{
		case DLL::USER32:
			memcpy(dllName, "user32.dll", 11);
			break;
		case DLL::NTDLL:
			memcpy(dllName, "ntdll.dll", 10);
			break;
		case DLL::KERNELBASE:
			memcpy(dllName, "KernelBase.dll", 14);
			break;
		}
		HMODULE dll = LoadLibraryA(dllName);
		auto fn = (fnFreeCall)GetAPI(dll, hash);
		if (*(char*)fn == 0xCC || *(char*)fn == 0xE9) {
			exit(0xDEADBEEF);
		}
		auto retV = fn(std::forward<Params>(params)...);
		FreeLibrary(dll);
		return retV;
	}
}
